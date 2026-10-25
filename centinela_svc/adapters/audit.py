"""Append-only, hash-chained audit log.

Each entry is one canonical JSON line carrying the sha256 of the previous line.
Backends: a JSONL file (default) or a Postgres table when a DSN is given, so the
log survives container restarts. Both resume the chain from the last entry.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

GENESIS = "0" * 64
CHAIN_LOCK_KEY = 0x43454E54  # pg_advisory_xact_lock key serializing transactional appends ("CENT")

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq         bigint PRIMARY KEY,
    ts          double precision NOT NULL,
    kind        text NOT NULL,
    prev_sha256 char(64) NOT NULL,
    sha256      char(64) NOT NULL,
    line        text NOT NULL
);
CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END $$;
DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log;
CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();
"""


def _sha(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def verify_lines(lines: list[str], stored: list[str] | None = None) -> tuple[bool, int | None]:
    """Check the chain. Return (True, None) or (False, seq of the first bad entry).

    `stored` are the hashes saved next to each line (Postgres backend); with
    them an edited line is pinned to itself instead of to the entry after it.
    """
    prev = GENESIS
    for i, line in enumerate(lines):
        entry = json.loads(line)
        sha = _sha(line)
        if entry.get("prev_sha256") != prev or (stored is not None and stored[i] != sha):
            return False, entry.get("seq")
        prev = sha
    return True, None


class AuditLog:
    def __init__(self, path: str, keep: int = 500, dsn: str | None = None) -> None:
        self.keep = keep
        self.entries: list[dict] = []
        self._lock = threading.Lock()
        self._prev = GENESIS
        self._seq = 0
        self._dsn = dsn
        self._conn = None
        self._unique = None  # UniqueViolation type, set for the Postgres backend
        if dsn:
            self._init_pg()
        else:
            self.path = Path(path)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                self._resume(self.path.read_text(encoding="utf-8").splitlines()[-keep:])

    def _resume(self, lines: list[str]) -> None:
        for line in lines:
            entry = json.loads(line)
            self.entries.append(entry)
            self._seq = entry["seq"]
            self._prev = _sha(line)

    def _init_pg(self) -> None:
        import psycopg  # only needed for the Postgres backend

        self._unique = psycopg.errors.UniqueViolation
        self._conn = psycopg.connect(self._dsn, autocommit=True)
        self._conn.execute(SCHEMA)
        rows = self._conn.execute(
            "SELECT line FROM (SELECT seq, line FROM audit_log ORDER BY seq DESC LIMIT %s) t ORDER BY seq",
            (self.keep,)).fetchall()
        self._resume([r[0] for r in rows])

    def _pg_resync(self) -> None:
        """Re-read the tail from the DB after a concurrent writer advanced it.

        During a zero-downtime deploy the draining and starting containers both
        run the monitor and write here, so their seq counters collide. Catching
        up from the DB lets the survivor keep one valid chain instead of crashing.
        """
        row = self._conn.execute(
            "SELECT seq, sha256 FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        self._seq, self._prev = (row[0], row[1]) if row else (0, GENESIS)

    def append(self, kind: str, data: dict) -> dict:
        with self._lock:
            ts = time.time()
            # Retry once: a concurrent writer (deploy overlap) may take our seq.
            for attempt in (1, 2):
                seq = self._seq + 1
                entry = {"seq": seq, "ts": ts, "kind": kind,
                         "prev_sha256": self._prev, "data": data}
                line = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
                sha = _sha(line)
                if self._conn is None:
                    with self.path.open("a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                    break
                try:
                    # Fails closed: if the write does not land, nothing is acknowledged.
                    self._conn.execute(
                        "INSERT INTO audit_log (seq, ts, kind, prev_sha256, sha256, line) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (seq, ts, kind, self._prev, sha, line))
                    break
                except self._unique:
                    if attempt == 2:
                        raise
                    self._pg_resync()  # catch up and relink to the real last entry
            self._seq = seq
            self._prev = sha
            self.entries.append(entry)
            del self.entries[:-self.keep]
            return entry

    @property
    def transactional(self) -> bool:
        """True when entries can join a caller's Postgres transaction (`append_in`)."""
        return self._conn is not None

    def append_in(self, conn, kind: str, data: dict) -> dict:
        """Insert an entry through the caller's connection, inside the caller's open transaction.

        The entry commits or rolls back with the caller's own changes. Seq and prev
        hash come from the DB tail, read after taking a transaction-scoped advisory
        lock, so transactional writers (any container) serialize on the chain tail.
        Plain `append` (other writers, deploy overlap) takes no lock; if it lands
        the same seq first, the insert raises UniqueViolation (in a savepoint) and
        we re-read the tail and relink once, mirroring `append`'s resync.

        The in-memory tail is NOT touched here: call `adopt(entry)` after the
        caller's transaction commits (never when it rolls back).
        """
        if self._conn is None:
            raise RuntimeError("append_in needs the Postgres backend")
        ts = time.time()
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (CHAIN_LOCK_KEY,))
        for attempt in (1, 2):
            row = conn.execute("SELECT seq, sha256 FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
            entry = {"seq": seq, "ts": ts, "kind": kind, "prev_sha256": prev, "data": data}
            line = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
            try:
                with conn.transaction():  # savepoint: a collision must not abort the caller's transaction
                    conn.execute(
                        "INSERT INTO audit_log (seq, ts, kind, prev_sha256, sha256, line) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (seq, ts, kind, prev, _sha(line), line))
                return entry
            except self._unique:
                if attempt == 2:
                    raise

    def adopt(self, entry: dict) -> None:
        """Fold an entry committed through `append_in` into the in-memory tail."""
        with self._lock:
            self.entries.append(entry)
            self.entries.sort(key=lambda e: e["seq"])
            del self.entries[:-self.keep]
            if entry["seq"] > self._seq:
                line = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
                self._seq, self._prev = entry["seq"], _sha(line)

    def recent(self, n: int) -> list[dict]:
        """The last `n` entries re-read from storage, oldest first (used to rebuild state on startup)."""
        if self._conn is not None:
            rows = self._conn.execute(
                "SELECT line FROM (SELECT seq, line FROM audit_log ORDER BY seq DESC LIMIT %s) t ORDER BY seq",
                (n,)).fetchall()
            return [json.loads(r[0]) for r in rows]
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()[-n:]]

    def verify(self) -> tuple[bool, int | None]:
        """Re-read the whole log from storage and check the hash chain."""
        if self._conn is not None:
            rows = self._conn.execute("SELECT line, sha256 FROM audit_log ORDER BY seq").fetchall()
            return verify_lines([r[0] for r in rows], [r[1] for r in rows])
        return verify_lines(self.path.read_text(encoding="utf-8").splitlines())
