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

        self._conn = psycopg.connect(self._dsn, autocommit=True)
        self._conn.execute(SCHEMA)
        rows = self._conn.execute(
            "SELECT line FROM (SELECT seq, line FROM audit_log ORDER BY seq DESC LIMIT %s) t ORDER BY seq",
            (self.keep,)).fetchall()
        self._resume([r[0] for r in rows])

    def append(self, kind: str, data: dict) -> dict:
        with self._lock:
            seq = self._seq + 1
            entry = {"seq": seq, "ts": time.time(), "kind": kind,
                     "prev_sha256": self._prev, "data": data}
            line = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
            sha = _sha(line)
            if self._conn is not None:
                # Fails closed: if the write does not land, nothing is acknowledged.
                self._conn.execute(
                    "INSERT INTO audit_log (seq, ts, kind, prev_sha256, sha256, line) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (seq, entry["ts"], kind, self._prev, sha, line))
            else:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            self._seq = seq
            self._prev = sha
            self.entries.append(entry)
            del self.entries[:-self.keep]
            return entry

    def verify(self) -> tuple[bool, int | None]:
        """Re-read the whole log from storage and check the hash chain."""
        if self._conn is not None:
            rows = self._conn.execute("SELECT line, sha256 FROM audit_log ORDER BY seq").fetchall()
            return verify_lines([r[0] for r in rows], [r[1] for r in rows])
        return verify_lines(self.path.read_text(encoding="utf-8").splitlines())
