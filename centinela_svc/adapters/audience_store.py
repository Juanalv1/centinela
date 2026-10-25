"""Postgres persistence for audience events (adapter for application.audience)."""
from __future__ import annotations

import logging
import threading

log = logging.getLogger("centinela.audience")

STORE_SCHEMA = """
CREATE TABLE IF NOT EXISTS audience_event (
    id     bigserial PRIMARY KEY,
    ts     double precision NOT NULL,
    handle text NOT NULL,
    kind   text NOT NULL,
    data   jsonb NOT NULL DEFAULT '{}'
)
"""


class AudienceStore:
    """Audience events in their own table of the audit database (never the victim's, never the hash chain).

    Best effort: any database error is logged and swallowed, so a flaky database
    can never break /api/join or /api/participate. The connection is reopened lazily.
    """

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._conn = None
        self._lock = threading.Lock()
        self._connect()  # also creates the table; a failure only disables persistence until the next write

    def _connect(self):
        import psycopg  # only needed when a database is configured

        try:
            self._conn = psycopg.connect(self._dsn, autocommit=True, connect_timeout=3)
            self._conn.execute(STORE_SCHEMA)
        except Exception as exc:
            self._conn = None
            log.warning("audience store unavailable: %s", exc)
        return self._conn

    def append(self, handle: str, kind: str, ts: float, data: dict) -> None:
        from psycopg.types.json import Jsonb

        with self._lock:
            try:
                conn = self._conn or self._connect()
                if conn is not None:
                    conn.execute("INSERT INTO audience_event (ts, handle, kind, data) VALUES (%s, %s, %s, %s)",
                                 (ts, handle, kind, Jsonb(data)))
            except Exception as exc:
                self._conn = None  # reconnect on the next write
                log.warning("audience event lost: %s", exc)

    def load(self) -> list[dict]:
        """Every stored event, oldest first; empty when the database is unreachable."""
        with self._lock:
            try:
                conn = self._conn or self._connect()
                rows = (conn.execute("SELECT ts, handle, kind, data FROM audience_event ORDER BY id")
                        .fetchall() if conn else [])
            except Exception as exc:
                self._conn = None
                log.warning("audience history not loaded: %s", exc)
                return []
        return [{"ts": r[0], "handle": r[1], "kind": r[2], "data": r[3]} for r in rows]
