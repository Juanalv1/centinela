"""Invite-only members and roles for the dashboard.

Members live in their own table of the audit database (never the victim's, never
inside the hash chain), and every change is also appended to the hash-chained
audit log as `kind: "member"`. Without `AUDIT_DATABASE_URL` the store is in
memory, seeded from `ADMIN_EMAILS` on every start: NOT persistent.

Unlike the audience store, writes are never swallowed: a failed write raises
`MemberError("unavailable")` so the admin sees the error. Guards that depend on
other rows (last admin) run inside one transaction with the admin rows locked,
so two containers overlapping during a deploy cannot both demote the last two admins.
"""
from __future__ import annotations

import logging
import re
import threading
import time

log = logging.getLogger("centinela.members")

ROLES = ("admin", "viewer")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")
EMAIL_MAX = 254

STORE_SCHEMA = """
CREATE TABLE IF NOT EXISTS member (
    email    text PRIMARY KEY,
    role     text NOT NULL CHECK (role IN ('admin', 'viewer')),
    added_by text NOT NULL,
    added_at double precision NOT NULL
)
"""


class MemberError(Exception):
    """`code` is one of: invalid, exists, not_found, last_admin, self, unavailable."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def normalize_email(raw: object) -> str | None:
    """` Ana@Example.COM ` -> `ana@example.com`; None when it does not look like an email."""
    if not isinstance(raw, str):
        return None
    email = raw.strip().lower()
    return email if len(email) <= EMAIL_MAX and EMAIL_RE.match(email) else None


def _row(r) -> dict:
    return {"email": r[0], "role": r[1], "added_by": r[2], "added_at": r[3]}


class MemberStore:
    def __init__(self, dsn: str | None = None, audit=None, clock=time.time) -> None:
        self._dsn = dsn
        self._audit = audit
        self._clock = clock
        self._conn = None
        self._lock = threading.Lock()
        self._mem: dict[str, dict] = {}  # used only without a database

    # --- plumbing ---------------------------------------------------------
    def _connection(self):
        if self._conn is None:
            import psycopg

            self._conn = psycopg.connect(self._dsn, autocommit=True, connect_timeout=3)
            self._conn.execute(STORE_SCHEMA)
        return self._conn

    def _db(self, fn):
        """Run `fn(conn)` under the lock; any database failure resets the connection and surfaces."""
        with self._lock:
            try:
                return fn(self._connection())
            except MemberError:
                raise
            except Exception as exc:
                self._conn = None  # reconnect on the next call
                log.warning("member store failed: %s", exc)
                raise MemberError("unavailable") from exc

    def _emit(self, action: str, email: str, role: str | None, actor: str) -> None:
        if self._audit is not None:
            self._audit.append("member", {"action": action, "email": email, "role": role, "actor": actor})

    # --- reads ------------------------------------------------------------
    def list(self) -> list[dict]:
        if not self._dsn:
            with self._lock:
                return sorted(self._mem.values(), key=lambda m: (m["added_at"], m["email"]))
        return self._db(lambda c: [_row(r) for r in c.execute(
            "SELECT email, role, added_by, added_at FROM member ORDER BY added_at, email").fetchall()])

    def role_of(self, email: str) -> str | None:
        email = (email or "").strip().lower()
        if not self._dsn:
            with self._lock:
                m = self._mem.get(email)
                return m["role"] if m else None
        row = self._db(lambda c: c.execute("SELECT role FROM member WHERE email = %s", (email,)).fetchone())
        return row[0] if row else None

    # --- bootstrap --------------------------------------------------------
    def bootstrap(self, emails) -> list[str]:
        """When the table is empty, make `emails` the first admins. Returns the emails inserted."""
        wanted = sorted({e for e in (normalize_email(x) for x in emails) if e})
        if not wanted:
            return []
        now = self._clock()
        if not self._dsn:
            with self._lock:
                if self._mem:
                    return []
                for e in wanted:
                    self._mem[e] = {"email": e, "role": "admin", "added_by": "bootstrap", "added_at": now}
            inserted = wanted
        else:
            def run(conn):
                with conn.transaction():
                    conn.execute("LOCK TABLE member IN EXCLUSIVE MODE")  # two containers may start together
                    if conn.execute("SELECT 1 FROM member LIMIT 1").fetchone():
                        return []
                    for e in wanted:
                        conn.execute("INSERT INTO member (email, role, added_by, added_at) "
                                     "VALUES (%s, 'admin', 'bootstrap', %s)", (e, now))
                    return wanted
            inserted = self._db(run)
        for e in inserted:
            self._emit("add", e, "admin", "bootstrap")
        return inserted

    # --- writes -----------------------------------------------------------
    def add(self, email: str, role: str, actor: str) -> dict:
        email, actor = normalize_email(email), (actor or "").strip().lower()
        if not email or role not in ROLES:
            raise MemberError("invalid")
        now = self._clock()
        if not self._dsn:
            with self._lock:
                if email in self._mem:
                    raise MemberError("exists")
                member = self._mem[email] = {"email": email, "role": role, "added_by": actor, "added_at": now}
        else:
            def run(conn):
                row = conn.execute(
                    "INSERT INTO member (email, role, added_by, added_at) VALUES (%s, %s, %s, %s) "
                    "ON CONFLICT (email) DO NOTHING RETURNING email, role, added_by, added_at",
                    (email, role, actor, now)).fetchone()
                if row is None:
                    raise MemberError("exists")
                return _row(row)
            member = self._db(run)
        self._emit("add", email, role, actor)
        return dict(member)

    def set_role(self, email: str, role: str, actor: str) -> dict:
        email, actor = normalize_email(email), (actor or "").strip().lower()
        if not email or role not in ROLES:
            raise MemberError("invalid")
        if email == actor:
            raise MemberError("self")
        if not self._dsn:
            with self._lock:
                member = self._mem.get(email)
                if member is None:
                    raise MemberError("not_found")
                if member["role"] == "admin" and role != "admin" and self._admins() <= 1:
                    raise MemberError("last_admin")
                member["role"] = role
                result = dict(member)
        else:
            def run(conn):
                with conn.transaction():
                    admins = {r[0] for r in conn.execute(
                        "SELECT email FROM member WHERE role = 'admin' FOR UPDATE").fetchall()}
                    row = conn.execute("SELECT role FROM member WHERE email = %s FOR UPDATE", (email,)).fetchone()
                    if row is None:
                        raise MemberError("not_found")
                    if email in admins and role != "admin" and len(admins) <= 1:
                        raise MemberError("last_admin")
                    return _row(conn.execute(
                        "UPDATE member SET role = %s WHERE email = %s RETURNING email, role, added_by, added_at",
                        (role, email)).fetchone())
            result = self._db(run)
        self._emit("role", email, role, actor)
        return result

    def remove(self, email: str, actor: str) -> None:
        email, actor = normalize_email(email), (actor or "").strip().lower()
        if not email:
            raise MemberError("invalid")
        if email == actor:
            raise MemberError("self")
        if not self._dsn:
            with self._lock:
                member = self._mem.get(email)
                if member is None:
                    raise MemberError("not_found")
                if member["role"] == "admin" and self._admins() <= 1:
                    raise MemberError("last_admin")
                del self._mem[email]
        else:
            def run(conn):
                with conn.transaction():
                    admins = {r[0] for r in conn.execute(
                        "SELECT email FROM member WHERE role = 'admin' FOR UPDATE").fetchall()}
                    if email in admins and len(admins) <= 1:
                        raise MemberError("last_admin")
                    if conn.execute("DELETE FROM member WHERE email = %s RETURNING email", (email,)).fetchone() is None:
                        raise MemberError("not_found")
            self._db(run)
        self._emit("remove", email, None, actor)

    def _admins(self) -> int:
        return sum(1 for m in self._mem.values() if m["role"] == "admin")
