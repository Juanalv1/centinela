"""Victim adapters: the executor's least-privilege HTTP and Postgres channels, and the
mapping of the victim's /access-log rows to normalized access events."""
from __future__ import annotations

import httpx

from domain.access import VICTIM_SOURCE, AccessEvent, page_of


def from_victim_row(row: dict) -> AccessEvent | None:
    """The demo victim's /access-log row as an event; rows not made with a key are dropped."""
    if row.get("api_key_id") is None:
        return None
    return AccessEvent(VICTIM_SOURCE, row["id"], float(row["ts"]), row["api_key_id"], row["ip"], row["path"],
                       row["status"], row.get("bytes") or 0, row.get("method"), None, page_of(row.get("query")))


class VictimClient:
    """Least-privilege channel to the victim. Only the executor holds the token."""

    def __init__(self, victim_url: str, token: str, http: httpx.AsyncClient) -> None:
        self.victim_url = victim_url.rstrip("/")
        self.token = token
        self.http = http

    async def kill(self, pid: int) -> dict:
        if not self.token:
            return {"status_code": None, "error": "EXECUTOR_TOKEN not configured"}
        try:
            resp = await self.http.post(f"{self.victim_url}/kill", json={"pid": pid},
                                        headers={"X-Executor-Token": self.token}, timeout=10)
        except httpx.HTTPError as exc:
            return {"status_code": None, "error": str(exc)}
        try:
            body = resp.json()
        except ValueError:
            body = {"raw": resp.text[:200]}
        return {"status_code": resp.status_code, "body": body}


class VictimDb:
    """Case-2 actions through the executor's least-privilege Postgres role.

    The role can write only api_keys.status, ip_blocklist, sessions and
    user_suspensions, and never reads users (see victim/roles.sql). Database
    refusals surface as psycopg.errors.InsufficientPrivilege.
    """

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    async def _connect(self):
        import psycopg  # only needed for case-2 actions

        return await psycopg.AsyncConnection.connect(self.dsn, autocommit=True)

    async def policy(self, action: str, target_id: int) -> str | None:
        """Read-only checks that need the database. Return a rejection reason or None."""
        async with await self._connect() as conn:
            if action == "revoke_key":
                row = await (await conn.execute(
                    "SELECT protected FROM api_keys WHERE id = %s", (target_id,))).fetchone()
                if row is None:
                    return f"api key {target_id} does not exist"
                return f"api key {target_id} is a protected key" if row[0] else None
            protected = (await (await conn.execute(
                "SELECT is_protected_user(%s)", (target_id,))).fetchone())[0]
            return f"user {target_id} is a protected user" if protected else None

    async def act(self, action: str, value: str, why: str) -> dict:
        async with await self._connect() as conn:
            if action == "revoke_key":
                cur = await conn.execute("UPDATE api_keys SET status = 'revoked' "
                                         "WHERE id = %s AND status <> 'revoked'", (int(value),))
                return {"revoked": cur.rowcount}
            if action == "block_ip":
                cur = await conn.execute("INSERT INTO ip_blocklist (ip, reason) VALUES (%s, %s) "
                                         "ON CONFLICT DO NOTHING", (value, why))
                return {"blocked": cur.rowcount}
            if action == "close_sessions":
                cur = await conn.execute("DELETE FROM sessions WHERE user_id = %s", (int(value),))
                return {"closed": cur.rowcount}
            if action == "suspend_user":
                async with conn.transaction():
                    cur = await conn.execute("INSERT INTO user_suspensions (user_id, reason) VALUES (%s, %s) "
                                             "ON CONFLICT DO NOTHING", (int(value), why))
                    closed = await conn.execute("DELETE FROM sessions WHERE user_id = %s", (int(value),))
                return {"suspended": cur.rowcount, "closed": closed.rowcount}
        raise ValueError(f"no database handler for {action!r}")
