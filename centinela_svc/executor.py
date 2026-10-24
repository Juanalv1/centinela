"""Deterministic executor. No AI here.

Every proposal goes through the same layers, in order:
  menu    action is on the closed MENU and the target type matches it
  policy  the concrete target is allowed (kill_process: only job-runner pids;
          block_ip: never protected networks; keys/users: never admins)
  lane    taken from MENU; low model confidence can only tighten AUTO to APPROVAL
  infra   the victim performs the action with least privilege and may still refuse
          (kernel EPERM for /kill, Postgres `permission denied` for case-2 actions)
"""
from __future__ import annotations

import ipaddress

import httpx

from audit import AuditLog
from domain import MENU, NO_ACTION, RECOMMEND_ACTION, Decision, Lane, Proposal

# Networks block_ip never touches: loopback, private and link-local ranges
# (internal service traffic). The office network is added from OFFICE_CIDR.
BASE_PROTECTED_NETWORKS: tuple[str, ...] = (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
)


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


def _positive_int(value: str) -> int | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def check_menu(proposal: Proposal) -> str | None:
    """Return a rejection reason, or None if the proposal fits the closed menu."""
    spec = MENU.get(proposal.action or "")
    if spec is None:
        return f"action {proposal.action!r} not in menu {sorted(MENU)}"
    if proposal.target is None:
        return f"{proposal.action} requires a {spec.target_type} target"
    if proposal.target.type != spec.target_type:
        return (f"target type {proposal.target.type!r} does not match "
                f"{proposal.action} (expects {spec.target_type!r})")
    return None


def check_policy(proposal: Proposal, snapshot: dict | None,
                 protected_networks: tuple[str, ...] = ()) -> str | None:
    """Return a rejection reason, or None if the concrete target is allowed. No I/O."""
    value = proposal.target.value
    if proposal.action == "block_ip":
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return f"ip target {value!r} is not a valid ip"
        for net in (*BASE_PROTECTED_NETWORKS, *protected_networks):
            network = ipaddress.ip_network(net, strict=False)
            if ip.version == network.version and ip in network:
                return f"ip {ip} is in protected network {network}"
        return None
    if proposal.action == "revoke_key":
        return None if _positive_int(value) else f"key target {value!r} is not a key id"
    if proposal.action in ("close_sessions", "suspend_user"):
        return None if _positive_int(value) else f"user target {value!r} is not a user id"
    try:
        pid = int(proposal.target.value)
    except (TypeError, ValueError):
        return f"process target {proposal.target.value!r} is not a pid"
    if pid <= 1:
        return f"pid {pid} is protected (init)"
    if not snapshot:
        return "no snapshot available"
    proc = next((p for p in snapshot.get("processes", []) if p.get("pid") == pid), None)
    if proc is None:
        return f"pid {pid} not present in latest snapshot"
    # Allowlist: only processes started by the victim's job runner may be killed.
    if proc.get("managed") is not True:
        return f"pid {pid} ({proc.get('name')!r}) was not started by the job runner"
    return None


DB_ACTIONS = ("revoke_key", "block_ip", "close_sessions", "suspend_user")


class Executor:
    def __init__(self, victim, audit: AuditLog, db: VictimDb | None = None,
                 protected_networks: tuple[str, ...] = ()) -> None:
        self.victim = victim  # anything with `async kill(pid) -> dict`
        self.audit = audit
        self.db = db  # case-2 actions; None until EXECUTOR_DATABASE_URL is set
        self.protected_networks = tuple(protected_networks)
        self._pending: dict[int, Proposal] = {}

    async def _policy(self, proposal: Proposal, snapshot: dict | None) -> str | None:
        if reason := check_policy(proposal, snapshot, self.protected_networks):
            return reason
        if self.db is not None and proposal.action in ("revoke_key", "close_sessions", "suspend_user"):
            import psycopg

            try:
                return await self.db.policy(proposal.action, int(proposal.target.value))
            except psycopg.Error as exc:
                return f"policy lookup failed: {exc}".strip()  # fail closed
        return None

    def _decide(self, decision: Decision, kind: str = "decision") -> Decision:
        self.audit.append(kind, decision.to_dict())
        return decision

    async def handle(self, proposal: Proposal, snapshot: dict | None) -> Decision:
        self.audit.append("proposal", proposal.to_dict())
        pid, target = proposal.id, proposal.target
        if proposal.discarded:
            return self._decide(Decision(pid, "rejected", f"discarded proposal: {proposal.error}", "menu"))
        if proposal.action == NO_ACTION:
            return self._decide(Decision(pid, "noop", "model proposed no action"))
        if proposal.action == RECOMMEND_ACTION:
            return self._decide(Decision(pid, "recommended", "recommendation for a human; never executed",
                                         target=target))
        if reason := check_menu(proposal):
            return self._decide(Decision(pid, "rejected", reason, "menu", target))
        if reason := await self._policy(proposal, snapshot):
            return self._decide(Decision(pid, "rejected", reason, "policy", target))

        lane = MENU[proposal.action].lane
        if lane is Lane.AUTO and proposal.confidence not in ("medium", "high"):
            lane = Lane.APPROVAL  # the model can only tighten, never relax
        if lane is Lane.APPROVAL:
            self._pending[pid] = proposal
            why = ("action requires human approval" if MENU[proposal.action].lane is Lane.APPROVAL
                   else f"model confidence {proposal.confidence!r} escalated it to human approval")
            return self._decide(Decision(pid, "pending_approval", why, target=target))
        return await self._execute(proposal)

    def pending(self) -> list[dict]:
        return [p.to_dict() for p in self._pending.values()]

    async def resolve(self, proposal_id: int, approve: bool, snapshot: dict | None) -> Decision | None:
        """Approve or discard a pending proposal. Approval re-runs menu and policy checks."""
        proposal = self._pending.pop(proposal_id, None)
        if proposal is None:
            return None
        target = proposal.target
        if not approve:
            return self._decide(Decision(proposal_id, "rejected", "discarded by human approver",
                                         target=target))
        if reason := check_menu(proposal):
            return self._decide(Decision(proposal_id, "rejected", reason, "menu", target))
        if reason := await self._policy(proposal, snapshot):
            return self._decide(Decision(proposal_id, "rejected", reason, "policy", target))
        self.audit.append("approval", {"proposal_id": proposal_id, "approved": True})
        return await self._execute(proposal)

    async def bypass_demo(self, proposal: Proposal) -> Decision:
        """Demo only: skip menu and policy, as if the executor itself were compromised.

        Still uses the least-privilege database role, so it shows what the
        infra layer alone refuses. Never called from the monitor loop.
        """
        self.audit.append("bypass_demo", proposal.to_dict())
        if proposal.action not in DB_ACTIONS or proposal.target is None:
            return self._decide(Decision(proposal.id, "rejected", "bypass demo covers case-2 actions only",
                                         "menu", proposal.target))
        return await self._act_db(proposal, "executor checks bypassed (demo)")

    async def _execute(self, proposal: Proposal) -> Decision:
        pid, target = proposal.id, proposal.target
        self.audit.append("decision", {"proposal_id": pid, "status": "approved",
                                       "reason": "menu and policy checks passed"})
        if proposal.action in DB_ACTIONS:
            return await self._act_db(proposal, "menu and policy checks passed")
        result = await self.victim.kill(int(target.value))
        if result.get("status_code") == 200:
            return self._decide(Decision(pid, "executed", "menu and policy checks passed; victim killed it",
                                         target=target, result=result), "action_result")
        return self._decide(Decision(pid, "failed", f"victim refused: {result}", "infra", target, result),
                            "action_result")

    async def _act_db(self, proposal: Proposal, passed: str) -> Decision:
        pid, target = proposal.id, proposal.target
        if self.db is None:
            return self._decide(Decision(pid, "failed", "EXECUTOR_DATABASE_URL not configured", "infra",
                                         target), "action_result")
        import psycopg

        try:
            result = await self.db.act(proposal.action, str(target.value).strip(),
                                       (proposal.rationale or "centinela")[:200])
        except psycopg.errors.InsufficientPrivilege as exc:
            return self._decide(Decision(pid, "failed", f"database refused: {exc}".strip(), "infra", target,
                                         {"sqlstate": exc.sqlstate}), "action_result")
        except psycopg.Error as exc:
            return self._decide(Decision(pid, "failed", f"database error: {exc}".strip(), "infra", target,
                                         {"sqlstate": getattr(exc, "sqlstate", None)}), "action_result")
        if not any(result.values()):
            return self._decide(Decision(pid, "noop", f"{proposal.action}: nothing to change (already applied)",
                                         target=target, result=result), "action_result")
        return self._decide(Decision(pid, "executed", f"{passed}; {proposal.action} applied", target=target,
                                     result=result), "action_result")
