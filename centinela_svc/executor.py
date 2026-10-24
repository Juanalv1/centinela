"""Deterministic executor. No AI here.

Every proposal goes through the same layers, in order:
  menu    action is on the closed MENU and the target type matches it
  policy  the concrete target is allowed (kill_process: only job-runner pids)
  lane    taken from MENU; low model confidence can only tighten AUTO to APPROVAL
  infra   the victim performs the action with least privilege and may still refuse
"""
from __future__ import annotations

import httpx

from audit import AuditLog
from domain import MENU, NO_ACTION, RECOMMEND_ACTION, Decision, Lane, Proposal

NOT_IMPLEMENTED = "not implemented yet (case 2)"


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


def check_policy(proposal: Proposal, snapshot: dict | None) -> str | None:
    """Return a rejection reason, or None if the concrete target is allowed."""
    if proposal.action != "kill_process":
        return None  # case-2 actions define their own policy when implemented
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


class Executor:
    def __init__(self, victim, audit: AuditLog) -> None:
        self.victim = victim  # anything with `async kill(pid) -> dict`
        self.audit = audit
        self._pending: dict[int, Proposal] = {}

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
        if reason := check_policy(proposal, snapshot):
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
        if reason := check_policy(proposal, snapshot):
            return self._decide(Decision(proposal_id, "rejected", reason, "policy", target))
        self.audit.append("approval", {"proposal_id": proposal_id, "approved": True})
        return await self._execute(proposal)

    async def _execute(self, proposal: Proposal) -> Decision:
        pid, target = proposal.id, proposal.target
        if proposal.action != "kill_process":
            return self._decide(Decision(pid, "failed", NOT_IMPLEMENTED, target=target), "action_result")
        self.audit.append("decision", {"proposal_id": pid, "status": "approved",
                                       "reason": "menu and policy checks passed"})
        result = await self.victim.kill(int(target.value))
        if result.get("status_code") == 200:
            return self._decide(Decision(pid, "executed", "menu and policy checks passed; victim killed it",
                                         target=target, result=result), "action_result")
        return self._decide(Decision(pid, "failed", f"victim refused: {result}", "infra", target, result),
                            "action_result")
