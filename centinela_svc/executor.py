"""Deterministic executor. No AI here.

Validates a Proposal against the closed MENU, the latest snapshot and the
protected-process list, and only then calls the victim's /kill endpoint.
"""
from __future__ import annotations

import httpx

from audit import AuditLog
from domain import (MENU, NO_ACTION, PROTECTED_CMDLINE_TOKENS, PROTECTED_NAMES,
                    Decision, Proposal)


def validate(proposal: Proposal, snapshot: dict | None) -> tuple[bool, str, dict | None]:
    """Return (ok, reason, target_process). Pure function."""
    if proposal.discarded:
        return False, f"discarded proposal: {proposal.error}", None
    if proposal.accion not in MENU:
        return False, f"action {proposal.accion!r} not in menu {sorted(MENU)}", None
    if not isinstance(proposal.pid, int) or isinstance(proposal.pid, bool):
        return False, "missing or non-integer target pid", None
    if proposal.pid <= 1:
        return False, f"pid {proposal.pid} is protected (init)", None
    if not snapshot:
        return False, "no snapshot available", None
    target = next((p for p in snapshot.get("processes", []) if p["pid"] == proposal.pid), None)
    if target is None:
        return False, f"pid {proposal.pid} not present in latest snapshot", None
    if target["name"] != proposal.nombre:
        return False, f"name mismatch: proposed {proposal.nombre!r}, actual {target['name']!r}", target
    cmdline = " ".join(target.get("cmdline") or [])
    if target["name"] in PROTECTED_NAMES:
        return False, f"target {target['name']!r} is a protected process", target
    hit = next((tok for tok in PROTECTED_CMDLINE_TOKENS if tok in cmdline), None)
    if hit:
        return False, f"target cmdline matches protected token {hit!r}", target
    return True, "validated: action in menu, pid present, name matches, not protected", target


class Executor:
    def __init__(self, victim_url: str, token: str, audit: AuditLog, http: httpx.AsyncClient) -> None:
        self.victim_url = victim_url.rstrip("/")
        self.token = token
        self.audit = audit
        self.http = http

    async def handle(self, proposal: Proposal, snapshot: dict | None) -> Decision:
        self.audit.append("proposal", proposal.to_dict())
        if not proposal.discarded and proposal.accion == NO_ACTION:
            decision = Decision(proposal.id, "noop", "model proposed no action")
            self.audit.append("decision", decision.to_dict())
            return decision

        ok, reason, _target = validate(proposal, snapshot)
        if not ok:
            decision = Decision(proposal.id, "rejected", reason, pid=proposal.pid)
            self.audit.append("decision", decision.to_dict())
            return decision

        self.audit.append("decision", {"proposal_id": proposal.id, "status": "approved", "reason": reason})
        result = await self.kill(proposal.pid)
        status = "executed" if result.get("status_code") == 200 else "failed"
        decision = Decision(proposal.id, status, reason if status == "executed" else
                            f"victim refused: {result}", pid=proposal.pid, result=result)
        self.audit.append("action_result", decision.to_dict())
        return decision

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
