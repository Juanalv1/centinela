"""Rebuild the dashboard history (proposals, decisions, incidents) from audit entries. No I/O here.

The audit log is the only thing that survives a restart, so this replays it into the
same shapes `Monitor.state()` serves. Pending approvals are never revived: their
target pids belong to the previous process, so unresolved ones are returned
separately and the monitor shows them as expired.
"""
from __future__ import annotations

MAX_INCIDENTS = 50
INCIDENT_FIELDS = ("pid", "name", "cmdline", "attack_start", "proposal_at", "killed_at",
                   "gone_confirmed_at", "detection_s", "containment_s", "confirmed_s", "model_latency_s")


def replay(entries: list[dict]) -> dict:
    """Return oldest-first `proposals`/`decisions`, newest-first `incidents`, the
    `unresolved` pending_approval decisions and the highest `max_id` proposal id seen."""
    proposals: list[dict] = []
    decisions: list[dict] = []
    by_id: dict[int, dict] = {}
    pending: dict[int, dict] = {}
    killed: list[dict] = []  # executed decisions, oldest first
    facts: dict[int, dict] = {}  # proposal_id -> incident facts written by the monitor
    max_id = 0
    for entry in entries:
        kind, data = entry.get("kind"), entry.get("data")
        if not isinstance(data, dict):
            continue
        if kind == "proposal" and isinstance(data.get("id"), int):
            proposals.append(data)
            by_id[data["id"]] = data
            max_id = max(max_id, data["id"])
        elif kind in ("decision", "action_result"):
            pid = data.get("proposal_id")
            if data.get("status") == "approved":  # internal step; never part of the live history
                continue
            decisions.append(data)
            if data.get("status") == "pending_approval":
                pending[pid] = data
            else:
                pending.pop(pid, None)
            if kind == "action_result" and data.get("status") == "executed":
                killed.append(data)
        elif kind == "approval":
            pending.pop(data.get("proposal_id"), None)
        elif kind == "incident":
            facts.setdefault(data.get("proposal_id"), {}).update(data)

    incidents = []
    for dec in killed:
        prop = by_id.get(dec.get("proposal_id"))
        if prop is None or prop.get("action") != "kill_process" or not prop.get("target"):
            continue
        # Entries from before incident facts were audited only know these fields; the rest stay null.
        inc = {f: None for f in INCIDENT_FIELDS}
        inc.update(pid=int(prop["target"]["value"]), proposal_at=prop.get("created_at"),
                   killed_at=dec.get("at"), model_latency_s=prop.get("latency_s"))
        inc.update({k: v for k, v in facts.get(prop["id"], {}).items() if k in INCIDENT_FIELDS})
        inc.update(proposal_id=prop["id"], restored=True)
        incidents.append(inc)
    return {"proposals": proposals, "decisions": decisions, "max_id": max_id,
            "incidents": incidents[::-1][:MAX_INCIDENTS], "unresolved": list(pending.values())}
