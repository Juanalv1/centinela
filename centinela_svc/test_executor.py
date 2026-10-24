"""Executor rules, checked without network (fake victim client)."""
import asyncio

import pytest

from audit import AuditLog
from domain import MENU, Lane, Proposal, Target
from executor import Executor

JOB_PID = 4242
DB_PID = 7


class FakeVictim:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code
        self.killed: list[int] = []

    async def kill(self, pid: int) -> dict:
        self.killed.append(pid)
        if self.status_code == 403:
            return {"status_code": 403, "body": {"error": "kernel denied: EPERM"}}
        return {"status_code": self.status_code, "body": {"killed": True, "pid": pid}}


SNAPSHOT = {
    "processes": [
        {"pid": 1, "name": "sh", "cmdline": ["sh"], "managed": False},
        {"pid": DB_PID, "name": "db-sim", "cmdline": ["db-sim", "infinity"], "managed": False},
        {"pid": JOB_PID, "name": "python", "cmdline": ["python", "/app/jobs/report.py"], "managed": True},
    ]
}


@pytest.fixture
def victim():
    return FakeVictim()


@pytest.fixture
def executor(victim, tmp_path):
    return Executor(victim, AuditLog(str(tmp_path / "audit.jsonl")))


def proposal(action="kill_process", ttype="process", value=str(JOB_PID), confidence="high", **kw):
    target = Target(ttype, value) if ttype is not None else None
    return Proposal(action=action, target=target, rationale="test", evidence=["cpu 99%"],
                    confidence=confidence, source=kw.pop("source", "claude"), **kw)


def run(coro):
    return asyncio.run(coro)


# Rule 1: the lane comes only from MENU.
def test_lane_comes_from_menu_not_model(executor, victim):
    assert MENU["suspend_user"].lane is Lane.APPROVAL
    d = run(executor.handle(proposal("suspend_user", "user", "alice", confidence="high"), SNAPSHOT))
    assert d.status == "pending_approval"
    assert victim.killed == []
    assert [p["id"] for p in executor.pending()] == [d.proposal_id]


def test_auto_action_with_high_confidence_executes(executor, victim):
    d = run(executor.handle(proposal(), SNAPSHOT))
    assert d.status == "executed", d.reason
    assert d.layer is None
    assert victim.killed == [JOB_PID]


# Rule 2: the model can only tighten.
def test_low_confidence_escalates_auto_to_approval(executor, victim):
    d = run(executor.handle(proposal(confidence="low"), SNAPSHOT))
    assert d.status == "pending_approval"
    assert victim.killed == []


def test_unknown_confidence_is_treated_as_low(executor, victim):
    d = run(executor.handle(proposal(confidence="certain"), SNAPSHOT))
    assert d.status == "pending_approval"


def test_approval_runs_the_same_checks_and_executes(executor, victim):
    d = run(executor.handle(proposal(confidence="low"), SNAPSHOT))
    done = run(executor.resolve(d.proposal_id, True, SNAPSHOT))
    assert done.status == "executed"
    assert victim.killed == [JOB_PID]
    assert executor.pending() == []


def test_approval_rechecks_policy_against_new_snapshot(executor, victim):
    d = run(executor.handle(proposal(confidence="low"), SNAPSHOT))
    gone = {"processes": [p for p in SNAPSHOT["processes"] if p["pid"] != JOB_PID]}
    done = run(executor.resolve(d.proposal_id, True, gone))
    assert (done.status, done.layer) == ("rejected", "policy")
    assert victim.killed == []


def test_discarding_an_approval_never_executes(executor, victim):
    d = run(executor.handle(proposal(confidence="low"), SNAPSHOT))
    done = run(executor.resolve(d.proposal_id, False, SNAPSHOT))
    assert done.status == "rejected"
    assert victim.killed == []
    assert run(executor.resolve(d.proposal_id, True, SNAPSHOT)) is None


# Rule 3: target type must match the action.
def test_target_type_mismatch_is_rejected_by_menu(executor, victim):
    d = run(executor.handle(proposal(ttype="ip", value="10.0.0.1"), SNAPSHOT))
    assert (d.status, d.layer) == ("rejected", "menu")
    assert victim.killed == []


def test_missing_target_is_rejected_by_menu(executor):
    d = run(executor.handle(proposal(ttype=None), SNAPSHOT))
    assert (d.status, d.layer) == ("rejected", "menu")


# Rule 4: off-menu, none and recommend.
def test_action_not_in_menu_is_rejected_by_menu(executor, victim):
    d = run(executor.handle(proposal("delete_database", "process", str(DB_PID)), SNAPSHOT))
    assert (d.status, d.layer) == ("rejected", "menu")
    assert victim.killed == []


def test_recommend_is_never_executed(executor, victim):
    d = run(executor.handle(proposal("recommend", None), SNAPSHOT))
    assert d.status == "recommended"
    assert d.layer is None
    assert victim.killed == []


def test_none_is_noop(executor, victim):
    d = run(executor.handle(proposal("none", None), SNAPSHOT))
    assert d.status == "noop"


def test_discarded_proposal_is_rejected(executor, victim):
    p = Proposal(action=None, target=None, rationale="", evidence=[], confidence="low",
                 source="claude", discarded=True, error="model refused")
    d = run(executor.handle(p, SNAPSHOT))
    assert d.status == "rejected"
    assert victim.killed == []


# Rule 5 + allowlist: protected resources are stopped by policy.
@pytest.mark.parametrize("value", [str(DB_PID), "1", "0", "-3", "abc", "99999"])
def test_kill_outside_allowlist_is_rejected_by_policy(executor, victim, value):
    d = run(executor.handle(proposal(value=value, source="forged"), SNAPSHOT))
    assert (d.status, d.layer) == ("rejected", "policy"), d.reason
    assert victim.killed == []


def test_missing_snapshot_is_rejected_by_policy(executor, victim):
    d = run(executor.handle(proposal(), None))
    assert (d.status, d.layer) == ("rejected", "policy")


def test_victim_refusal_is_failed_at_infra_layer(tmp_path):
    victim = FakeVictim(status_code=403)
    ex = Executor(victim, AuditLog(str(tmp_path / "a.jsonl")))
    d = run(ex.handle(proposal(), SNAPSHOT))
    assert (d.status, d.layer) == ("failed", "infra")


# Rule 7: other menu actions are not implemented yet.
@pytest.mark.parametrize("action,ttype,value", [
    ("revoke_key", "key", "k1"), ("block_ip", "ip", "10.0.0.1"), ("close_sessions", "user", "alice"),
])
def test_unimplemented_actions_fail(executor, victim, action, ttype, value):
    d = run(executor.handle(proposal(action, ttype, value), SNAPSHOT))
    assert d.status == "failed"
    assert d.reason == "not implemented yet (case 2)"
    assert victim.killed == []
