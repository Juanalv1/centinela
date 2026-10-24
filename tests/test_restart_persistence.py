"""A restart must not wipe the dashboard history or the audience (audit log + audience table survive)."""
import asyncio

import pytest
from fastapi.testclient import TestClient

from audience import AudienceState, AudienceStore
from audit import AuditLog
from conftest import SVC, load_module
from domain import Proposal, Target
from executor import Executor
from monitor import Monitor
from pg import fresh_db

JOB_PID = 4242
SNAPSHOT = {"processes": [{"pid": JOB_PID, "name": "python", "cmdline": ["python", "/app/jobs/report.py"],
                           "managed": True, "create_time": 1000.0}]}


class FakeVictim:
    async def kill(self, pid: int) -> dict:
        return {"status_code": 200, "body": {"killed": True, "pid": pid}}


@pytest.fixture(params=["pg", "jsonl"])
def open_audit(request, tmp_path):
    """Factory for AuditLog over the same storage: calling it again simulates a restart."""
    dsn = fresh_db() if request.param == "pg" else None
    return lambda: AuditLog(str(tmp_path / "audit.jsonl"), dsn=dsn)


def boot(audit: AuditLog) -> Monitor:
    mon = Monitor("http://victim", 1.0, None, Executor(FakeVictim(), audit), None)
    mon.restore(audit.recent(2000))
    return mon


def kill_proposal(confidence="high", **kw) -> Proposal:
    return Proposal("kill_process", Target("process", str(JOB_PID)), "burning cpu", ["cpu 99%"],
                    confidence, "claude", **kw)


def test_restart_restores_proposals_decisions_and_incidents(open_audit):
    first = boot(open_audit())
    first.latest = SNAPSHOT
    asyncio.run(first.submit(kill_proposal()))
    asyncio.run(first.submit(Proposal("none", None, "all quiet", [], "high", "claude")))
    first._confirm_kills(set(), 1010.0)  # the killed pid is gone
    live = first.state()
    assert live["incidents"][0]["name"] == "python" and live["incidents"][0]["confirmed_s"] is not None

    second = boot(open_audit())  # simulated restart
    back = second.state()
    assert back["proposals"] == live["proposals"]
    assert back["decisions"] == live["decisions"]
    inc, was = back["incidents"][0], live["incidents"][0]
    assert inc.pop("restored") is True
    assert inc == was
    assert second.executor.pending() == []


def test_new_proposal_ids_continue_after_the_audit_log(open_audit):
    audit = open_audit()
    mon = boot(audit)
    asyncio.run(mon.submit(Proposal("none", None, "quiet", [], "high", "claude", id=900)))
    boot(open_audit())
    assert Proposal("none", None, "next", [], "high", "claude").id > 900


def test_unresolved_pending_approval_comes_back_expired(open_audit):
    first = boot(open_audit())
    first.latest = SNAPSHOT
    stale = kill_proposal("low")  # low confidence escalates to human approval
    answered = kill_proposal("low")
    asyncio.run(first.submit(stale))
    asyncio.run(first.submit(answered))
    asyncio.run(first.resolve_approval(answered.id, False))
    assert [a["id"] for a in first.executor.pending()] == [stale.id]

    second = boot(open_audit())
    expired = [d for d in second.decisions if d["status"] == "expired"]
    assert [(d["proposal_id"], d["reason"]) for d in expired] == [(stale.id, "reinicio del servicio")]
    assert second.executor.pending() == []
    assert asyncio.run(second.resolve_approval(stale.id, True)) is None  # cannot be approved any more

    third = boot(open_audit())  # the expiry is audited, so it is not repeated
    assert len([d for d in third.decisions if d["status"] == "expired"]) == 1


def test_incident_from_before_incident_facts_were_audited(open_audit):
    audit = open_audit()
    prop = kill_proposal()
    audit.append("proposal", prop.to_dict())
    audit.append("decision", {"proposal_id": prop.id, "status": "approved", "reason": "ok"})
    audit.append("action_result", {"proposal_id": prop.id, "status": "executed", "reason": "killed",
                                   "layer": None, "target": {"type": "process", "value": str(JOB_PID)},
                                   "result": {"status_code": 200}, "at": 1005.0})
    mon = boot(open_audit())
    inc = mon.incidents[0]
    assert inc["pid"] == JOB_PID and inc["killed_at"] == 1005.0 and inc["restored"] is True
    assert inc["name"] is None and inc["containment_s"] is None and inc["confirmed_s"] is None
    mon._confirm_kills(set(), 2000.0)  # a restored incident is never re-confirmed (the pid may be reused)
    assert inc["confirmed_s"] is None
    assert [d["status"] for d in mon.decisions] == ["executed"]  # "approved" is internal, never listed


# --- app wiring ------------------------------------------------------------
def app_client(monkeypatch, tmp_path, name, dsn=None):
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("VICTIM_URL", "http://127.0.0.1:9")  # unreachable; monitor records errors
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("APPROVER_TOKEN", raising=False)
    if dsn:
        monkeypatch.setenv("AUDIT_DATABASE_URL", dsn)
    else:
        monkeypatch.delenv("AUDIT_DATABASE_URL", raising=False)
    mod = load_module(name, SVC / "app.py")
    return mod, TestClient(mod.app)


def test_stale_approval_is_not_found_through_the_api(monkeypatch, tmp_path):
    old = AuditLog(str(tmp_path / "audit.jsonl"))
    prop = kill_proposal("low")
    old.append("proposal", prop.to_dict())
    old.append("decision", {"proposal_id": prop.id, "status": "pending_approval", "reason": "needs a human",
                            "layer": None, "target": {"type": "process", "value": str(JOB_PID)},
                            "result": None, "at": 1.0})
    _, client = app_client(monkeypatch, tmp_path, "centinela_app_restart_jsonl")
    with client:
        state = client.get("/api/state").json()
        assert state["approvals"] == []
        assert [d["status"] for d in state["decisions"]] == ["expired", "pending_approval"]
        assert client.post(f"/api/approvals/{prop.id}", json={"approve": True}).status_code == 404


def test_audience_survives_restart_through_the_app(monkeypatch, tmp_path):
    dsn = fresh_db()
    mod, client = app_client(monkeypatch, tmp_path, "centinela_app_restart_pg1", dsn)
    with client:
        assert client.post("/api/join", json={"handle": "@Vale"}).status_code == 200
        assert client.post("/api/participate", json={"handle": "vale", "attack": "inject"}).status_code == 200
        before = client.get("/api/live").json()
    assert before["people"] == 1 and len(before["activity"]) == 1

    _, again = app_client(monkeypatch, tmp_path, "centinela_app_restart_pg2", dsn)
    with again:
        assert again.get("/api/live").json() == before


def test_audience_without_database_stays_in_memory(monkeypatch, tmp_path):
    mod, client = app_client(monkeypatch, tmp_path, "centinela_app_restart_mem")
    with client:
        assert client.post("/api/join", json={"handle": "vale"}).status_code == 200
        assert mod.audience.store is None
        assert client.get("/api/live").json()["people"] == 1


# --- audience store --------------------------------------------------------
def test_audience_rebuilds_board_feed_and_restarts_cooldowns():
    dsn = fresh_db()
    a = AudienceState(store=AudienceStore(dsn))
    for handle in ("vale", "tomi"):
        a.join(handle, handle)
    a.join("vale", "again")  # a repeated join is not a new participant
    a.record("vale", "inject", {"status": "rejected", "layer": "policy"})
    a.record("vale", "miner", {"status": "launched", "containment_s": 7.5})
    a.record("tomi", "miner", {"status": "launched", "containment_s": 3.0})

    b = AudienceState(store=AudienceStore(dsn))  # simulated restart
    b.restore()
    assert b.live() == a.live()
    assert b.participants["vale"]["best_s"] == 7.5
    b.check_action("vale")  # rate-limit timers are not restored


def test_audience_store_takes_hostile_handles_as_data():
    dsn = fresh_db()
    store = AudienceStore(dsn)
    evil = "x'); DROP TABLE audience_event; --"
    store.append(evil, "join", 1.0, {"note": "'; DELETE FROM audience_event; --"})
    assert [e["handle"] for e in store.load()] == [evil]


def test_audience_database_failure_never_breaks_join_or_record():
    dsn = fresh_db()
    store = AudienceStore(dsn)
    store._conn.close()
    store._dsn = "postgresql://nobody@127.0.0.1:9/none"  # reconnecting fails too
    a = AudienceState(store=store)
    a.join("vale", "1.1.1.1")
    a.record("vale", "inject", {"status": "rejected"})
    assert a.live()["people"] == 1 and len(a.activity) == 1
    assert store.load() == []
