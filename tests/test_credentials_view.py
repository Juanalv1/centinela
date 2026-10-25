"""credentials-view: per-key profile, state and latest AI rationale for the client dashboard."""
import asyncio
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import SVC, load_module
from test_keywatch import NOW, entry, office_history, watch_with
from test_monitor_keys import ATTACK, KEYS, FakeExecutor, Victim, _history, domain, from_victim_row

kw = load_module("centinela_keywatch_creds", SVC / "domain" / "keywatch.py")
monitor_mod = load_module("centinela_monitor_creds", SVC / "application" / "monitor.py")


def _attack(at=NOW, n=20):
    return [entry(at - timedelta(seconds=300 - 10 * p), ip="198.51.100.23", path="/api/customers",
                  query=f"page={p}", size=4000) for p in range(1, n + 1)]


# --- C1: keywatch overview ---------------------------------------------------

def test_overview_lists_quiet_keys_with_their_learned_profile():
    w = watch_with(office_history(key=2) + office_history(key=5))
    rows = w.overview(NOW.timestamp())
    assert [r["key_id"] for r in rows] == [2, 5]
    quiet = rows[0]
    assert quiet["flagged"] is False and quiet["score"] == 0
    assert quiet["window"] is None and quiet["signals"] is None
    assert quiet["profile"]["networks"] == ["203.0.113.0/24"]
    assert quiet["profile"]["endpoints"] == ["/api/invoices", "/api/me"]


def test_overview_shows_the_current_window_deviations_of_a_flagged_key():
    w = watch_with(office_history())
    w.ingest(_attack(), now=NOW.timestamp())
    [row] = w.overview(NOW.timestamp())
    assert row["flagged"] is True and row["score"] >= 3
    assert row["signals"]["new_endpoints"] == ["/api/customers"]
    assert row["window"]["requests"] == 20


def test_overview_shows_a_window_under_the_flag_score_without_flagging_it():
    w = watch_with(office_history())
    monday = NOW + timedelta(days=1, hours=-4)  # Monday 11:00, travelling user
    w.ingest([entry(monday - timedelta(seconds=60), ip="192.0.2.80")], now=monday.timestamp())
    [row] = w.overview(monday.timestamp())
    assert row["flagged"] is False and row["score"] == 1
    assert row["signals"]["new_ip"] is True


# --- C1: monitor credentials -------------------------------------------------

class KeyReasoner:
    def __init__(self):
        self.seen = []

    async def propose(self, metrics):
        self.seen.append(metrics)
        return domain.Proposal(action="revoke_key", target=domain.Target("key", "2"),
                               rationale="Red nueva, fuera de horario y descarga paginada.",
                               evidence=[], confidence="high", source="claude")


async def _monitor(victim, reasoner, ticks=1):
    async with httpx.AsyncClient(transport=httpx.MockTransport(victim)) as http:
        mon = monitor_mod.Monitor("http://victim", 2, reasoner, FakeExecutor(), http, victim_events=from_victim_row)
        mon._last_reason_at = float("inf")
        for _ in range(ticks):
            await mon.tick()
            for _ in range(3):
                await asyncio.sleep(0)
        return mon


def _by_id(rows):
    return {r["key_id"]: r for r in rows}


def test_credentials_merge_profile_state_label_and_latest_rationale():
    mon = asyncio.run(_monitor(Victim(_history() + ATTACK), KeyReasoner()))
    rows = _by_id(mon.credentials())
    assert set(rows) == {1, 2}  # every key the victim lists, even without history
    ana = rows[2]
    assert ana["label"] == "ana-integration" and ana["state"] == "suspicious" and ana["protected"] is False
    assert ana["profile"]["endpoints"] == ["/api/invoices"]
    assert ana["signals"]["new_endpoints"] == ["/api/customers"]
    assert ana["analysis"]["action"] == "revoke_key"
    assert ana["analysis"]["rationale"].startswith("Red nueva")
    assert ana["analysis"]["decision"] == "noop"
    admin = rows[1]
    assert admin["state"] == "active" and admin["profile"] is None and admin["analysis"] is None


def test_credentials_never_carry_key_values_or_user_names():
    mon = asyncio.run(_monitor(Victim(_history() + ATTACK), KeyReasoner()))
    for row in mon.credentials():
        assert not {"key", "key_hash", "token", "username", "role"} & set(row)


def test_a_revoked_key_is_shown_as_revoked_even_while_flagged():
    revoked = {**KEYS, "api_keys": [dict(k, status="revoked") if k["id"] == 2 else k for k in KEYS["api_keys"]]}

    class RevokedVictim(Victim):
        def __call__(self, request):
            if request.url.path == "/security-state":
                return httpx.Response(200, json=revoked)
            return super().__call__(request)

    mon = asyncio.run(_monitor(RevokedVictim(_history() + ATTACK), KeyReasoner()))
    row = _by_id(mon.credentials())[2]
    assert row["state"] == "revoked" and row["flagged"] is True


def test_a_quiet_look_by_the_ai_is_still_the_latest_analysis_of_that_key():
    class NoneReasoner(KeyReasoner):
        async def propose(self, metrics):
            self.seen.append(metrics)
            return domain.Proposal(action="none", target=None, rationale="Un viaje de trabajo.",
                                   evidence=[], confidence="medium", source="claude")

    mon = asyncio.run(_monitor(Victim(_history() + ATTACK), NoneReasoner()))
    analysis = _by_id(mon.credentials())[2]["analysis"]
    assert analysis["action"] == "none" and analysis["rationale"] == "Un viaje de trabajo."


# --- C1: /api/keys -----------------------------------------------------------

@pytest.fixture()
def app_mod(monkeypatch, tmp_path):
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("VICTIM_URL", "http://127.0.0.1:9")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("APPROVER_TOKEN", raising=False)
    return load_module("centinela_app_creds", SVC / "web" / "app.py")


def test_api_keys_serves_the_monitor_credentials(app_mod):
    with TestClient(app_mod.app) as client:
        app_mod.app.state.ctx.monitor.credentials = lambda: [{"key_id": 2, "label": "ana-integration", "state": "active"}]
        r = client.get("/api/keys")
        assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
        assert r.json() == {"keys": [{"key_id": 2, "label": "ana-integration", "state": "active"}]}


# --- C2: "mark as normal" feedback -------------------------------------------

def test_a_window_marked_normal_is_learned_and_the_same_behavior_no_longer_flags():
    w = watch_with(office_history())
    w.ingest(_attack(), now=NOW.timestamp())
    assert w.evaluate(NOW.timestamp())
    learned = w.learn_window(2, NOW.timestamp())
    assert len(learned) == 20
    later = NOW + timedelta(days=7)  # same export, same network, same time next week
    w.ingest(_attack(at=later), now=later.timestamp())
    assert w.evaluate(later.timestamp()) == []
    assert "/api/customers" in w.overview(later.timestamp())[0]["profile"]["endpoints"]


def test_learning_the_same_entries_twice_counts_them_once():
    w = watch_with(office_history())
    attack = _attack()
    w.learn(2, attack)
    busiest = w.profiles[2].summary(NOW.timestamp())["max_hour_bytes"]
    w.learn(2, attack)  # e.g. replayed from the audit log, then re-read from the access log
    assert w.profiles[2].summary(NOW.timestamp())["max_hour_bytes"] == busiest


class AuditExecutor(FakeExecutor):
    def __init__(self):
        self.appended = []
        outer = self

        class audit:
            entries: list = []

            @staticmethod
            def append(kind, data):
                outer.appended.append((kind, data))
                return {"kind": kind, "data": data}

        self.audit = audit


async def _monitor_with(victim, executor, ticks=1):
    async with httpx.AsyncClient(transport=httpx.MockTransport(victim)) as http:
        mon = monitor_mod.Monitor("http://victim", 2, KeyReasoner(), executor, http, victim_events=from_victim_row)
        mon._last_reason_at = float("inf")
        for _ in range(ticks):
            await mon.tick()
            for _ in range(3):
                await asyncio.sleep(0)
        return mon


def test_mark_normal_learns_the_window_and_audits_it_without_touching_the_key():
    executor, victim = AuditExecutor(), Victim(_history() + ATTACK)
    mon = asyncio.run(_monitor_with(victim, executor))
    calls = list(victim.calls)
    result = mon.mark_normal(2, "owner@example.com")
    assert result == {"key_id": 2, "learned": 20}
    [(kind, data)] = [a for a in executor.appended if a[0] == "key_feedback"]
    assert data["key_id"] == 2 and data["by"] == "owner@example.com" and len(data["entries"]) == 20
    assert set(data["entries"][0]) == {"source", "id", "ts", "ip", "path", "bytes"}
    assert victim.calls == calls  # nothing sent to the victim: revocation is never undone here
    row = _by_id(mon.credentials())[2]
    assert row["flagged"] is False and row["state"] == "active"
    assert mon.state()["key_activity"] == []


def test_mark_normal_refuses_a_key_that_is_not_flagged():
    executor = AuditExecutor()
    mon = asyncio.run(_monitor_with(Victim(_history()), executor))
    assert mon.mark_normal(2, "owner@example.com") is None
    assert mon.mark_normal(99, "owner@example.com") is None
    assert not [a for a in executor.appended if a[0] == "key_feedback"]


def test_feedback_survives_a_restart_through_the_audit_log():
    executor = AuditExecutor()
    mon = asyncio.run(_monitor_with(Victim(_history() + ATTACK), executor))
    mon.mark_normal(2, "owner@example.com")
    audit = [{"seq": i, "kind": k, "data": d} for i, (k, d) in enumerate(executor.appended, 1)]

    async def restarted():
        again = [dict(e, id=e["id"] + 1000, ts=e["ts"] + 60) for e in ATTACK]
        async with httpx.AsyncClient(transport=httpx.MockTransport(Victim(_history() + again))) as http:
            fresh = monitor_mod.Monitor("http://victim", 2, KeyReasoner(), AuditExecutor(), http, victim_events=from_victim_row)
            fresh._last_reason_at = float("inf")
            fresh.restore(audit)
            await fresh.tick()
            return fresh

    assert asyncio.run(restarted()).state()["key_activity"] == []


@pytest.fixture()
def feedback_client(monkeypatch, tmp_path):
    def make(token):
        monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.jsonl"))
        monkeypatch.setenv("VICTIM_URL", "http://127.0.0.1:9")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        if token is None:
            monkeypatch.delenv("APPROVER_TOKEN", raising=False)
        else:
            monkeypatch.setenv("APPROVER_TOKEN", token)
        mod = load_module("centinela_app_feedback", SVC / "web" / "app.py")
        return mod, TestClient(mod.app)
    return make


def test_feedback_endpoint_requires_the_approver_token_when_configured(feedback_client):
    mod, client = feedback_client("human-secret")
    with client:
        seen = []
        mod.app.state.ctx.monitor.mark_normal = lambda key, by: seen.append((key, by)) or {"key_id": key, "learned": 3}
        assert client.post("/api/keys/2/normal").status_code == 401
        assert client.post("/api/keys/2/normal", headers={"X-Approver-Token": "nope"}).status_code == 401
        r = client.post("/api/keys/2/normal", headers={"X-Approver-Token": "human-secret"})
        assert r.status_code == 200 and r.json() == {"feedback": {"key_id": 2, "learned": 3}}
        assert seen == [(2, "approver-token")]


def test_feedback_endpoint_reports_a_key_that_is_not_flagged(feedback_client):
    _, client = feedback_client(None)
    with client:
        r = client.post("/api/keys/2/normal")
        assert r.status_code == 409 and r.json() == {"error": "key is not flagged"}
