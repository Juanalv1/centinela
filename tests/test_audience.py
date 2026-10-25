"""Audience live portal: handle normalization, rate limits, feed, and app wiring."""
import pytest
from fastapi.testclient import TestClient

from conftest import SVC, load_module

audience_mod = load_module("centinela_audience", SVC / "application" / "audience.py")
AudienceState = audience_mod.AudienceState
RateLimited = audience_mod.RateLimited
normalize_handle = audience_mod.normalize_handle


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


# --- normalize_handle ------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("@Vale", "vale"), ("vale", "vale"), ("  NICO ", "nico"), ("ok_1", "ok_1"),
    ("ab", "ab"), ("a", None), ("x" * 16, None), ("has space", None),
    ("tilde-é", None), ("", None), (None, None), (123, None),
])
def test_normalize_handle(raw, expected):
    assert normalize_handle(raw) == expected


# --- join ------------------------------------------------------------------
def test_join_registers_and_counts():
    clk = Clock()
    a = AudienceState(clock=clk)
    a.join("vale", "1.1.1.1")
    assert a.known("vale") and len(a.participants) == 1


def test_join_rate_limited_per_ip():
    clk = Clock()
    a = AudienceState(clock=clk)
    a.join("vale", "1.1.1.1")
    with pytest.raises(RateLimited) as exc:
        a.join("tomi", "1.1.1.1")  # same ip, no time passed
    assert exc.value.reason == "rate"
    clk.t += 2.0
    a.join("tomi", "1.1.1.1")  # cooldown elapsed
    assert len(a.participants) == 2


def test_join_full(monkeypatch):
    monkeypatch.setattr(audience_mod, "MAX_PARTICIPANTS", 1)
    clk = Clock()
    a = AudienceState(clock=clk)
    a.join("vale", "1.1.1.1")
    clk.t += 2.0
    with pytest.raises(RateLimited) as exc:
        a.join("tomi", "2.2.2.2")
    assert exc.value.reason == "full"


# --- actions ---------------------------------------------------------------
def test_check_action_unknown_and_cooldown():
    clk = Clock()
    a = AudienceState(clock=clk)
    with pytest.raises(KeyError):
        a.check_action("ghost")
    a.join("vale", "1.1.1.1")
    a.check_action("vale")
    a.record("vale", "inject", {"status": "rejected"})  # sets last_action_at
    with pytest.raises(RateLimited):
        a.check_action("vale")  # within ACTION_COOLDOWN_S
    clk.t += 3.0
    a.check_action("vale")  # ok now


def test_miner_singleton_cooldown():
    clk = Clock()
    a = AudienceState(clock=clk)
    assert a.miner_allowed()
    a.note_miner()
    assert not a.miner_allowed()
    clk.t += audience_mod.MINER_COOLDOWN_S
    assert a.miner_allowed()


def test_record_tracks_best_containment_and_feed_order():
    clk = Clock()
    a = AudienceState(clock=clk)
    a.join("vale", "1.1.1.1")
    a.record("vale", "miner", {"status": "launched", "containment_s": 5.0})
    a.record("vale", "miner", {"status": "launched", "containment_s": 7.5})
    a.record("vale", "miner", {"status": "launched", "containment_s": 3.0})
    assert a.participants["vale"]["best_s"] == 7.5  # longest resisted
    assert a.participants["vale"]["actions"] == 3
    assert a.activity[0]["containment_s"] == 3.0  # newest first


def test_live_board_ranks_by_actions_then_containment():
    clk = Clock()
    a = AudienceState(clock=clk)
    for h in ("vale", "tomi"):
        a.join(h, h)  # distinct ips, no join cooldown
    a.record("vale", "inject", {"status": "rejected"})
    a.record("vale", "inject", {"status": "rejected"})
    a.record("tomi", "miner", {"status": "launched", "containment_s": 6.0})
    live = a.live()
    assert live["people"] == 2
    assert [r["handle"] for r in live["board"]] == ["vale", "tomi"]  # vale: 2 actions
    assert len(live["activity"]) == 3


# --- app wiring ------------------------------------------------------------
@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("VICTIM_URL", "http://127.0.0.1:9")  # unreachable; monitor records errors
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    mod = load_module("centinela_app_audience", SVC / "web" / "app.py")
    with TestClient(mod.app) as c:
        yield c


def test_join_endpoint_validates_handle(client):
    assert client.post("/api/join", json={"handle": "a"}).status_code == 400
    r = client.post("/api/join", json={"handle": "@Vale"})
    assert r.status_code == 200 and r.json()["handle"] == "vale"


def test_participate_requires_registration(client):
    assert client.post("/api/participate", json={"handle": "ghost", "attack": "inject"}).status_code == 403


def test_participate_inject_records_real_outcome_and_feed(client):
    assert client.post("/api/join", json={"handle": "vale"}).status_code == 200
    r = client.post("/api/participate", json={"handle": "vale", "attack": "inject"})
    assert r.status_code == 200 and r.json()["ok"] is True
    live = client.get("/api/live").json()
    assert live["people"] == 1 and len(live["activity"]) == 1


def test_participate_action_cooldown(client):
    client.post("/api/join", json={"handle": "vale"})
    assert client.post("/api/participate", json={"handle": "vale", "attack": "inject"}).status_code == 200
    # second tap immediately -> rate limited
    assert client.post("/api/participate", json={"handle": "vale", "attack": "inject"}).status_code == 429


def test_unknown_attack_rejected(client):
    client.post("/api/join", json={"handle": "vale"})
    assert client.post("/api/participate", json={"handle": "vale", "attack": "nope"}).status_code == 400
