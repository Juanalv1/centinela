"""generic-ingestion: one normalized access-event format feeds the per-key baseline from any source."""
import asyncio
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from conftest import SVC, load_module
from test_keywatch import NOW, entry, office_history, watch_with
from test_monitor_keys import NOW as VICTIM_NOW
from test_monitor_keys import ATTACK, FakeExecutor, FakeReasoner, Victim, _history, _run

monitor_mod = load_module("centinela_monitor_ingest", SVC / "application" / "monitor.py")
from adapters.victim import from_victim_row  # noqa: E402
from domain import access as ingest  # noqa: E402
from web.config import INGEST_MAX_BYTES, INGEST_MAX_EVENTS  # noqa: E402


def as_pushed(row: dict, label="ana-integration") -> dict:
    """A victim access-log row as a customer's forwarder would send it."""
    out = {"id": f"req-{row['id']}", "ts": row["ts"], "key_id": row["api_key_id"], "ip": row["ip"],
           "method": row.get("method") or "GET", "path": row["path"], "status": row["status"],
           "bytes": row["bytes"], "key_label": label}
    page = (row.get("query") or "").removeprefix("page=")
    return out | ({"page": page} if page else {})


# --- E1: the event format ------------------------------------------------------

def test_parse_event_keeps_metadata_only():
    ev = ingest.parse_event({"id": "r1", "ts": 1_700_000_000, "key_id": 7, "ip": "198.51.100.23",
                             "method": "get", "path": "/api/customers?page=3&token=secret", "status": 200,
                             "bytes": 4000, "key_label": "erp-sync", "api_key": "sk_live_x",
                             "body": "{...}"}, source="nginx-edge")
    assert ev.entry() == {"source": "nginx-edge", "id": "r1", "ts": 1_700_000_000.0, "api_key_id": 7,
                          "ip": "198.51.100.23", "method": "GET", "path": "/api/customers", "page": "3",
                          "status": 200, "bytes": 4000}
    assert ev.key_label == "erp-sync"
    assert "secret" not in repr(ev) and "sk_live_x" not in repr(ev)


@pytest.mark.parametrize("bad", [
    {"ts": 1.0, "key_id": 7, "ip": "1.2.3.4", "path": "/", "status": 200},  # no id
    {"id": "r", "ts": "yesterday", "key_id": 7, "ip": "1.2.3.4", "path": "/", "status": 200},
    {"id": "r", "ts": 1.0, "key_id": "sk_live_x", "ip": "1.2.3.4", "path": "/", "status": 200},
    {"id": "r", "ts": 1.0, "key_id": True, "ip": "1.2.3.4", "path": "/", "status": 200},
    {"id": "r", "ts": 1.0, "key_id": 7, "ip": "1.2.3.4", "path": "/", "status": 999},
    {"id": "r", "ts": 1.0, "key_id": 7, "ip": "1.2.3.4", "path": "/", "status": 200, "bytes": -1},
    {"id": "x" * 200, "ts": 1.0, "key_id": 7, "ip": "1.2.3.4", "path": "/", "status": 200},
    {"id": "r", "ts": 1.0, "key_id": 7, "ip": "1.2.3.4", "path": "api", "status": 200},
])
def test_parse_event_rejects_malformed_events(bad):
    with pytest.raises(ingest.InvalidEvent):
        ingest.parse_event(bad, source="nginx-edge")


def test_victim_rows_map_to_events_and_keyless_rows_are_dropped():
    row = {"id": 12, "ts": 1.5, "ip": "203.0.113.1", "method": "GET", "path": "/api/invoices",
           "query": "page=4&sort=date", "status": 200, "bytes": 190, "api_key_id": 2, "username": "ana",
           "user_agent": "curl", "lab_seed": True}
    ev = from_victim_row(row)
    assert ev.entry() == {"source": "victim", "id": 12, "ts": 1.5, "api_key_id": 2, "ip": "203.0.113.1",
                          "method": "GET", "path": "/api/invoices", "page": "4", "status": 200, "bytes": 190}
    assert from_victim_row(dict(row, api_key_id=None)) is None


# --- E1: dedupe by (source, event id) ---------------------------------------------

def test_the_same_event_id_from_two_sources_is_two_events():
    w = watch_with(office_history())
    a = dict(entry(NOW - timedelta(seconds=60), ip="198.51.100.23"), source="proxy")
    b = dict(a, source="app")
    assert w.ingest([a, b], now=NOW.timestamp()) == 2
    assert len(w.recent[2]) == 2


def test_replaying_events_into_the_window_counts_them_once():
    w = watch_with(office_history())
    attack = [dict(entry(NOW - timedelta(seconds=300 - 10 * p), ip="198.51.100.23", path="/api/customers",
                         query=f"page={p}", size=4000), source="proxy") for p in range(1, 21)]
    assert w.ingest(attack, now=NOW.timestamp()) == 20
    assert w.ingest(attack, now=NOW.timestamp()) == 0
    [flag] = w.evaluate(NOW.timestamp())
    assert flag["window"]["requests"] == 20 and flag["window"]["bytes"] == 80_000


def test_replaying_history_learns_nothing_twice():
    history = [dict(e, source="proxy") for e in office_history()]
    w = watch_with(history)
    busiest = w.profiles[2].summary(NOW.timestamp())["max_hour_bytes"]
    assert w.ingest(history, now=NOW.timestamp()) == 0
    assert w.profiles[2].summary(NOW.timestamp())["max_hour_bytes"] == busiest


# --- E1: one feed path ----------------------------------------------------------

def test_pushed_events_flag_exactly_like_the_same_activity_read_from_the_victim():
    victim_mon, _ = asyncio.run(_run(Victim(_history() + ATTACK)))
    [from_victim] = victim_mon.state()["key_activity"]

    pushed = monitor_mod.Monitor("http://unused", 2, FakeReasoner(), FakeExecutor(), http=None)
    events = [ingest.parse_event(as_pushed(r), source="nginx-edge") for r in _history() + ATTACK]
    assert pushed.feed(events, now=VICTIM_NOW) > 0
    assert pushed.feed(events, now=VICTIM_NOW) == 0  # a replayed batch adds nothing
    [flag] = pushed.evaluate_keys(VICTIM_NOW)
    for k in ("key_id", "score", "signals", "window", "profile"):
        assert flag[k] == from_victim[k]
    assert pushed.credentials()[0]["label"] == "ana-integration"


def test_feedback_written_before_sources_existed_still_dedupes_victim_rows():
    """Old key_feedback audit rows carry no source: they came from the victim."""
    mon = monitor_mod.Monitor("http://unused", 2, FakeReasoner(), FakeExecutor(), http=None)
    old = [{k: e[k] for k in ("id", "ts", "ip", "path", "bytes")} for e in ATTACK]
    mon.restore([{"seq": 1, "kind": "key_feedback", "data": {"key_id": 2, "entries": old}}])
    busiest = mon.keywatch.profiles[2].summary(ATTACK[-1]["ts"])["max_hour_bytes"]
    later = ATTACK[-1]["ts"] + 2 * 86400  # the same rows re-read as history after a restart
    mon.feed([from_victim_row(r) for r in ATTACK], now=later)
    assert mon.keywatch.profiles[2].summary(later)["max_hour_bytes"] == busiest


def test_keys_unknown_to_the_victim_are_still_evaluated():
    """Pushed keys are not in /security-state; only keys known to be inactive are skipped."""
    mon, _ = asyncio.run(_run(Victim(_history())))
    other = [dict(as_pushed(dict(r, api_key_id=40)), id=f"o-{r['id']}") for r in _history() + ATTACK]
    mon.feed([ingest.parse_event(e, source="nginx-edge") for e in other], now=ATTACK[-1]["ts"] + 1)
    assert [f["key_id"] for f in mon.evaluate_keys(ATTACK[-1]["ts"] + 1)] == [40]


# --- E2: POST /api/ingest/access -------------------------------------------------

@pytest.fixture()
def ingest_client(monkeypatch, tmp_path):
    def make(token):
        monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.jsonl"))
        monkeypatch.setenv("VICTIM_URL", "http://127.0.0.1:9")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        if token is None:
            monkeypatch.delenv("INGEST_TOKEN", raising=False)
        else:
            monkeypatch.setenv("INGEST_TOKEN", token)
        mod = load_module("centinela_app_ingest", SVC / "web" / "app.py")
        return mod, TestClient(mod.app)
    return make


def _batch(rows, source="nginx-edge"):
    return {"source": source, "events": [as_pushed(r) for r in rows]}


AUTH = {"Authorization": "Bearer ingest-secret"}


def test_pushed_batch_flags_like_the_victim_and_a_replay_learns_nothing(ingest_client):
    victim_mon, _ = asyncio.run(_run(Victim(_history() + ATTACK)))
    [from_victim] = victim_mon.state()["key_activity"]
    mod, client = ingest_client("ingest-secret")
    with client:
        mod.app.state.ctx.monitor.clock_offset = time.time() - VICTIM_NOW  # judge on the victim's clock
        r = client.post("/api/ingest/access", json=_batch(_history() + ATTACK), headers=AUTH)
        assert r.status_code == 200 and r.json()["received"] == len(_history()) + len(ATTACK)
        first = r.json()["new"]
        busiest = mod.app.state.ctx.monitor.keywatch.profiles[2].summary(VICTIM_NOW)["max_hour_bytes"]
        again = client.post("/api/ingest/access", json=_batch(_history() + ATTACK), headers=AUTH)
        assert first > 0 and again.json()["new"] == 0
        assert mod.app.state.ctx.monitor.keywatch.profiles[2].summary(VICTIM_NOW)["max_hour_bytes"] == busiest
        [flag] = mod.app.state.ctx.monitor.evaluate_keys(VICTIM_NOW)
        for k in ("key_id", "score", "signals", "window", "profile"):
            assert flag[k] == from_victim[k]
        assert flag["label"] == "ana-integration"


def test_ingest_requires_the_token(ingest_client):
    mod, client = ingest_client("ingest-secret")
    with client:
        body = _batch(ATTACK[:1])
        assert client.post("/api/ingest/access", json=body).status_code == 401
        assert client.post("/api/ingest/access", json=body,
                           headers={"Authorization": "Bearer nope"}).status_code == 401
        assert client.post("/api/ingest/access", json=body,
                           headers={"Authorization": "ingest-secret"}).status_code == 401
        assert mod.app.state.ctx.monitor.keywatch.recent == {}


def test_ingest_is_disabled_without_a_token(ingest_client):
    _, client = ingest_client(None)
    with client:
        r = client.post("/api/ingest/access", json=_batch(ATTACK[:1]), headers=AUTH)
        assert r.status_code == 404


def test_batches_over_the_limit_are_refused(ingest_client):
    mod, client = ingest_client("ingest-secret")
    with client:
        rows = [dict(ATTACK[0], id=i) for i in range(INGEST_MAX_EVENTS + 1)]
        assert client.post("/api/ingest/access", json=_batch(rows), headers=AUTH).status_code == 413
        huge = b'{"source": "x", "events": [], "pad": "' + b"a" * INGEST_MAX_BYTES + b'"}'
        r = client.post("/api/ingest/access", content=huge,
                        headers=AUTH | {"Content-Type": "application/json"})
        assert r.status_code == 413
        assert mod.app.state.ctx.monitor.keywatch.recent == {}


def test_a_malformed_event_rejects_the_whole_batch(ingest_client):
    mod, client = ingest_client("ingest-secret")
    with client:
        body = _batch(ATTACK[:3])
        body["events"][1]["key_id"] = "sk_live_x"
        r = client.post("/api/ingest/access", json=body, headers=AUTH)
        assert r.status_code == 422 and r.json()["index"] == 1 and "key_id" in r.json()["error"]
        assert "sk_live_x" not in r.text
        assert client.post("/api/ingest/access", content=b"{nope", headers=AUTH).status_code == 400
        assert client.post("/api/ingest/access", json={"source": "victim", "events": []},
                           headers=AUTH).status_code == 422  # the victim adapter's namespace is reserved
        assert mod.app.state.ctx.monitor.keywatch.recent == {}
