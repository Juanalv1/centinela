"""generic-ingestion E3: the reference forwarder reads an nginx JSON access log and pushes batches."""
import asyncio
import json
import time

from conftest import ROOT, load_module
from test_ingest import AUTH, ingest_client  # noqa: F401 (fixture)
from test_monitor_keys import NOW as VICTIM_NOW
from test_monitor_keys import ATTACK, Victim, _history, _run

fwd = load_module("forward_nginx", ROOT / "lab" / "attack" / "forward_nginx.py")


def nginx_line(row: dict, **extra) -> str:
    """One line as written by the documented `log_format centinela escape=json` (every value a string)."""
    uri = row["path"] + (f"?{row['query']}&sort=desc" if row.get("query") else "")
    rec = {"request_id": f"{row['id']:032x}", "msec": f"{row['ts']:.3f}", "remote_addr": row["ip"],
           "request_method": "GET", "request_uri": uri, "status": str(row["status"]),
           "body_bytes_sent": str(row["bytes"]), "key_id": str(row["api_key_id"]),
           "key_label": "ana-integration"} | extra
    return json.dumps(rec) + "\n"


def test_a_line_becomes_an_event_without_the_query_string():
    ev = fwd.parse_line(nginx_line(ATTACK[0]))
    assert ev == {"id": f"{ATTACK[0]['id']:032x}", "ts": ATTACK[0]["ts"], "key_id": 2, "ip": "198.51.100.23",
                  "method": "GET", "path": "/api/customers", "page": "1", "status": 200, "bytes": 4000,
                  "key_label": "ana-integration"}


def test_lines_without_a_key_or_malformed_are_skipped():
    assert fwd.parse_line(nginx_line(ATTACK[0], key_id="")) is None
    assert fwd.parse_line(nginx_line(ATTACK[0], key_id="-")) is None
    assert fwd.parse_line(nginx_line(ATTACK[0], key_id="sk_live_x")) is None  # a value, never an id
    assert fwd.parse_line("not json\n") is None
    assert fwd.parse_line(nginx_line(ATTACK[0], status="abc")) is None


def test_forward_posts_in_batches_and_keeps_an_incomplete_last_line(tmp_path):
    log = tmp_path / "access.json"
    log.write_bytes(("".join(nginx_line(r) for r in ATTACK[:5]) + '{"request_id": "half').encode())
    sent = []
    offset = fwd.forward(log, 0, lambda events: sent.append(events), batch=2)
    assert [len(b) for b in sent] == [2, 2, 1]
    assert offset == len("".join(nginx_line(r) for r in ATTACK[:5]).encode())
    assert fwd.forward(log, offset, lambda events: sent.append(events), batch=2) == offset  # nothing new


def test_a_failed_post_stops_at_the_last_delivered_batch(tmp_path):
    log = tmp_path / "access.json"
    lines = [nginx_line(r) for r in ATTACK[:4]]
    log.write_bytes(("".join(lines)).encode())
    calls = []

    def post(events):
        calls.append(events)
        if len(calls) == 2:
            raise OSError("centinela unreachable")

    try:
        fwd.forward(log, 0, post, batch=2)
    except fwd.DeliveryFailed as exc:
        assert exc.offset == len("".join(lines[:2]).encode())
    else:
        raise AssertionError("expected DeliveryFailed")


def test_a_rotated_log_is_read_from_the_start(tmp_path):
    log = tmp_path / "access.json"
    log.write_bytes((nginx_line(ATTACK[0])).encode())
    sent = []
    assert fwd.forward(log, 10_000, lambda events: sent.append(events)) == len(nginx_line(ATTACK[0]).encode())
    assert len(sent) == 1


def test_post_batch_sends_the_token_as_a_bearer_header():
    seen = {}

    class Resp:
        status = 200

        def read(self):
            return b'{"received": 1, "new": 1}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout):
        seen.update(url=req.full_url, auth=req.get_header("Authorization"), body=json.loads(req.data))
        return Resp()

    out = fwd.post_batch("https://centinela.example/", "tok", "nginx-edge", [{"id": "a"}], opener=opener)
    assert out == {"received": 1, "new": 1}
    assert seen == {"url": "https://centinela.example/api/ingest/access", "auth": "Bearer tok",
                    "body": {"source": "nginx-edge", "events": [{"id": "a"}]}}


def test_forwarded_nginx_log_flags_like_the_victim(tmp_path, ingest_client):
    victim_mon, _ = asyncio.run(_run(Victim(_history() + ATTACK)))
    [from_victim] = victim_mon.state()["key_activity"]
    log = tmp_path / "access.json"
    log.write_bytes(("".join(nginx_line(r) for r in _history() + ATTACK)).encode())
    mod, client = ingest_client("ingest-secret")
    with client:
        mod.app.state.ctx.monitor.clock_offset = time.time() - VICTIM_NOW

        def post(events):
            r = client.post("/api/ingest/access", json={"source": "nginx-edge", "events": events}, headers=AUTH)
            assert r.status_code == 200, r.text

        fwd.forward(log, 0, post, batch=500)
        [flag] = mod.app.state.ctx.monitor.evaluate_keys(VICTIM_NOW)
        for k in ("key_id", "score", "signals", "window", "profile"):
            assert flag[k] == from_victim[k]
