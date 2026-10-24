"""behavioral-signals T1: /metrics exposes per-process behavior (parent, network, disk I/O)."""
import http.server
import os
import threading
import time
from collections import namedtuple

import pytest
from fastapi.testclient import TestClient

from conftest import VICTIM, load_module

behavior = load_module("victim_behavior", VICTIM / "behavior.py")

Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "laddr raddr status")
Io = namedtuple("Io", "read_bytes write_bytes")


def test_connections_summary_counts_only_remote_peers():
    conns = [
        Conn(Addr("0.0.0.0", 8000), (), "LISTEN"),
        Conn(Addr("10.0.0.5", 51000), Addr("203.0.113.9", 443), "ESTABLISHED"),
        Conn(Addr("10.0.0.5", 51001), Addr("203.0.113.9", 443), "ESTABLISHED"),
        Conn(Addr("10.0.0.5", 51002), Addr("198.51.100.4", 3333), "SYN_SENT"),
        Conn(Addr("10.0.0.5", 51003), Addr("192.0.2.1", 80), "ESTABLISHED"),
        Conn(Addr("10.0.0.5", 51004), Addr("192.0.2.2", 80), "ESTABLISHED"),
    ]
    summary = behavior.summarize_connections(conns)
    assert summary["count"] == 5
    assert summary["listening"] == 1
    assert len(summary["remotes"]) == 3  # capped, distinct peers
    assert summary["remotes"][0] == "203.0.113.9:443 ESTABLISHED"


def test_io_rate_needs_two_samples_then_reports_bytes_per_second():
    tracker = behavior.IoTracker()
    assert tracker.rate(42, 1.0, Io(1_000, 2_000), now=100.0) == {"read_bps": None, "write_bps": None}
    rate = tracker.rate(42, 1.0, Io(1_000, 2_000 + 4_096), now=102.0)
    assert rate == {"read_bps": 0, "write_bps": 2048}


def test_io_rate_resets_when_pid_is_reused():
    tracker = behavior.IoTracker()
    tracker.rate(42, 1.0, Io(0, 10_000_000), now=100.0)
    # same pid, different create_time: a new process, so no bogus delta
    assert tracker.rate(42, 5.0, Io(0, 10), now=101.0) == {"read_bps": None, "write_bps": None}


def test_io_rate_is_null_when_counters_are_unavailable():
    assert behavior.IoTracker().rate(42, 1.0, None, now=1.0) == {"read_bps": None, "write_bps": None}


class _Quiet(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, like a real check-in channel

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class _Closing(_Quiet):
    """Ends every exchange, like an edge proxy dropping idle keep-alives."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"ok")
        self.close_connection = True


@pytest.fixture(params=[_Quiet, _Closing], ids=["keep-alive", "closing"])
def endpoint(request):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), request.param)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/health"
    server.shutdown()


@pytest.fixture()
def victim(monkeypatch, endpoint, tmp_path):
    monkeypatch.setenv("EXECUTOR_TOKEN", "test-token")
    monkeypatch.setenv("SYNC_ENDPOINT", endpoint)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    mod = load_module("victim_app_behavior", VICTIM / "app.py")
    mod.JOB_ARGS["backup"] = ["--dest", str(tmp_path / "backups")]
    with TestClient(mod.app) as client:
        client.tmp_path = tmp_path
        yield client


def _kill(victim, pid):
    victim.post("/kill", json={"pid": pid}, headers={"X-Executor-Token": "test-token"})


def _proc(victim, pid):
    return next(p for p in victim.get("/metrics").json()["processes"] if p["pid"] == pid)


def test_every_process_carries_behavior_fields(victim):
    me = _proc(victim, os.getpid())
    assert {"ppid", "parent", "net", "io"} <= me.keys()
    assert set(me["io"]) == {"read_bps", "write_bps"}
    assert {"count", "listening", "remotes"} <= me["net"].keys()
    # pre-existing fields are still there
    assert {"pid", "name", "cmdline", "username", "cpu_percent", "create_time", "managed"} <= me.keys()


def test_sync_job_shows_a_persistent_outbound_connection_and_no_pool_string(victim):
    pid = victim.post("/jobs", json={"job": "sync"}).json()["pid"]
    try:
        time.sleep(2)  # well after the first check-in: the channel must still be up
        proc = _proc(victim, pid)
        assert proc["net"]["count"] >= 1
        assert any(r.endswith("ESTABLISHED") for r in proc["net"]["remotes"])
        assert proc["ppid"] == os.getpid()
        cmdline = " ".join(proc["cmdline"]).lower()
        assert "stratum" not in cmdline and "pool" not in cmdline
    finally:
        _kill(victim, pid)


def test_backup_job_writes_real_files_and_opens_no_connections(victim):
    pid = victim.post("/jobs", json={"job": "backup"}).json()["pid"]
    try:
        dest = victim.tmp_path / "backups"
        deadline = time.time() + 10
        while not any(dest.glob("*")) and time.time() < deadline:
            time.sleep(0.3)
        assert any(f.stat().st_size > 0 for f in dest.glob("*"))
        assert _proc(victim, pid)["net"]["count"] == 0
    finally:
        _kill(victim, pid)
