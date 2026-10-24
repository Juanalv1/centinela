"""Victim real-time monitor: container CPU/memory (cgroup v2) and the monitor page."""
import pytest
from fastapi.testclient import TestClient

from conftest import VICTIM, load_module

sysload = load_module("victim_sysload", VICTIM / "sysload.py")


def _write_cgroup(tmp_path, usage_usec, quota="50000", period="100000"):
    stat = tmp_path / "cpu.stat"
    stat.write_text(f"usage_usec {usage_usec}\n")
    mx = tmp_path / "cpu.max"
    mx.write_text(f"{quota} {period}\n")
    return stat, mx


def test_container_cpu_primes_then_pegs(tmp_path, monkeypatch):
    stat, mx = _write_cgroup(tmp_path, 0)  # 0.5-core quota
    monkeypatch.setattr(sysload, "_CPU_STAT", stat)
    monkeypatch.setattr(sysload, "_CPU_MAX", mx)
    monkeypatch.setattr(sysload, "_cpu_prev", {"usage_usec": None, "t": None})
    clock = {"t": 1000.0}
    monkeypatch.setattr(sysload.time, "monotonic", lambda: clock["t"])

    assert sysload.container_cpu_percent() is None     # first call primes
    clock["t"] = 1001.0
    stat.write_text("usage_usec 500000\n")             # 0.5 CPU-s of a 0.5-core quota
    assert sysload.container_cpu_percent() == pytest.approx(100.0, abs=0.5)


def test_container_cpu_unavailable_is_none(tmp_path, monkeypatch):
    monkeypatch.setattr(sysload, "_CPU_STAT", tmp_path / "missing")
    monkeypatch.setattr(sysload, "_cpu_prev", {"usage_usec": None, "t": None})
    assert sysload.container_cpu_percent() is None


def test_container_mem_percent(tmp_path, monkeypatch):
    (tmp_path / "memory.current").write_text("268435456\n")  # 256 MiB
    (tmp_path / "memory.max").write_text("536870912\n")      # 512 MiB
    monkeypatch.setattr(sysload, "_MEM_CUR", tmp_path / "memory.current")
    monkeypatch.setattr(sysload, "_MEM_MAX", tmp_path / "memory.max")
    assert sysload.container_mem_percent() == pytest.approx(50.0, abs=0.1)


@pytest.fixture()
def victim(monkeypatch):
    monkeypatch.setenv("EXECUTOR_TOKEN", "test-token")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    mod = load_module("victim_app_monitor", VICTIM / "app.py")
    with TestClient(mod.app) as c:
        yield c


def test_monitor_stats_shape(victim):
    s = victim.get("/monitor/stats").json()
    assert "cpu_percent" in s and "mem_percent" in s


def test_monitor_page_served_at_root(victim):
    r = victim.get("/")
    assert r.status_code == 200 and "Monitor en vivo" in r.text


def test_metrics_still_works_and_has_no_flood(victim):
    m = victim.get("/metrics").json()
    assert "cpu_percent" in m and "processes" in m
    assert "flood_sources" not in m
