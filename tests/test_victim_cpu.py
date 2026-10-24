"""Victim /metrics reports the container's OWN CPU (cgroup v2), not the host."""
import pytest

from conftest import VICTIM, load_module

app = load_module("victim_app_cpu", VICTIM / "app.py")


def _write_cgroup(tmp_path, usage_usec, quota="50000", period="100000"):
    stat = tmp_path / "cpu.stat"
    stat.write_text(f"usage_usec {usage_usec}\nuser_usec 1\nsystem_usec 1\n")
    mx = tmp_path / "cpu.max"
    mx.write_text(f"{quota} {period}\n")
    return stat, mx


def test_quota_cores_parsed(tmp_path, monkeypatch):
    _, mx = _write_cgroup(tmp_path, 0, quota="50000", period="100000")
    monkeypatch.setattr(app, "_CPU_MAX", mx)
    assert app._cgroup_quota_cores() == 0.5


def test_quota_cores_uncapped_is_none(tmp_path, monkeypatch):
    mx = tmp_path / "cpu.max"
    mx.write_text("max 100000\n")
    monkeypatch.setattr(app, "_CPU_MAX", mx)
    assert app._cgroup_quota_cores() is None


def test_container_cpu_first_call_primes_then_measures(tmp_path, monkeypatch):
    stat, mx = _write_cgroup(tmp_path, 0, quota="50000", period="100000")  # 0.5 core
    monkeypatch.setattr(app, "_CPU_STAT", stat)
    monkeypatch.setattr(app, "_CPU_MAX", mx)
    monkeypatch.setattr(app, "_cpu_prev", {"usage_usec": None, "t": None})

    clock = {"t": 1000.0}
    monkeypatch.setattr(app.time, "monotonic", lambda: clock["t"])

    assert app._container_cpu_percent() is None  # first call primes

    # 1s later, the container used 0.5 CPU-seconds -> 100% of its 0.5-core quota
    clock["t"] = 1001.0
    stat.write_text("usage_usec 500000\n")
    assert app._container_cpu_percent() == pytest.approx(100.0, abs=0.5)


def test_container_cpu_half_load(tmp_path, monkeypatch):
    stat, mx = _write_cgroup(tmp_path, 0, quota="50000", period="100000")
    monkeypatch.setattr(app, "_CPU_STAT", stat)
    monkeypatch.setattr(app, "_CPU_MAX", mx)
    monkeypatch.setattr(app, "_cpu_prev", {"usage_usec": None, "t": None})
    clock = {"t": 1000.0}
    monkeypatch.setattr(app.time, "monotonic", lambda: clock["t"])
    app._container_cpu_percent()
    clock["t"] = 1001.0
    stat.write_text("usage_usec 250000\n")  # 0.25 CPU-s of a 0.5-core quota = 50%
    assert app._container_cpu_percent() == pytest.approx(50.0, abs=0.5)


def test_container_cpu_unavailable_returns_none(tmp_path, monkeypatch):
    missing = tmp_path / "nope.stat"
    monkeypatch.setattr(app, "_CPU_STAT", missing)
    monkeypatch.setattr(app, "_cpu_prev", {"usage_usec": None, "t": None})
    assert app._container_cpu_percent() is None


def test_metrics_exposes_both_cpu_fields(monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("EXECUTOR_TOKEN", "t")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    mod = load_module("victim_app_cpu_metrics", VICTIM / "app.py")
    with TestClient(mod.app) as c:
        m = c.get("/metrics").json()
        assert "cpu_percent" in m and "host_cpu_percent" in m
        assert 0 <= m["cpu_percent"] <= 100
