"""S1 (victim side): /metrics marks only the job-runner child as managed."""
import os

import pytest
from fastapi.testclient import TestClient

from conftest import VICTIM, load_module


@pytest.fixture()
def victim(monkeypatch):
    monkeypatch.setenv("EXECUTOR_TOKEN", "test-token")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    mod = load_module("victim_app_managed", VICTIM / "app.py")
    with TestClient(mod.app) as client:
        yield client


def test_metrics_marks_job_and_nothing_else(victim):
    started = victim.post("/jobs", json={"job": "report"}).json()
    try:
        procs = victim.get("/metrics").json()["processes"]
        assert [p["pid"] for p in procs if p.get("managed") is True] == [started["pid"]]
        assert next(p for p in procs if p["pid"] == os.getpid())["managed"] is False
    finally:
        r = victim.post("/kill", json={"pid": started["pid"]}, headers={"X-Executor-Token": "test-token"})
        assert r.status_code == 200
