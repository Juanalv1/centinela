"""Centinela app wiring: approvals need APPROVER_TOKEN when it is configured."""
import pytest
from fastapi.testclient import TestClient

from conftest import SVC, load_module


@pytest.fixture()
def make_client(monkeypatch, tmp_path):
    def make(token: str | None):
        monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.jsonl"))
        monkeypatch.setenv("VICTIM_URL", "http://127.0.0.1:9")  # unreachable; monitor just records errors
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        if token is None:
            monkeypatch.delenv("APPROVER_TOKEN", raising=False)
        else:
            monkeypatch.setenv("APPROVER_TOKEN", token)
        mod = load_module("centinela_app_wiring", SVC / "app.py")
        return TestClient(mod.app)
    return make


def test_approval_requires_token_when_configured(make_client):
    with make_client("human-secret") as client:
        assert client.post("/api/approvals/1", json={"approve": True}).status_code == 401
        r = client.post("/api/approvals/1", json={"approve": True}, headers={"X-Approver-Token": "nope"})
        assert r.status_code == 401
        r = client.post("/api/approvals/1", json={"approve": True}, headers={"X-Approver-Token": "human-secret"})
        assert r.status_code == 404  # authorized; nothing pending with that id


def test_approval_unchanged_without_token(make_client):
    with make_client(None) as client:
        assert client.post("/api/approvals/1", json={"approve": True}).status_code == 404
