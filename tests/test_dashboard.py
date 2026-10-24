"""Client dashboard: served at /dashboard and only consumes endpoints that exist."""
import re

import pytest
from fastapi.testclient import TestClient

from conftest import SVC, load_module


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("VICTIM_URL", "http://127.0.0.1:9")  # unreachable; monitor just records errors
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    mod = load_module("centinela_app_dashboard", SVC / "app.py")
    with TestClient(mod.app) as c:
        yield c


def test_dashboard_served(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "Respuesta a incidentes" in r.text and "Política de respuesta" in r.text


def test_dashboard_only_fetches_existing_routes(client):
    html = client.get("/dashboard").text
    paths = set(re.findall(r"fetch\(\s*['\"](/[^'\"?]*)", html))
    assert "/api/state" in paths
    routes = {r.path for r in client.app.routes}
    assert paths <= routes, f"dashboard fetches unknown routes: {paths - routes}"


def test_dashboard_builds_dom_safely(client):
    # Event text can come from attackers: server data must never reach innerHTML.
    assert "innerHTML" not in client.get("/dashboard").text
