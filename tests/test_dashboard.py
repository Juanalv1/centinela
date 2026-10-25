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
    mod = load_module("centinela_app_dashboard", SVC / "web" / "app.py")
    with TestClient(mod.app) as c:
        yield c


def test_dashboard_served(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "Respuesta a incidentes" in r.text and "Política de respuesta" in r.text


def test_dashboard_only_fetches_existing_routes(client):
    html = client.get("/dashboard").text
    paths = set(re.findall(r"(?:fetch|getJson)\(\s*['\"](/[^'\"?]*)", html))
    assert {"/api/state", "/api/live", "/api/server-stats", "/api/me"} <= paths
    routes = {r.path for r in client.app.routes}

    def exists(p: str) -> bool:  # a trailing slash is a prefix of a parametrised route
        return p in routes or (p.endswith("/") and any(r.startswith(p) for r in routes))

    unknown = {p for p in paths if not exists(p)}
    assert not unknown, f"dashboard fetches unknown routes: {unknown}"


def test_dashboard_builds_dom_safely(client):
    # Event text can come from attackers: server data must never reach innerHTML.
    assert "innerHTML" not in client.get("/dashboard").text
