"""Google login, session-gated dashboard, /api/me, server-stats and dashboard approvals."""
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import SVC, load_module

PUBLIC = "https://centinela.example"
ADMIN = {"X-Requested-With": "centinela", "Origin": PUBLIC}
AUTH_ENV = {"GOOGLE_CLIENT_ID": "cid", "GOOGLE_CLIENT_SECRET": "csecret",
            "SESSION_SECRET": "s3ssion", "PUBLIC_URL": PUBLIC, "ADMIN_EMAILS": "Boss@Example.com, other@x.com"}
ALL_ENV = [*AUTH_ENV, "APPROVER_TOKEN", "ANTHROPIC_API_KEY"]


@pytest.fixture()
def make(monkeypatch, tmp_path):
    """make(auth=True, **env) -> (module, started TestClient). Env is applied before app.py loads."""
    clients = []

    def _make(auth: bool = True, **env):
        for k in ALL_ENV:
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.jsonl"))
        monkeypatch.setenv("VICTIM_URL", "http://127.0.0.1:9")
        for k, v in {**(AUTH_ENV if auth else {}), **env}.items():
            monkeypatch.setenv(k, v)
        mod = load_module("centinela_app_auth", SVC / "web" / "app.py")
        c = TestClient(mod.app, follow_redirects=False, base_url=PUBLIC if auth else "http://testserver")
        c.__enter__()
        clients.append(c)
        return mod, c

    yield _make
    for c in clients:
        c.__exit__(None, None, None)


def google_mock(mod, email="boss@example.com", verified=True, token_ok=True):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": "at"}) if token_ok else httpx.Response(400, json={})
        if request.url.host == "openidconnect.googleapis.com":
            return httpx.Response(200, json={"email": email, "email_verified": verified,
                                             "name": "Ana Boss", "picture": "https://img/p.png"})
        return httpx.Response(404)
    mod.app.state.ctx.google_transport = httpx.MockTransport(handler)


def login(mod, client, **kw):
    google_mock(mod, **kw)
    r = client.get("/auth/google")
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    return client.get("/auth/callback", params={"code": "c", "state": state})


# --- server-stats -------------------------------------------------------

def test_server_stats_success(make):
    mod, c = make(auth=False)
    mod.app.state.ctx.monitor.http = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={"cpu_percent": 42.5, "mem_percent": 10, "extra": "x"})))
    r = c.get("/api/server-stats")
    assert r.status_code == 200 and r.json() == {"cpu_percent": 42.5, "mem_percent": 10}


def test_server_stats_victim_failure_is_502_with_nulls(make):
    mod, c = make(auth=False)

    def boom(req):
        raise httpx.ConnectError("down")
    mod.app.state.ctx.monitor.http = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    r = c.get("/api/server-stats")
    body = r.json()
    assert r.status_code == 502
    assert body["cpu_percent"] is None and body["mem_percent"] is None and "ConnectError" in body["error"]


def test_server_stats_ignores_non_numeric_values(make):
    mod, c = make(auth=False)
    mod.app.state.ctx.monitor.http = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={"cpu_percent": None, "mem_percent": "boom"})))
    assert c.get("/api/server-stats").json() == {"cpu_percent": None, "mem_percent": None}


# --- demo mode ----------------------------------------------------------

def test_demo_mode_dashboard_open_and_me(make):
    _, c = make(auth=False)
    r = c.get("/dashboard")
    assert r.status_code == 200 and "Modo demo" in r.text
    assert c.get("/api/me").json() == {"auth": "demo", "user": None, "can_approve": True}
    assert c.get("/login").status_code == 303 and c.get("/login").headers["location"] == "/dashboard"


def test_demo_mode_with_partial_config_is_still_demo(make):
    _, c = make(auth=False, GOOGLE_CLIENT_ID="cid", GOOGLE_CLIENT_SECRET="x")  # no SESSION_SECRET
    assert c.get("/dashboard").status_code == 200
    assert c.get("/api/me").json()["auth"] == "demo"


def test_demo_mode_me_cannot_approve_when_token_configured(make):
    _, c = make(auth=False, APPROVER_TOKEN="tok")
    assert c.get("/api/me").json()["can_approve"] is False


# --- configured mode ----------------------------------------------------

def test_dashboard_redirects_to_login_without_session(make):
    _, c = make()
    r = c.get("/dashboard")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert "Continuar con Google" in c.get("/login").text
    assert c.get("/api/me").json() == {"auth": "google", "member": False, "role": None, "user": None,
                                       "can_approve": False, "can_manage": False}


def test_public_endpoints_stay_public(make):
    _, c = make()
    for path in ("/", "/unirse", "/api/state", "/api/live"):
        assert c.get(path).status_code == 200, path


def test_auth_google_sets_state_and_redirects(make):
    _, c = make()
    r = c.get("/auth/google")
    assert r.status_code == 303
    url = urlparse(r.headers["location"])
    q = parse_qs(url.query)
    assert url.netloc == "accounts.google.com"
    assert q["redirect_uri"] == [f"{PUBLIC}/auth/callback"]
    assert q["client_id"] == ["cid"] and q["scope"] == ["openid email profile"] and q["response_type"] == ["code"]
    assert len(q["state"][0]) >= 32
    cookie = r.headers["set-cookie"].lower()
    assert "centinela_session" in cookie and "secure" in cookie and "samesite=lax" in cookie


def test_callback_rejects_bad_state(make):
    mod, c = make()
    google_mock(mod)
    c.get("/auth/google")
    r = c.get("/auth/callback", params={"code": "c", "state": "forged"})
    assert r.status_code == 303 and r.headers["location"] == "/login?error=state"
    assert c.get("/dashboard").status_code == 303  # still logged out


def test_callback_rejects_missing_session_state(make):
    mod, c = make()
    google_mock(mod)
    r = c.get("/auth/callback", params={"code": "c", "state": "anything"})
    assert r.headers["location"] == "/login?error=state"


def test_callback_state_is_single_use(make):
    mod, c = make()
    google_mock(mod)
    state = parse_qs(urlparse(c.get("/auth/google").headers["location"]).query)["state"][0]
    assert c.get("/auth/callback", params={"code": "c", "state": state}).headers["location"] == "/dashboard"
    r = c.get("/auth/callback", params={"code": "c", "state": state})
    assert r.headers["location"] == "/login?error=state"


def test_callback_rejects_unverified_email(make):
    mod, c = make()
    r = login(mod, c, verified=False)
    assert r.headers["location"] == "/login?error=email"
    assert c.get("/dashboard").status_code == 303


def test_callback_google_error_param(make):
    _, c = make()
    c.get("/auth/google")
    r = c.get("/auth/callback", params={"error": "access_denied"})
    assert r.headers["location"] == "/login?error=denied"


def test_callback_token_exchange_failure(make):
    mod, c = make()
    r = login(mod, c, token_ok=False)
    assert r.headers["location"] == "/login?error=failed"


def test_callback_success_logs_in_and_logout_clears(make):
    mod, c = make()
    r = login(mod, c)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard"
    assert c.get("/dashboard").status_code == 200
    me = c.get("/api/me").json()
    assert me["auth"] == "google" and me["can_approve"] is True  # case-insensitive ADMIN_EMAILS
    assert me["user"] == {"name": "Ana Boss", "email": "boss@example.com", "picture": "https://img/p.png"}
    out = c.post("/logout")
    assert out.status_code == 303 and out.headers["location"] == "/"
    assert c.get("/dashboard").status_code == 303


def test_non_admin_me_cannot_approve(make):
    mod, c = make()
    login(mod, c, email="guest@example.com")
    assert c.get("/api/me").json()["can_approve"] is False


# --- approvals ----------------------------------------------------------

def test_approval_session_admin_ok(make):
    mod, c = make()
    login(mod, c)
    r = c.post("/api/approvals/1", json={"approve": True}, headers=ADMIN)
    assert r.status_code == 404  # authorized; nothing pending with that id


def test_approval_non_admin_forbidden(make):
    mod, c = make()
    login(mod, c, email="guest@example.com")
    assert c.post("/api/approvals/1", json={"approve": True}, headers=ADMIN).status_code == 403


def test_approval_without_session_unauthorized(make):
    _, c = make()
    assert c.post("/api/approvals/1", json={"approve": True}, headers=ADMIN).status_code == 401


@pytest.mark.parametrize("headers", [
    {"Origin": PUBLIC},                                          # missing custom header
    {"X-Requested-With": "centinela"},                           # missing Origin
    {"X-Requested-With": "centinela", "Origin": "https://evil.example"},
])
def test_approval_csrf_checks(make, headers):
    mod, c = make()
    login(mod, c)
    assert c.post("/api/approvals/1", json={"approve": True}, headers=headers).status_code == 403


def test_approval_token_path_still_works_when_auth_configured(make):
    _, c = make(APPROVER_TOKEN="human-secret")
    r = c.post("/api/approvals/1", json={"approve": True}, headers={"X-Approver-Token": "human-secret"})
    assert r.status_code == 404
    assert c.post("/api/approvals/1", json={"approve": True}, headers={"X-Approver-Token": "bad"}).status_code == 401


def test_approval_csrf_same_host_when_public_url_unset(make):
    mod, c = make(PUBLIC_URL="")
    login(mod, c)
    host = "http://" + c.base_url.host
    ok = c.post("/api/approvals/1", json={"approve": True},
                headers={"X-Requested-With": "centinela", "Origin": host})
    assert ok.status_code == 404
    bad = c.post("/api/approvals/1", json={"approve": True},
                 headers={"X-Requested-With": "centinela", "Origin": "http://evil.example"})
    assert bad.status_code == 403
