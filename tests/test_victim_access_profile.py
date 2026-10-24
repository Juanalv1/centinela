"""behavioral-signals A1: richer access log, a paginated data endpoint, seeded lab history, lab reset."""
from datetime import datetime, timedelta, timezone

import psycopg
import pytest
from fastapi.testclient import TestClient

from conftest import VICTIM, load_module
from pg import fresh_db

LEAKED = "cen_demo_ana_leaked_key"
LUIS = "cen_demo_luis_reports_key"
KNOWN_IP = "198.51.100.77"
CARACAS = timezone(timedelta(hours=-4))


@pytest.fixture()
def env(monkeypatch):
    dsn = fresh_db()
    monkeypatch.setenv("DATABASE_URL", dsn)
    monkeypatch.setenv("EXECUTOR_TOKEN", "test-token")
    monkeypatch.setenv("DEMO_LEAKED_KEY", LEAKED)
    monkeypatch.setenv("DEMO_LUIS_KEY", LUIS)
    monkeypatch.setenv("OFFICE_CIDR", "203.0.113.0/24")
    monkeypatch.setenv("LAB_KNOWN_IPS", KNOWN_IP)
    monkeypatch.setenv("LAB_TOKEN", "lab-token")
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    mod = load_module("victim_app_profile", VICTIM / "app.py")
    with TestClient(mod.app) as client:
        client.mod = mod
        yield client, dsn


def _log(client, **filters):
    entries, after = [], 0
    while batch := client.get("/access-log", params={"after": after, "limit": 500}).json()["entries"]:
        entries += batch
        after = batch[-1]["id"]
    return [e for e in entries if all(e.get(k) == v for k, v in filters.items())]


def test_live_requests_log_bytes_query_and_are_not_lab_seed(env):
    client, _ = env
    r = client.get("/api/customers", params={"page": 2},
                   headers={"X-API-Key": LEAKED, "X-Forwarded-For": "192.0.2.50"})
    assert r.status_code == 200
    hit = _log(client, ip="192.0.2.50")[-1]
    assert hit["path"] == "/api/customers" and hit["query"] == "page=2"
    assert hit["bytes"] == len(r.content) and hit["bytes"] > 0
    assert hit["lab_seed"] is False


def test_customers_is_paginated_fake_data(env):
    client, _ = env
    h = {"X-API-Key": LEAKED}
    first = client.get("/api/customers", params={"page": 1}, headers=h).json()
    assert len(first["customers"]) == first["page_size"] > 0
    assert first["page"] == 1 and first["pages"] > 5
    assert client.get("/api/customers", params={"page": 2}, headers=h).json()["customers"] != first["customers"]
    assert client.get("/api/customers", params={"page": first["pages"] + 1}, headers=h).json()["customers"] == []
    assert client.get("/api/customers").status_code == 401


def test_seeded_history_ana_office_weekdays_business_hours(env):
    client, _ = env
    ana = [e for e in _log(client, lab_seed=True) if e["username"] == "ana"]
    assert len(ana) >= 50
    for e in ana:
        local = datetime.fromtimestamp(e["ts"], CARACAS)
        assert local.weekday() < 5 and 8 <= local.hour < 18, local
        assert e["ip"].startswith("203.0.113.")
        assert e["path"] in ("/api/me", "/api/invoices")
        assert e["status"] == 200 and e["api_key_id"] is not None
    assert min(e["ts"] for e in ana) < (datetime.now(timezone.utc) - timedelta(days=14)).timestamp()


def test_seeded_history_luis_reports_from_known_ips_around_the_clock(env):
    client, _ = env
    luis = [e for e in _log(client, lab_seed=True) if e["username"] == "luis"]
    assert {e["ip"] for e in luis} == {KNOWN_IP}
    assert "/api/customers" in {e["path"] for e in luis}
    assert len({datetime.fromtimestamp(e["ts"], CARACAS).hour for e in luis}) == 24
    # the reports key really works for the live legit trial
    assert client.get("/api/me", headers={"X-API-Key": LUIS}).json()["username"] == "luis"


def test_history_is_seeded_once_even_on_an_existing_database(env, monkeypatch):
    client, dsn = env
    with psycopg.connect(dsn, autocommit=True) as conn:
        before = conn.execute("SELECT count(*) FROM access_log WHERE lab_seed").fetchone()[0]
        conn.execute("DELETE FROM access_log")  # a database seeded before history existed
    client.mod.pyme.close()
    client.mod.pyme.init(dsn)
    client.mod.pyme.close()
    client.mod.pyme.init(dsn)
    with psycopg.connect(dsn, autocommit=True) as conn:
        assert conn.execute("SELECT count(*) FROM access_log WHERE lab_seed").fetchone()[0] == before > 0


def test_lab_reset_restores_keys_blocks_and_suspensions(env):
    client, dsn = env
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("UPDATE api_keys SET status = 'revoked' WHERE NOT protected")
        conn.execute("INSERT INTO ip_blocklist (ip, reason) VALUES ('192.0.2.9', 't')")
        conn.execute("INSERT INTO user_suspensions (user_id, reason) "
                     "SELECT id, 't' FROM users WHERE username = 'ana'")
    assert client.post("/lab/reset").status_code == 401
    assert client.post("/lab/reset", headers={"X-Lab-Token": "nope"}).status_code == 401
    r = client.post("/lab/reset", headers={"X-Lab-Token": "lab-token"})
    assert r.status_code == 200
    assert client.get("/api/me", headers={"X-API-Key": LEAKED}).status_code == 200
    state = client.get("/security-state").json()
    assert state["ip_blocklist"] == [] and not any(u["suspended"] for u in state["users"])


def test_lab_reset_does_not_exist_without_lab_token(env, monkeypatch):
    client, _ = env
    monkeypatch.delenv("LAB_TOKEN")
    assert client.post("/lab/reset", headers={"X-Lab-Token": "lab-token"}).status_code == 404
