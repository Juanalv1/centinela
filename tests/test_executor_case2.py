"""S4/S5: case-2 menu actions on the English contract, against a real victim database.

Layers: menu -> policy (format, protected networks, protected keys/users) -> lane
-> infra (least-privilege Postgres role; its denials land in the audit log)."""
import asyncio
import json

import psycopg
import pytest
from fastapi.testclient import TestClient

from adapters.audit import AuditLog
from conftest import VICTIM, load_module
from domain.model import Proposal, Target
from adapters.victim import VictimDb
from application.executor import Executor, check_policy
from pg import fresh_db

LEAKED = "cen_demo_ana_leaked_key"
EXEC_PW = "exec-test-pw"
OFFICE = ("203.0.113.0/24",)


class NoVictim:
    async def kill(self, pid: int) -> dict:
        raise AssertionError("case-2 actions never call /kill")


def prop(action: str, ttype: str, value: str, confidence: str = "high", source: str = "claude") -> Proposal:
    return Proposal(action=action, target=Target(ttype, value), rationale="clave filtrada usada desde una IP nueva",
                    evidence=["GET /api/invoices 200 ua=curl"], confidence=confidence, source=source)


def run(coro):
    return asyncio.run(coro)


# --- pure policy -------------------------------------------------------------

@pytest.mark.parametrize("p, needle", [
    (prop("revoke_key", "key", "k1"), "not a key id"),
    (prop("revoke_key", "key", "0"), "not a key id"),
    (prop("block_ip", "ip", "not-an-ip"), "not a valid ip"),
    (prop("block_ip", "ip", "203.0.113.10"), "protected network"),
    (prop("block_ip", "ip", "10.1.2.3"), "protected network"),
    (prop("block_ip", "ip", "127.0.0.1"), "protected network"),
    (prop("block_ip", "ip", "::ffff:203.0.113.10"), "protected network"),
    (prop("block_ip", "ip", "::ffff:10.0.0.1"), "protected network"),
    (prop("block_ip", "ip", "0.0.0.0"), "not a single routable host"),
    (prop("block_ip", "ip", "::"), "not a single routable host"),
    (prop("close_sessions", "user", "alice"), "not a user id"),
    (prop("suspend_user", "user", "-3"), "not a user id"),
])
def test_case2_policy_rejects_bad_targets(p, needle):
    reason = check_policy(p, None, OFFICE)
    assert reason and needle in reason


@pytest.mark.parametrize("p", [
    prop("revoke_key", "key", "2"), prop("block_ip", "ip", "198.51.100.7"),
    prop("close_sessions", "user", "2"), prop("suspend_user", "user", "2"),
])
def test_case2_policy_accepts_well_formed_targets(p):
    assert check_policy(p, None, OFFICE) is None


# --- against a real victim database -----------------------------------------

@pytest.fixture()
def lab(monkeypatch, tmp_path):
    dsn = fresh_db()
    for k, v in {"DATABASE_URL": dsn, "EXECUTOR_TOKEN": "t", "DEMO_LEAKED_KEY": LEAKED,
                 "EXECUTOR_DB_PASSWORD": EXEC_PW, "OFFICE_CIDR": OFFICE[0],
                 "TRUSTED_PROXY_HOPS": "1"}.items():
        monkeypatch.setenv(k, v)
    mod = load_module("victim_app_exec", VICTIM / "app.py")
    exec_dsn = psycopg.conninfo.make_conninfo(dsn, user="centinela_executor", password=EXEC_PW)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    with TestClient(mod.app) as victim:
        yield victim, Executor(NoVictim(), audit, db=VictimDb(exec_dsn), protected_networks=OFFICE), audit


def state(victim) -> dict:
    return victim.get("/security-state").json()


def key_id(victim, username: str) -> str:
    return str(next(k["id"] for k in state(victim)["api_keys"] if k["username"] == username))


def user_id(victim, username: str) -> str:
    return str(next(u["id"] for u in state(victim)["users"] if u["username"] == username))


def test_revoke_leaked_key_locks_the_attacker_out(lab):
    victim, ex, audit = lab
    d = run(ex.handle(prop("revoke_key", "key", key_id(victim, "ana")), None))
    assert d.status == "executed", d.reason
    assert victim.get("/api/me", headers={"X-API-Key": LEAKED}).status_code == 401
    assert [e["kind"] for e in audit.entries] == ["proposal", "decision", "action_result"]
    again = run(ex.handle(prop("revoke_key", "key", key_id(victim, "ana")), None))
    assert again.status == "noop"


def test_admin_key_and_admin_user_are_refused_by_policy(lab):
    victim, ex, _ = lab
    d = run(ex.handle(prop("revoke_key", "key", key_id(victim, "admin")), None))
    assert (d.status, d.layer) == ("rejected", "policy")
    assert "protected key" in d.reason
    d = run(ex.handle(prop("close_sessions", "user", user_id(victim, "admin")), None))
    assert (d.status, d.layer) == ("rejected", "policy")
    assert "protected user" in d.reason
    d = run(ex.handle(prop("revoke_key", "key", "999"), None))
    assert (d.status, d.layer) == ("rejected", "policy")
    assert next(k for k in state(victim)["api_keys"] if k["username"] == "admin")["status"] == "active"


def test_bypassed_executor_is_stopped_by_the_database_and_audited(lab):
    victim, ex, audit = lab
    cases = [
        (prop("revoke_key", "key", key_id(victim, "admin"), source="forged"), "protected key"),
        (prop("block_ip", "ip", "203.0.113.10", source="forged"), "protected network"),
        (prop("suspend_user", "user", user_id(victim, "admin"), source="forged"), "protected user"),
        (prop("close_sessions", "user", user_id(victim, "admin"), source="forged"), "protected user"),
    ]
    for p, needle in cases:
        d = run(ex.bypass_demo(p))
        assert (d.status, d.layer) == ("failed", "infra"), d.reason
        assert "permission denied" in d.reason and needle in d.reason
        assert audit.entries[-1]["kind"] == "action_result"
        assert "permission denied" in json.dumps(audit.entries[-1]["data"])
    assert state(victim)["sessions_by_user"]["admin"] >= 1


def test_block_ip_then_its_requests_get_403(lab):
    victim, ex, _ = lab
    assert run(ex.handle(prop("block_ip", "ip", "198.51.100.7"), None)).status == "executed"
    r = victim.get("/api/me", headers={"X-API-Key": LEAKED, "X-Forwarded-For": "198.51.100.7"})
    assert r.status_code == 403
    assert run(ex.handle(prop("block_ip", "ip", "198.51.100.7"), None)).status == "noop"


def test_close_sessions_runs_automatically(lab):
    victim, ex, _ = lab
    d = run(ex.handle(prop("close_sessions", "user", user_id(victim, "ana")), None))
    assert d.status == "executed" and d.result["closed"] >= 1
    assert state(victim)["sessions_by_user"]["ana"] == 0


def test_suspend_user_waits_for_a_human_then_locks_the_user_out(lab):
    victim, ex, audit = lab
    p = prop("suspend_user", "user", user_id(victim, "ana"))
    assert run(ex.handle(p, None)).status == "pending_approval"
    assert victim.get("/api/me", headers={"X-API-Key": LEAKED}).status_code == 200

    d = run(ex.resolve(p.id, True, None))
    assert d.status == "executed", d.reason
    assert victim.get("/api/me", headers={"X-API-Key": LEAKED}).status_code == 403
    assert state(victim)["sessions_by_user"]["ana"] == 0
    assert "ana" in [u["username"] for u in state(victim)["users"] if u["suspended"]]
    assert audit.verify() == (True, None)


def test_without_database_case2_actions_fail_cleanly(tmp_path):
    ex = Executor(NoVictim(), AuditLog(str(tmp_path / "a.jsonl")), protected_networks=OFFICE)
    d = run(ex.handle(prop("block_ip", "ip", "198.51.100.7"), None))
    assert (d.status, d.layer) == ("failed", "infra")
    assert "EXECUTOR_DATABASE_URL not configured" in d.reason
