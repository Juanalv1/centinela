"""Invite-only members: store, login gate, role-based approvals and the /api/members routes."""
import json
import threading

import pytest
from fastapi.testclient import TestClient

from audit import AuditLog
from members import MemberError, MemberStore, normalize_email
from pg import fresh_db
from test_auth import ADMIN, AUTH_ENV, PUBLIC, google_mock, login, make  # noqa: F401  (make is a fixture)

BOSS, OTHER = "boss@example.com", "other@x.com"


@pytest.fixture(params=["mem", "pg"])
def boot(make, request):  # noqa: F811
    """boot(**env) -> (module, admin TestClient logged in as BOSS), on both store backends."""
    def _boot(**env):
        if request.param == "pg":
            env.setdefault("AUDIT_DATABASE_URL", fresh_db())
        mod, c = make(**env)
        login(mod, c)
        return mod, c
    return _boot


def second_client(mod, email):
    c = TestClient(mod.app, follow_redirects=False, base_url=PUBLIC)
    login(mod, c, email=email)
    return c


def member_events(mod):
    return [e["data"] for e in mod.members._audit.entries if e["kind"] == "member"]


# --- store --------------------------------------------------------------

def test_normalize_email():
    assert normalize_email("  Ana@Example.COM ") == "ana@example.com"
    for bad in ("", "nope", "a@b", "a b@c.d", "@x.com", None, 5, "a@" + "x" * 250 + ".com"):
        assert normalize_email(bad) is None


@pytest.fixture(params=["mem", "pg"])
def store_factory(request, tmp_path):
    dsn = fresh_db() if request.param == "pg" else None
    audit = AuditLog(str(tmp_path / "a.jsonl"), dsn=dsn)
    return lambda: MemberStore(dsn, audit)


def test_bootstrap_only_when_empty_and_audited(store_factory):
    st = store_factory()
    assert st.bootstrap(["A@x.com", " b@x.com", "bad"]) == ["a@x.com", "b@x.com"]
    assert [m["added_by"] for m in st.list()] == ["bootstrap", "bootstrap"]
    assert st.bootstrap(["c@x.com"]) == []  # not empty: ADMIN_EMAILS is only a seed
    assert st.role_of("c@x.com") is None
    events = [e["data"] for e in st._audit.entries if e["kind"] == "member"]
    assert {e["email"] for e in events} == {"a@x.com", "b@x.com"}
    assert all(e["action"] == "add" and e["actor"] == "bootstrap" for e in events)


def test_store_guards(store_factory):
    st = store_factory()
    st.bootstrap(["a@x.com"])
    st.add("v@x.com", "viewer", "a@x.com")
    for call, code in [
        (lambda: st.add("V@x.com", "viewer", "a@x.com"), "exists"),
        (lambda: st.add("bad", "viewer", "a@x.com"), "invalid"),
        (lambda: st.add("n@x.com", "root", "a@x.com"), "invalid"),
        (lambda: st.set_role("a@x.com", "viewer", "a@x.com"), "self"),
        (lambda: st.remove("a@x.com", "a@x.com"), "self"),
        (lambda: st.set_role("zz@x.com", "admin", "a@x.com"), "not_found"),
        (lambda: st.remove("zz@x.com", "a@x.com"), "not_found"),
        (lambda: st.set_role("a@x.com", "viewer", "v@x.com"), "last_admin"),
        (lambda: st.remove("a@x.com", "v@x.com"), "last_admin"),
    ]:
        with pytest.raises(MemberError) as e:
            call()
        assert e.value.code == code
    assert st.role_of("a@x.com") == "admin"


def test_postgres_members_survive_a_new_store(tmp_path):
    dsn = fresh_db()
    audit = AuditLog(str(tmp_path / "a.jsonl"), dsn=dsn)
    first = MemberStore(dsn, audit)
    first.bootstrap(["a@x.com"])
    first.add("v@x.com", "viewer", "a@x.com")
    second = MemberStore(dsn, audit)  # simulated restart
    assert {m["email"]: m["role"] for m in second.list()} == {"a@x.com": "admin", "v@x.com": "viewer"}
    assert second.bootstrap(["other@x.com"]) == []


def test_write_failure_is_not_swallowed(tmp_path):
    st = MemberStore("postgresql://nobody@127.0.0.1:9/none?connect_timeout=1", None)
    with pytest.raises(MemberError) as e:
        st.add("a@x.com", "viewer", "b@x.com")
    assert e.value.code == "unavailable"


def test_two_stores_cannot_demote_both_last_admins(tmp_path):
    dsn = fresh_db()
    a, b = MemberStore(dsn, None), MemberStore(dsn, None)
    a.bootstrap(["a@x.com", "b@x.com"])
    a.set_role("b@x.com", "viewer", "a@x.com")  # a is now the only admin
    with pytest.raises(MemberError) as e:
        b.set_role("a@x.com", "viewer", "b@x.com")
    assert e.value.code == "last_admin"


# --- member change + audit entry are one transaction ----------------------

def pg_pair(tmp_path):
    dsn = fresh_db()
    audit = AuditLog(str(tmp_path / "a.jsonl"), dsn=dsn)
    return dsn, audit, MemberStore(dsn, audit)


def chain_ok(audit):
    """Recompute the whole chain from the DB: valid hashes, prev links and gap-free seq."""
    rows = audit._conn.execute("SELECT seq, line, sha256 FROM audit_log ORDER BY seq").fetchall()
    assert [r[0] for r in rows] == list(range(1, len(rows) + 1))
    assert audit.verify() == (True, None)
    return [json.loads(r[1]) for r in rows]


def break_audit_insert(audit, monkeypatch):
    """Make the audit INSERT fail inside the member transaction (the member write itself still runs)."""
    real = audit.append_in

    def boom(conn, kind, data):
        conn.execute("INSERT INTO audit_log (seq, ts, kind, prev_sha256, sha256, line) VALUES (NULL, 0, '', '', '', '')")
        return real(conn, kind, data)
    monkeypatch.setattr(audit, "append_in", boom)


def test_pg_change_and_audit_entry_both_land_and_chain_stays_valid(tmp_path):
    dsn, audit, st = pg_pair(tmp_path)
    st.bootstrap(["a@x.com"])
    st.add("v@x.com", "viewer", "a@x.com")
    st.set_role("v@x.com", "admin", "a@x.com")
    st.remove("v@x.com", "a@x.com")
    entries = chain_ok(audit)
    assert [(e["data"]["action"], e["data"]["email"]) for e in entries] == [
        ("add", "a@x.com"), ("add", "v@x.com"), ("role", "v@x.com"), ("remove", "v@x.com")]
    assert [e["seq"] for e in audit.entries] == [1, 2, 3, 4]  # in-memory tail adopted after commit
    audit.append("note", {})  # a plain append continues the chain after transactional ones
    assert len(chain_ok(audit)) == 5


@pytest.mark.parametrize("op", ["bootstrap", "add", "role", "remove"])
def test_pg_audit_failure_rolls_back_the_member_change(tmp_path, monkeypatch, op):
    dsn, audit, st = pg_pair(tmp_path)
    if op != "bootstrap":
        st.bootstrap(["a@x.com"])
        st.add("v@x.com", "viewer", "a@x.com")
    before_members, before_audit = st.list(), chain_ok(audit) if op != "bootstrap" else []
    tail = list(audit.entries)
    break_audit_insert(audit, monkeypatch)
    calls = {"bootstrap": lambda: st.bootstrap(["z@x.com"]),
             "add": lambda: st.add("n@x.com", "viewer", "a@x.com"),
             "role": lambda: st.set_role("v@x.com", "admin", "a@x.com"),
             "remove": lambda: st.remove("v@x.com", "a@x.com")}
    with pytest.raises(MemberError) as e:
        calls[op]()
    assert e.value.code == "unavailable"
    assert st.list() == before_members  # member table unchanged
    assert audit._conn.execute("SELECT count(*) FROM audit_log").fetchone()[0] == len(before_audit)
    assert audit.entries == tail  # in-memory tail untouched on rollback
    monkeypatch.undo()
    assert chain_ok(audit) == before_audit


def test_pg_concurrent_appends_from_two_audit_logs_keep_one_chain(tmp_path):
    dsn = fresh_db()
    plain, other = AuditLog(str(tmp_path / "1.jsonl"), dsn=dsn), AuditLog(str(tmp_path / "2.jsonl"), dsn=dsn)
    st = MemberStore(dsn, other)
    errors = []

    def plain_writer():
        try:
            for i in range(25):
                plain.append("tick", {"i": i})
        except Exception as exc:  # pragma: no cover - failure is asserted below
            errors.append(exc)

    def member_writer():
        try:
            for i in range(25):
                st.add(f"m{i}@x.com", "viewer", "a@x.com")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
    threads = [threading.Thread(target=plain_writer), threading.Thread(target=member_writer)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []
    entries = chain_ok(plain)  # gap-free seq and valid links
    assert len(entries) == 50
    assert sum(e["kind"] == "member" for e in entries) == 25
    assert len(st.list()) == 25


def test_fallback_never_mutates_when_audit_append_fails(tmp_path):
    class BrokenAudit:
        transactional = False

        def append(self, kind, data):
            raise OSError("disk full")
    st = MemberStore(None, BrokenAudit())
    with pytest.raises(MemberError) as e:
        st.bootstrap(["a@x.com"])
    assert e.value.code == "unavailable" and st.list() == []
    st = MemberStore(None, AuditLog(str(tmp_path / "a.jsonl")))
    st.bootstrap(["a@x.com"])
    st.add("v@x.com", "viewer", "a@x.com")
    st._audit = BrokenAudit()
    for call in (lambda: st.add("n@x.com", "viewer", "a@x.com"),
                 lambda: st.set_role("v@x.com", "admin", "a@x.com"),
                 lambda: st.remove("v@x.com", "a@x.com")):
        with pytest.raises(MemberError) as e:
            call()
        assert e.value.code == "unavailable"
    assert {m["email"]: m["role"] for m in st.list()} == {"a@x.com": "admin", "v@x.com": "viewer"}


# --- login gate ---------------------------------------------------------

def test_bootstrap_from_admin_emails_logs_in_admin(boot):
    mod, c = boot()
    assert c.get("/dashboard").status_code == 200
    me = c.get("/api/me").json()
    assert (me["member"], me["role"], me["can_approve"], me["can_manage"]) == (True, "admin", True, True)
    assert {m["email"] for m in mod.members.list()} == {BOSS, OTHER}


def test_non_member_gets_no_access_page(make):  # noqa: F811
    mod, c = make()
    r = login(mod, c, email="Stranger@evil.com")
    assert r.status_code == 303 and r.headers["location"] == "/sin-acceso"
    assert c.get("/dashboard").headers["location"] == "/sin-acceso"
    page = c.get("/sin-acceso")
    assert page.status_code == 403 and "stranger@evil.com" in page.text and "invitación" in page.text
    me = c.get("/api/me").json()
    assert me["member"] is False and me["role"] is None and me["can_approve"] is False and me["can_manage"] is False
    assert me["user"]["email"] == "stranger@evil.com"
    assert c.get("/api/members").status_code == 403
    assert c.post("/api/approvals/1", json={"approve": True}, headers=ADMIN).status_code == 403


def test_no_access_page_escapes_email_and_redirects_others(make):  # noqa: F811
    mod, c = make()
    assert c.get("/sin-acceso").headers["location"] == "/login"
    login(mod, c, email="<b>x</b>@evil.com")
    assert "<b>x</b>" not in c.get("/sin-acceso").text
    admin = second_client(mod, BOSS)
    assert admin.get("/sin-acceso").headers["location"] == "/dashboard"


# --- roles --------------------------------------------------------------

def test_viewer_is_read_only(boot):
    mod, admin = boot()
    assert admin.post("/api/members", json={"email": "v@x.com", "role": "viewer"}, headers=ADMIN).status_code == 201
    v = second_client(mod, "v@x.com")
    assert v.get("/dashboard").status_code == 200
    me = v.get("/api/me").json()
    assert (me["role"], me["can_approve"], me["can_manage"]) == ("viewer", False, False)
    assert v.post("/api/approvals/1", json={"approve": True}, headers=ADMIN).status_code == 403
    assert v.get("/api/members").status_code == 403
    assert v.post("/api/members", json={"email": "z@x.com", "role": "admin"}, headers=ADMIN).status_code == 403
    assert v.patch(f"/api/members/{OTHER}", json={"role": "viewer"}, headers=ADMIN).status_code == 403
    assert v.delete(f"/api/members/{OTHER}", headers=ADMIN).status_code == 403


def test_admin_invite_promote_remove_with_audit(boot):
    mod, c = boot()
    r = c.post("/api/members", json={"email": " New@X.com ", "role": "viewer"}, headers=ADMIN)
    assert r.status_code == 201 and r.json()["member"]["email"] == "new@x.com"
    assert c.post("/api/members", json={"email": "new@x.com", "role": "admin"}, headers=ADMIN).status_code == 409
    assert c.patch("/api/members/new@x.com", json={"role": "admin"}, headers=ADMIN).json()["member"]["role"] == "admin"
    listing = c.get("/api/members").json()
    assert {m["email"]: m["role"] for m in listing["members"]}["new@x.com"] == "admin"
    assert listing["roles"] == ["admin", "viewer"]
    assert c.delete("/api/members/new@x.com", headers=ADMIN).json() == {"ok": True}
    assert c.delete("/api/members/new@x.com", headers=ADMIN).status_code == 404
    mine = [e for e in member_events(mod) if e["email"] == "new@x.com"]
    assert [(e["action"], e["role"], e["actor"]) for e in mine] == [
        ("add", "viewer", BOSS), ("role", "admin", BOSS), ("remove", None, BOSS)]
    assert mod.monitor.executor.audit.verify()[0]  # still one valid hash chain


def test_invalid_input_is_400(boot):
    _, c = boot()
    assert c.post("/api/members", json={"email": "nope", "role": "viewer"}, headers=ADMIN).status_code == 400
    assert c.post("/api/members", json={"email": "a@b.co", "role": "root"}, headers=ADMIN).status_code == 400


def test_self_and_last_admin_guards_over_http(boot):
    mod, c = boot(ADMIN_EMAILS=BOSS)
    assert c.patch(f"/api/members/{BOSS}", json={"role": "viewer"}, headers=ADMIN).json()["code"] == "self"
    assert c.delete(f"/api/members/{BOSS}", headers=ADMIN).status_code == 409
    c.post("/api/members", json={"email": "v@x.com", "role": "viewer"}, headers=ADMIN)
    c.patch("/api/members/v@x.com", json={"role": "admin"}, headers=ADMIN)
    v = second_client(mod, "v@x.com")  # now two admins; v demotes boss, then cannot demote itself or the last admin
    assert v.patch(f"/api/members/{BOSS}", json={"role": "viewer"}, headers=ADMIN).status_code == 200
    assert v.delete("/api/members/v@x.com", headers=ADMIN).json()["code"] == "self"
    boss_again = second_client(mod, BOSS)  # demoted: viewer cannot touch the last admin
    assert boss_again.patch("/api/members/v@x.com", json={"role": "viewer"}, headers=ADMIN).status_code == 403
    with pytest.raises(MemberError) as e:
        mod.members.remove("v@x.com", "someone@else.com")
    assert e.value.code == "last_admin"


@pytest.mark.parametrize("headers", [
    {"Origin": PUBLIC},
    {"X-Requested-With": "centinela"},
    {"X-Requested-With": "centinela", "Origin": "https://evil.example"},
])
def test_member_writes_require_csrf(boot, headers):
    _, c = boot()
    assert c.post("/api/members", json={"email": "a@b.co", "role": "viewer"}, headers=headers).status_code == 403
    assert c.patch(f"/api/members/{OTHER}", json={"role": "viewer"}, headers=headers).status_code == 403
    assert c.delete(f"/api/members/{OTHER}", headers=headers).status_code == 403


def test_members_require_session(make):  # noqa: F811
    _, c = make()
    assert c.get("/api/members").status_code == 401
    assert c.post("/api/members", json={"email": "a@b.co", "role": "viewer"}, headers=ADMIN).status_code == 401


def test_removal_and_demotion_take_effect_on_next_request(boot):
    mod, admin = boot()
    admin.post("/api/members", json={"email": "t@x.com", "role": "admin"}, headers=ADMIN)
    t = second_client(mod, "t@x.com")
    assert t.get("/api/me").json()["can_manage"] is True
    admin.patch("/api/members/t@x.com", json={"role": "viewer"}, headers=ADMIN)
    assert t.get("/api/me").json()["can_manage"] is False
    assert t.post("/api/members", json={"email": "q@x.com", "role": "viewer"}, headers=ADMIN).status_code == 403
    admin.delete("/api/members/t@x.com", headers=ADMIN)
    assert t.get("/dashboard").headers["location"] == "/sin-acceso"
    assert t.get("/api/me").json()["member"] is False


def test_token_approval_path_unchanged_for_non_members(make):  # noqa: F811
    _, c = make(APPROVER_TOKEN="human-secret")
    assert c.post("/api/approvals/1", json={"approve": True},
                  headers={"X-Approver-Token": "human-secret"}).status_code == 404  # authorized, nothing pending


def test_demo_mode_has_no_member_api(make):  # noqa: F811
    mod, c = make(auth=False)
    assert mod.members is None
    assert c.get("/api/members").status_code == 404
    assert c.post("/api/members", json={"email": "a@b.co", "role": "viewer"}).status_code == 404
    assert c.get("/api/me").json() == {"auth": "demo", "user": None, "can_approve": True}


def test_member_write_failure_returns_503(make):  # noqa: F811
    mod, c = make(AUDIT_DATABASE_URL=fresh_db())
    login(mod, c)
    real, calls = mod.members._connection, []

    def flaky():
        calls.append(1)
        if len(calls) > 1:  # first call is the admin check of the request; the write itself fails
            raise RuntimeError("db down")
        return real()
    mod.members._connection = flaky
    r = c.post("/api/members", json={"email": "a@b.co", "role": "viewer"}, headers=ADMIN)
    assert r.status_code == 503 and r.json()["code"] == "unavailable"
    mod.members._connection = real
    assert "a@b.co" not in {m["email"] for m in mod.members.list()}
