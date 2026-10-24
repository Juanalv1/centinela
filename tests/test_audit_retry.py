"""Audit append survives a seq collision from a concurrent writer (deploy overlap)."""
from conftest import SVC, load_module

audit_mod = load_module("centinela_audit_retry", SVC / "audit.py")
AuditLog = audit_mod.AuditLog
GENESIS = audit_mod.GENESIS


class FakeUnique(Exception):
    pass


class FakeConn:
    """Minimal psycopg stand-in: stores seq->sha256, raises on duplicate seq."""

    def __init__(self, always_collide=False):
        self.rows: dict[int, str] = {}
        self.always_collide = always_collide
        self._result = None

    def seed(self, seq, sha):
        self.rows[seq] = sha

    def execute(self, sql, params=None):
        s = sql.strip()
        if s.startswith("INSERT"):
            seq, _ts, _kind, _prev, sha, _line = params
            if self.always_collide or seq in self.rows:
                raise FakeUnique("duplicate key")
            self.rows[seq] = sha
            self._result = None
        elif s.startswith("SELECT seq, sha256"):
            self._result = (max(self.rows), self.rows[max(self.rows)]) if self.rows else None
        return self

    def fetchone(self):
        return self._result


def _pg_audit(tmp_path, conn):
    a = AuditLog(str(tmp_path / "unused.jsonl"))  # file init; we swap the backend
    a._conn = conn
    a._unique = FakeUnique
    a._seq, a._prev = 0, GENESIS
    return a


def test_append_retries_and_relinks_after_collision(tmp_path):
    conn = FakeConn()
    conn.seed(1, "a" * 64)  # another writer already took seq 1
    a = _pg_audit(tmp_path, conn)
    entry = a.append("proposal", {"x": 1})
    assert entry["seq"] == 2                       # retried with the next seq
    assert entry["prev_sha256"] == "a" * 64        # relinked to the real last entry
    assert 2 in conn.rows
    assert a._seq == 2


def test_append_reraises_if_collision_persists(tmp_path):
    conn = FakeConn(always_collide=True)
    a = _pg_audit(tmp_path, conn)
    try:
        a.append("proposal", {"x": 1})
        assert False, "expected the persistent collision to propagate"
    except FakeUnique:
        pass


def test_normal_append_chain_links_each_entry(tmp_path):
    conn = FakeConn()
    a = _pg_audit(tmp_path, conn)
    e1 = a.append("startup", {})
    e2 = a.append("proposal", {"n": 1})
    assert e1["seq"] == 1 and e2["seq"] == 2
    assert e1["prev_sha256"] == GENESIS
    assert e2["prev_sha256"] == conn.rows[1]  # links to entry 1's stored sha256
