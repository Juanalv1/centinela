"""S2: audit log persisted in Postgres, hash chain kept across restarts."""
import hashlib
import json

import psycopg
import pytest

from audit import GENESIS, AuditLog
from pg import fresh_db


@pytest.fixture()
def dsn():
    return fresh_db()


def test_entries_survive_restart_and_chain_continues(dsn, tmp_path):
    first = AuditLog(str(tmp_path / "unused.jsonl"), dsn=dsn)
    a = first.append("proposal", {"n": 1})
    b = first.append("decision", {"n": 2})
    assert a["prev_sha256"] == GENESIS

    second = AuditLog(str(tmp_path / "unused.jsonl"), dsn=dsn)  # simulated container restart
    assert [e["seq"] for e in second.entries] == [1, 2]
    c = second.append("startup", {"n": 3})
    assert c["seq"] == 3

    with psycopg.connect(dsn) as conn:
        rows = conn.execute("SELECT seq, line, sha256 FROM audit_log ORDER BY seq").fetchall()
    assert [r[0] for r in rows] == [1, 2, 3]
    assert json.loads(rows[2][1])["prev_sha256"] == hashlib.sha256(rows[1][1].encode()).hexdigest()
    assert all(hashlib.sha256(line.encode()).hexdigest() == sha for _, line, sha in rows)
    assert second.verify() == (True, None)
    assert b["seq"] == 2


def test_tampering_is_blocked_and_detected(dsn, tmp_path):
    log = AuditLog(str(tmp_path / "unused.jsonl"), dsn=dsn)
    log.append("proposal", {"n": 1})
    log.append("decision", {"n": 2})
    with psycopg.connect(dsn, autocommit=True) as conn:
        with pytest.raises(psycopg.Error, match="append-only"):
            conn.execute("UPDATE audit_log SET line = 'x' WHERE seq = 1")
        with pytest.raises(psycopg.Error, match="append-only"):
            conn.execute("DELETE FROM audit_log WHERE seq = 1")
        # An owner who disables the guard can still edit, but verify() catches it.
        conn.execute("ALTER TABLE audit_log DISABLE TRIGGER USER")
        conn.execute("""UPDATE audit_log SET line = replace(line, '"n":1', '"n":9') WHERE seq = 1""")
    assert log.verify() == (False, 1)


def test_file_backend_unchanged_without_dsn(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    log.append("proposal", {"n": 1})
    log.append("decision", {"n": 2})
    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["prev_sha256"] == hashlib.sha256(lines[0].encode()).hexdigest()
    assert log.verify() == (True, None)
