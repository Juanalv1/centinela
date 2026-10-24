"""Embedded PostgreSQL for tests (pgserver). One server per test session."""
from __future__ import annotations

import os
import uuid

import pgserver
import psycopg

_server = None


def server():
    global _server
    if _server is None:
        _server = pgserver.get_server(os.environ["PGSERVER_DATA"], cleanup_mode="stop")
    return _server


def fresh_db() -> str:
    """Create an empty database and return its URI."""
    srv = server()
    name = "t_" + uuid.uuid4().hex[:12]
    with psycopg.connect(srv.get_uri(), autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    return srv.get_uri(name)
