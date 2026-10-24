"""Case 2: a small company's API (users, API keys, sessions) backed by Postgres.

Endpoints (only when DATABASE_URL is set; otherwise 503):
  POST /api/login       {username, password} -> session token
  GET  /api/me          X-API-Key or Authorization: Bearer <session>
  GET  /api/invoices    same auth; fake business data
  GET  /access-log      HTTP access log (with User-Agent) for the monitor
  GET  /security-state  keys, blocklist and session counts for the monitor

Every /api/* request is checked against ip_blocklist and user_suspensions and
written to access_log.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import secrets
import threading
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel

log = logging.getLogger("victim.pyme")
HERE = Path(__file__).resolve().parent

router = APIRouter()
_conn = None
_lock = threading.Lock()


def _h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(8)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${digest}"


def _password_ok(password: str, stored: str) -> bool:
    salt, _ = stored.split("$", 1)
    return secrets.compare_digest(_password_hash(password, salt), stored)


def enabled() -> bool:
    return _conn is not None


def init(dsn: str) -> None:
    """Create schema, seed demo data and the executor role. Idempotent."""
    global _conn
    import psycopg
    from psycopg import sql

    _conn = psycopg.connect(dsn, autocommit=True)
    _conn.execute((HERE / "schema.sql").read_text(encoding="utf-8"))
    _seed()
    password = os.environ.get("EXECUTOR_DB_PASSWORD")
    if password:
        roles = (HERE / "roles.sql").read_text(encoding="utf-8")
        try:
            _conn.execute(sql.SQL(roles).format(password=sql.Literal(password)))
        except psycopg.Error as exc:  # e.g. the owner lacks CREATEROLE
            log.error("could not provision executor role: %s", exc)


def close() -> None:
    global _conn
    if _conn is not None:
        _conn.close()
        _conn = None


def _seed() -> None:
    office = os.environ.get("OFFICE_CIDR", "203.0.113.0/24")
    leaked = os.environ.get("DEMO_LEAKED_KEY", "cen_demo_ana_leaked_key")
    admin_key = os.environ.get("ADMIN_API_KEY") or secrets.token_urlsafe(24)
    with _lock, _conn.transaction():
        if _conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            return
        users = {}
        for name, role, pw in (("admin", "admin", secrets.token_urlsafe(12)),
                               ("ana", "staff", "ana-demo"), ("luis", "staff", "luis-demo")):
            users[name] = _conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) RETURNING id",
                (name, _password_hash(pw), role)).fetchone()[0]
        _conn.execute("INSERT INTO api_keys (user_id, label, key_hash, protected) VALUES (%s, %s, %s, true)",
                      (users["admin"], "admin-ops", _h(admin_key)))
        _conn.execute("INSERT INTO api_keys (user_id, label, key_hash) VALUES (%s, %s, %s)",
                      (users["ana"], "ana-integration", _h(leaked)))
        _conn.execute("INSERT INTO api_keys (user_id, label, key_hash) VALUES (%s, %s, %s)",
                      (users["luis"], "luis-reports", _h(secrets.token_urlsafe(24))))
        for name in ("admin", "ana", "luis"):
            _conn.execute("INSERT INTO sessions (user_id, token_hash, ip) VALUES (%s, %s, %s)",
                          (users[name], _h(secrets.token_urlsafe(24)), office.split("/")[0]))
        _conn.execute("INSERT INTO protected_networks (cidr, label) VALUES (%s, 'office') "
                      "ON CONFLICT DO NOTHING", (office,))


def _query(sql: str, params: tuple = ()) -> list[tuple]:
    with _lock:
        cur = _conn.execute(sql, params)
        return cur.fetchall() if cur.description else []


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def client_ip(request: Request) -> str:
    # Render terminates TLS and sets X-Forwarded-For; the left-most entry is the
    # client. A malformed header falls back to the socket peer.
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if forwarded and _valid_ip(forwarded):
        return forwarded
    return request.client.host if request.client else ""


def _authenticate(request: Request) -> tuple[int, str] | None:
    """Return (user_id, username) plus set request.state.api_key_id, or None."""
    key = request.headers.get("x-api-key")
    if key:
        rows = _query("SELECT k.id, u.id, u.username FROM api_keys k JOIN users u ON u.id = k.user_id "
                      "WHERE k.key_hash = %s AND k.status = 'active'", (_h(key),))
        if rows:
            request.state.api_key_id = rows[0][0]
            return rows[0][1], rows[0][2]
        return None
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        rows = _query("SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id "
                      "WHERE s.token_hash = %s", (_h(auth[7:].strip()),))
        if rows:
            return rows[0]
    return None


def _guard_and_log(request: Request, ip: str) -> JSONResponse | None:
    """Blocklist + auth for /api/*. Returns an error response or None."""
    request.state.api_key_id = None
    request.state.user = None
    if _valid_ip(ip) and _query("SELECT 1 FROM ip_blocklist WHERE ip = %s::inet", (ip,)):
        return JSONResponse({"error": "ip blocked"}, status_code=403)
    if request.url.path == "/api/login":
        return None
    user = _authenticate(request)
    if user is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if _query("SELECT 1 FROM user_suspensions WHERE user_id = %s", (user[0],)):
        return JSONResponse({"error": "user suspended"}, status_code=403)
    request.state.user = user
    return None


def _write_log(request: Request, ip: str, status: int) -> None:
    user = getattr(request.state, "user", None)
    _query("INSERT INTO access_log (ip, method, path, status, user_agent, user_id, api_key_id) "
           "VALUES (%s, %s, %s, %s, %s, %s, %s)",
           (ip, request.method, request.url.path, status, request.headers.get("user-agent"),
            user[0] if user else None, getattr(request.state, "api_key_id", None)))


async def middleware(request: Request, call_next):
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    if not enabled():
        return JSONResponse({"error": "case 2 database not configured"}, status_code=503)
    ip = client_ip(request)
    denied = await run_in_threadpool(_guard_and_log, request, ip)
    response = denied or await call_next(request)
    await run_in_threadpool(_write_log, request, ip, response.status_code)
    return response


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/api/login")
def login(req: LoginRequest, request: Request):
    rows = _query("SELECT id, username, password_hash FROM users WHERE username = %s", (req.username,))
    if not rows or not _password_ok(req.password, rows[0][2]):
        return JSONResponse({"error": "invalid credentials"}, status_code=401)
    token = secrets.token_urlsafe(24)
    _query("INSERT INTO sessions (user_id, token_hash, ip) VALUES (%s, %s, %s)",
           (rows[0][0], _h(token), client_ip(request)))
    request.state.user = (rows[0][0], rows[0][1])
    return {"token": token}


@router.get("/api/me")
def me(request: Request):
    user_id, username = request.state.user
    role = _query("SELECT role FROM users WHERE id = %s", (user_id,))[0][0]
    return {"id": user_id, "username": username, "role": role}


@router.get("/api/invoices")
def invoices(request: Request):
    _, username = request.state.user
    return {"owner": username, "invoices": [
        {"id": 1001, "customer": "Panadería El Ávila", "amount_usd": 420.0},
        {"id": 1002, "customer": "Ferretería Chacao", "amount_usd": 1310.5},
    ]}


def _require_db():
    if not enabled():
        return JSONResponse({"error": "case 2 database not configured"}, status_code=503)
    return None


@router.get("/access-log")
def access_log(after: int = 0, limit: int = 100):
    if (err := _require_db()) is not None:
        return err
    rows = _query(
        "SELECT a.id, extract(epoch FROM a.ts), a.ip, a.method, a.path, a.status, a.user_agent, "
        "a.user_id, u.username, a.api_key_id FROM access_log a LEFT JOIN users u ON u.id = a.user_id "
        "WHERE a.id > %s ORDER BY a.id LIMIT %s", (after, max(1, min(limit, 500))))
    cols = ("id", "ts", "ip", "method", "path", "status", "user_agent", "user_id", "username", "api_key_id")
    return {"entries": [dict(zip(cols, r)) | {"ts": float(r[1])} for r in rows]}


@router.get("/security-state")
def security_state():
    if (err := _require_db()) is not None:
        return err
    keys = _query("SELECT k.id, u.username, u.role, k.label, k.status, k.protected "
                  "FROM api_keys k JOIN users u ON u.id = k.user_id ORDER BY k.id")
    blocked = _query("SELECT host(ip), reason FROM ip_blocklist ORDER BY created_at")
    sessions = _query("SELECT u.username, u.id, u.role, count(s.id), "
                      "EXISTS (SELECT 1 FROM user_suspensions x WHERE x.user_id = u.id) FROM users u "
                      "LEFT JOIN sessions s ON s.user_id = u.id GROUP BY u.username, u.id ORDER BY u.id")
    return {
        "api_keys": [dict(zip(("id", "username", "role", "label", "status", "protected"), r)) for r in keys],
        "ip_blocklist": [{"ip": ip, "reason": reason} for ip, reason in blocked],
        "users": [{"id": uid, "username": name, "role": role, "suspended": susp}
                  for name, uid, role, _, susp in sessions],
        "sessions_by_user": {name: n for name, _, _, n, _ in sessions},
    }
