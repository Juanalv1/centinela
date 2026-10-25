"""Case 2: a small company's API (users, API keys, sessions) backed by Postgres.

Endpoints (only when DATABASE_URL is set; otherwise 503):
  POST /api/login       {username, password} -> session token
  GET  /api/me          X-API-Key or Authorization: Bearer <session>
  GET  /api/invoices    same auth; fake business data
  GET  /api/customers   same auth; ?page=N, paginated fake customer records
  GET  /access-log      HTTP access log (User-Agent, bytes, query, lab_seed) for the monitor
  GET  /security-state  keys, blocklist and session counts for the monitor
  POST /lab/reset       X-Lab-Token (only when LAB_TOKEN is set): reactivate keys,
                        clear blocks and suspensions between lab trials

Every /api/* request is checked against ip_blocklist and user_suspensions and
written to access_log.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import random
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Header, Request
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
    _sync_lab_keys()
    _seed_history()
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
                      (users["luis"], "luis-reports",
                       _h(os.environ.get("DEMO_LUIS_KEY") or secrets.token_urlsafe(24))))
        for name in ("admin", "ana", "luis"):
            _conn.execute("INSERT INTO sessions (user_id, token_hash, ip) VALUES (%s, %s, %s)",
                          (users[name], _h(secrets.token_urlsafe(24)), office.split("/")[0]))
        _conn.execute("INSERT INTO protected_networks (cidr, label) VALUES (%s, 'office') "
                      "ON CONFLICT DO NOTHING", (office,))


LAB_TZ = timezone(timedelta(hours=float(os.environ.get("LAB_TZ_OFFSET_HOURS", "-4"))))  # Caracas
HISTORY_DAYS = 21
CUSTOMER_PAGES = 40
PAGE_SIZE = 25
_FIRST = ("María", "José", "Ana", "Luis", "Carmen", "Pedro", "Rosa", "Jesús", "Elena", "Carlos")
_LAST = ("González", "Rodríguez", "Pérez", "Hernández", "García", "Martínez", "López", "Díaz")


def customers_page(page: int) -> list[dict]:
    """Deterministic fake customer records (example.com addresses, no real people)."""
    if not 1 <= page <= CUSTOMER_PAGES:
        return []
    rng = random.Random(page)
    rows = []
    for i in range(PAGE_SIZE):
        cid = (page - 1) * PAGE_SIZE + i + 1
        name = f"{rng.choice(_FIRST)} {rng.choice(_LAST)}"
        rows.append({"id": cid, "name": name, "rif": f"V-{rng.randint(4_000_000, 29_999_999)}",
                     "email": f"cliente{cid}@example.com", "phone": f"+58-412-555-{cid:04d}",
                     "balance_usd": round(rng.uniform(0, 5000), 2)})
    return rows


def _customers_body(page: int) -> dict:
    return {"page": page, "pages": CUSTOMER_PAGES, "page_size": PAGE_SIZE, "customers": customers_page(page)}


def _sync_lab_keys() -> None:
    """Make the luis-reports key match DEMO_LUIS_KEY on databases seeded before it existed."""
    luis = os.environ.get("DEMO_LUIS_KEY")
    if luis:
        with _lock:
            _conn.execute("UPDATE api_keys SET key_hash = %s WHERE label = 'luis-reports' AND key_hash <> %s",
                          (_h(luis), _h(luis)))


def _known_ips(office: str) -> list[str]:
    ips = [ip for ip in (_normalize_ip(v) for v in os.environ.get("LAB_KNOWN_IPS", "").split(",") if v.strip())
           if ip]
    return ips or [office]


def _history_rows(now: datetime, ids: dict, office: str, known: list[str]) -> list[tuple]:
    """Lab history: ana's ERP integration (weekdays, office hours, office ip, two light
    endpoints) and luis's reports bot (every hour from LAB_KNOWN_IPS, paginated customers)."""
    rng = random.Random(2024)
    office_ips = [str(h) for _, h in zip(range(2), ipaddress.ip_network(office, strict=False).hosts())]
    sizes = {"/api/me": len(json.dumps({"id": 2, "username": "ana", "role": "staff"})), "/api/invoices": 190}
    rows = []
    start = (now - timedelta(days=HISTORY_DAYS)).astimezone(LAB_TZ).replace(minute=0, second=0, microsecond=0)
    for hour in range(HISTORY_DAYS * 24):
        t = start + timedelta(hours=hour)
        if t >= now:
            break
        if t.weekday() < 5 and 8 <= t.hour < 18:
            for _ in range(rng.randint(1, 2)):
                ts = t + timedelta(minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
                path = rng.choice(("/api/me", "/api/invoices"))
                rows.append((ts, rng.choice(office_ips), path, None, sizes[path], "AnaERP-Sync/2.3",
                             ids["ana-integration"]))
        ts = t + timedelta(minutes=rng.randint(0, 50))
        rows.append((ts, known[0], "/api/invoices", None, sizes["/api/invoices"], "ReportsBot/1.4",
                     ids["luis-reports"]))
        for page in range(1, rng.randint(2, 3)):
            rows.append((ts + timedelta(seconds=5 * page), known[0], "/api/customers", f"page={page}",
                         len(json.dumps(_customers_body(page))), "ReportsBot/1.4", ids["luis-reports"]))
    return rows


def _seed_history() -> None:
    """Seed the clearly-marked (lab_seed) usage history once; keep luis's ip in LAB_KNOWN_IPS."""
    office = os.environ.get("OFFICE_CIDR", "203.0.113.0/24")
    known = _known_ips(office.split("/")[0])
    with _lock, _conn.transaction():
        ids = dict(_conn.execute("SELECT label, id FROM api_keys "
                                 "WHERE label IN ('ana-integration', 'luis-reports')").fetchall())
        if len(ids) < 2:
            return
        if _conn.execute("SELECT 1 FROM access_log WHERE lab_seed LIMIT 1").fetchone():
            _conn.execute("UPDATE access_log SET ip = %s WHERE lab_seed AND api_key_id = %s "
                          "AND NOT (ip = ANY(%s))", (known[0], ids["luis-reports"], known))
            return
        users = dict(_conn.execute("SELECT k.id, k.user_id FROM api_keys k WHERE k.id = ANY(%s)",
                                   (list(ids.values()),)).fetchall())
        with _conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO access_log (ts, ip, method, path, query, status, bytes, user_agent, user_id, "
                "api_key_id, lab_seed) VALUES (%s, %s, 'GET', %s, %s, 200, %s, %s, %s, %s, true)",
                [(ts, ip, path, query, size, ua, users[key], key)
                 for ts, ip, path, query, size, ua, key in _history_rows(datetime.now(timezone.utc), ids,
                                                                          office, known)])


def _query(sql: str, params: tuple = ()) -> list[tuple]:
    with _lock:
        cur = _conn.execute(sql, params)
        return cur.fetchall() if cur.description else []


def _normalize_ip(value: str) -> str | None:
    """Canonical text form, with IPv4-mapped IPv6 turned into IPv4; None if invalid."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return str(getattr(ip, "ipv4_mapped", None) or ip)


def _valid_ip(value: str) -> bool:
    return _normalize_ip(value) is not None


def client_ip(request: Request) -> str:
    """Client ip as seen by the trusted proxies in front of us.

    Only the entries appended by our own proxies are trusted: with
    TRUSTED_PROXY_HOPS=1 (Render) that is the right-most X-Forwarded-For entry.
    Anything to its left was written by the client and is ignored. With 0
    (default, no proxy) the header is ignored and the socket peer is used.
    """
    peer = request.client.host if request.client else ""
    hops = int(os.environ.get("TRUSTED_PROXY_HOPS", "0") or 0)
    entries = [e.strip() for e in (request.headers.get("x-forwarded-for") or "").split(",") if e.strip()]
    candidate = entries[-hops] if hops > 0 and len(entries) >= hops else peer
    return _normalize_ip(candidate) or _normalize_ip(peer) or peer


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


def _write_log(request: Request, ip: str, status: int, size: int | None) -> None:
    user = getattr(request.state, "user", None)
    _query("INSERT INTO access_log (ip, method, path, query, status, bytes, user_agent, user_id, api_key_id) "
           "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
           (ip, request.method, request.url.path, request.url.query or None, status, size,
            request.headers.get("user-agent"), user[0] if user else None,
            getattr(request.state, "api_key_id", None)))


async def middleware(request: Request, call_next):
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    if not enabled():
        return JSONResponse({"error": "case 2 database not configured"}, status_code=503)
    ip = client_ip(request)
    denied = await run_in_threadpool(_guard_and_log, request, ip)
    response = denied or await call_next(request)
    size = response.headers.get("content-length")
    await run_in_threadpool(_write_log, request, ip, response.status_code, int(size) if size else None)
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


@router.get("/api/customers")
def customers(page: int = 1):
    return _customers_body(page)


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
        "a.user_id, u.username, a.api_key_id, a.bytes, a.query, a.lab_seed "
        "FROM access_log a LEFT JOIN users u ON u.id = a.user_id "
        "WHERE a.id > %s ORDER BY a.id LIMIT %s", (after, max(1, min(limit, 500))))
    cols = ("id", "ts", "ip", "method", "path", "status", "user_agent", "user_id", "username", "api_key_id",
            "bytes", "query", "lab_seed")
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


@router.post("/lab/reset")
def lab_reset(x_lab_token: str | None = Header(default=None)):
    """Undo containment between lab trials. Absent unless LAB_TOKEN is set."""
    expected = os.environ.get("LAB_TOKEN", "")
    if not expected:
        return JSONResponse({"error": "not found"}, status_code=404)
    if not x_lab_token or not hmac.compare_digest(x_lab_token.encode(), expected.encode()):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if (err := _require_db()) is not None:
        return err
    with _lock, _conn.transaction():
        keys = _conn.execute("UPDATE api_keys SET status = 'active' WHERE status = 'revoked' AND NOT protected")
        blocks = _conn.execute("DELETE FROM ip_blocklist")
        suspensions = _conn.execute("DELETE FROM user_suspensions")
    return {"reactivated_keys": keys.rowcount, "unblocked_ips": blocks.rowcount,
            "lifted_suspensions": suspensions.rowcount}
