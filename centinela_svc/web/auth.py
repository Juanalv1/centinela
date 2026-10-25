"""Google login, session helpers, role checks and CSRF (routes + guards)."""
from __future__ import annotations

import hmac
import logging
import secrets
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse

from adapters.members import MemberError
from web.context import AppContext

log = logging.getLogger("centinela")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
SESSION_MAX_AGE_S = 8 * 3600


class Guards:
    """Request guards bound to one app's context."""

    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx

    def session_user(self, request: Request) -> dict | None:
        """The logged-in Google user, or None (always None when auth is not configured)."""
        if not self.ctx.settings.auth_configured:
            return None
        user = request.session.get("user")
        return user if isinstance(user, dict) and user.get("email") else None

    def role(self, user: dict | None) -> str | None:
        """The member's role, read from the store on every request (never cached in the cookie)."""
        members = self.ctx.members
        if not user or members is None:
            return None
        try:
            return members.role_of(str(user["email"]))
        except MemberError:
            log.warning("member lookup failed; denying access")
            return None  # fail closed

    def is_admin(self, user: dict | None) -> bool:
        return self.role(user) == "admin"

    def redirect_uri(self, request: Request) -> str:
        base = self.ctx.settings.public_url or str(request.base_url).rstrip("/")
        return f"{base}/auth/callback"

    def csrf_ok(self, request: Request) -> bool:
        """Session-authenticated writes need a same-site Origin plus a custom header."""
        if request.headers.get("x-requested-with") != "centinela":
            return False
        origin = request.headers.get("origin")
        if not origin:
            return False
        public_url = self.ctx.settings.public_url
        if public_url:
            return origin.rstrip("/") == public_url
        return urlparse(origin).netloc == request.headers.get("host", "")

    def admin_gate(self, request: Request, write: bool) -> tuple[str | None, JSONResponse | None]:
        """(actor email, None) for an admin session, else (None, error response). Writes also need CSRF."""
        if not self.ctx.settings.auth_configured or self.ctx.members is None:
            return None, JSONResponse({"error": "members are disabled in demo mode"}, status_code=404)
        user = self.session_user(request)
        if user is None:
            return None, JSONResponse({"error": "unauthorized"}, status_code=401)
        if not self.is_admin(user) or (write and not self.csrf_ok(request)):
            return None, JSONResponse({"error": "forbidden"}, status_code=403)
        return str(user["email"]).lower(), None


def _login_error(code: str) -> RedirectResponse:
    return RedirectResponse("/login?" + urlencode({"error": code}), status_code=303)


def register(router: FastAPI, ctx: AppContext, guards: Guards) -> None:
    """Add these routes straight onto the app (keeps `app.routes` flat)."""
    settings = ctx.settings

    @router.get("/auth/google")
    def auth_google(request: Request):
        if not settings.auth_configured:
            return RedirectResponse("/dashboard", status_code=303)
        state = secrets.token_urlsafe(32)
        request.session["oauth_state"] = state
        query = urlencode({
            "client_id": settings.google_client_id, "redirect_uri": guards.redirect_uri(request),
            "response_type": "code", "scope": "openid email profile",
            "state": state, "prompt": "select_account",
        })
        return RedirectResponse(f"{GOOGLE_AUTH_URL}?{query}", status_code=303)

    @router.get("/auth/callback")
    async def auth_callback(request: Request, code: str | None = None, state: str | None = None,
                            error: str | None = None):
        if not settings.auth_configured:
            return RedirectResponse("/dashboard", status_code=303)
        expected = request.session.pop("oauth_state", None)  # single use
        if error:
            return _login_error("denied")
        if not (expected and state and code) or not hmac.compare_digest(str(state).encode(), str(expected).encode()):
            return _login_error("state")
        try:
            async with httpx.AsyncClient(timeout=10, transport=ctx.google_transport) as http:
                tok = await http.post(GOOGLE_TOKEN_URL, data={
                    "code": code, "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "redirect_uri": guards.redirect_uri(request), "grant_type": "authorization_code"})
                tok.raise_for_status()
                access = tok.json().get("access_token")
                if not access:
                    return _login_error("failed")
                info = await http.get(GOOGLE_USERINFO_URL, headers={"Authorization": f"Bearer {access}"})
                info.raise_for_status()
                profile = info.json()
        except Exception as exc:  # network / Google error / bad JSON
            logging.getLogger("centinela.auth").warning("google login failed: %s", type(exc).__name__)
            return _login_error("failed")
        if profile.get("email_verified") is not True or not profile.get("email"):
            return _login_error("email")
        request.session["user"] = {"email": str(profile["email"]).lower(),
                                   "name": str(profile.get("name") or profile["email"]),
                                   "picture": str(profile.get("picture") or "")}
        return RedirectResponse("/dashboard" if guards.role(request.session["user"]) else "/sin-acceso",
                                status_code=303)

    @router.post("/logout")
    def logout(request: Request):
        if settings.auth_configured:
            request.session.clear()
        return RedirectResponse("/", status_code=303)

    @router.get("/api/me")
    def api_me(request: Request) -> JSONResponse:
        """Who is looking, and whether they may resolve approvals (drives the dashboard UI)."""
        if not settings.auth_configured:
            # Demo mode keeps the legacy rule: open unless an approver token is configured.
            body = {"auth": "demo", "user": None, "can_approve": not settings.approver_token}
        else:
            user = guards.session_user(request)
            role = guards.role(user)
            body = {"auth": "google", "member": role is not None, "role": role,
                    "can_approve": role == "admin", "can_manage": role == "admin",
                    "user": {k: user.get(k, "") for k in ("name", "email", "picture")} if user else None}
        return JSONResponse(body, headers={"Cache-Control": "no-store"})

