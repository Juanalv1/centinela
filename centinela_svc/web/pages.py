"""HTML pages: panel, phone portal, dashboard and the login screens."""
from __future__ import annotations

import html

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from web import html_pages
from web.auth import Guards
from web.context import AppContext


def register(router: FastAPI, ctx: AppContext, guards: Guards) -> None:
    """Add these routes straight onto the app (keeps `app.routes` flat)."""
    auth_configured = ctx.settings.auth_configured

    @router.get("/health")
    def health() -> dict:
        return {"ok": True}

    @router.get("/", response_class=HTMLResponse)
    def panel() -> str:
        return html_pages.PANEL

    @router.get("/unirse", response_class=HTMLResponse)
    def join() -> str:
        """Short link printed on the QR; serves the mobile participant portal."""
        return html_pages.PORTAL

    @router.get("/legacy", response_class=HTMLResponse)
    def legacy_panel() -> str:
        """Raw technical panel (process table, audit log); kept for debugging."""
        return html_pages.LEGACY_PANEL

    @router.get("/dashboard", response_class=HTMLResponse)
    def dashboard(request: Request):
        """Client-facing security dashboard; requires a Google session when auth is configured."""
        if auth_configured:
            user = guards.session_user(request)
            if user is None:
                return RedirectResponse("/login", status_code=303)
            if guards.role(user) is None:
                return RedirectResponse("/sin-acceso", status_code=303)
        return HTMLResponse(html_pages.DASHBOARD)

    @router.get("/sin-acceso", response_class=HTMLResponse)
    def no_access(request: Request):
        """A verified Google account that is not a member: tells them to ask an admin for an invitation."""
        if not auth_configured:
            return RedirectResponse("/dashboard", status_code=303)
        user = guards.session_user(request)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        if guards.role(user) is not None:
            return RedirectResponse("/dashboard", status_code=303)
        return HTMLResponse(html_pages.NO_ACCESS.replace("{{email}}", html.escape(str(user["email"]))),
                            status_code=403, headers={"Cache-Control": "no-store"})

    @router.get("/login", response_class=HTMLResponse)
    def login(request: Request):
        if not auth_configured or guards.session_user(request) is not None:
            return RedirectResponse("/dashboard", status_code=303)  # /dashboard routes non-members onward
        return HTMLResponse(html_pages.LOGIN)

