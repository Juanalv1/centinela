"""Centinela API + panel: composition root (settings, adapters, lifespan, routers)."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from adapters.audience_store import AudienceStore
from adapters.audit import AuditLog
from adapters.members import MemberStore
from adapters.reasoner import ClaudeReasoner
from adapters.victim import VictimClient, VictimDb, from_victim_row
from application.executor import Executor
from application.monitor import Monitor
from web import api, auth, members_routes, pages
from web.config import Settings
from web.context import AppContext

log = logging.getLogger("centinela")

RESTORE_ENTRIES = 2000  # audit tail replayed at startup to refill the dashboard history


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    ctx = AppContext(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        async with httpx.AsyncClient() as http:
            audit = AuditLog(settings.audit_path, dsn=settings.audit_database_url)
            reasoner = ClaudeReasoner(settings.anthropic_api_key, settings.model)
            db = VictimDb(settings.executor_database_url) if settings.executor_database_url else None
            executor = Executor(VictimClient(settings.victim_url, settings.executor_token, http), audit,
                                db=db, protected_networks=(settings.office_cidr,))
            ctx.monitor = monitor = Monitor(settings.victim_url, settings.poll_seconds, reasoner, executor, http,
                                            victim_events=from_victim_row)
            try:  # a broken history must never keep the service from starting
                monitor.restore(audit.recent(RESTORE_ENTRIES))
                if settings.audit_database_url:  # audience history needs the database; JSONL stays in memory
                    ctx.audience.store = AudienceStore(settings.audit_database_url)
                    ctx.audience.restore()
            except Exception:
                logging.getLogger("centinela").exception("history restore failed; starting empty")
            if settings.auth_configured:  # a failed bootstrap must not keep the service from starting
                ctx.members = MemberStore(settings.audit_database_url, audit)
                try:
                    ctx.members.bootstrap(settings.admin_emails)
                except Exception:
                    log.exception("member bootstrap failed")
            task = asyncio.create_task(monitor.run())
            audit.append("startup", {"victim_url": settings.victim_url, "model": settings.model,
                                     "poll_s": settings.poll_seconds})
            try:
                yield
            finally:
                task.cancel()

    app = FastAPI(title="centinela", lifespan=lifespan)
    app.state.ctx = ctx

    # The victim's real-time monitor page (different origin) reads /api/state and
    # /api/live to render the live IA/executor columns, so allow cross-origin GETs.
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["GET"], allow_headers=["*"],
    )
    if settings.auth_configured:
        from starlette.middleware.sessions import SessionMiddleware

        app.add_middleware(
            SessionMiddleware, secret_key=settings.session_secret, session_cookie="centinela_session",
            max_age=auth.SESSION_MAX_AGE_S, same_site="lax", https_only=settings.public_url.startswith("https"),
        )

    guards = auth.Guards(ctx)
    for module in (pages, auth, api, members_routes):
        module.register(app, ctx, guards)
    return app


logging.basicConfig(level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per poll is noise
app = create_app()
