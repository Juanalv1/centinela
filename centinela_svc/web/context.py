"""Per-app runtime state shared by the routers (filled in by the lifespan)."""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from adapters.members import MemberStore
from application.audience import AudienceState
from application.monitor import Monitor
from web.config import Settings


@dataclass
class AppContext:
    settings: Settings
    monitor: Monitor | None = None
    members: MemberStore | None = None  # only exists when Google auth is configured
    audience: AudienceState = field(default_factory=AudienceState)  # in-memory; one process serves the demo
    google_transport: httpx.AsyncBaseTransport | None = None  # tests inject a mock transport
