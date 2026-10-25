"""Domain types for Centinela. No I/O here.

Shared contract between the reasoner (what the AI may propose) and the
executor (what the code will actually do). Change it only by agreement.
"""
from __future__ import annotations

import itertools
import time
from dataclasses import asdict, dataclass, field
from enum import StrEnum


class Lane(StrEnum):
    AUTO = "auto"            # reversible: executes immediately
    APPROVAL = "approval"    # waits for a human
    RECOMMEND = "recommend"  # outside the menu: shown to a human, never executed


@dataclass(frozen=True)
class ActionSpec:
    target_type: str  # "process" | "key" | "ip" | "user"
    lane: Lane


# Closed response menu: the only actions the executor will ever perform.
# The lane comes from here, never from the model.
MENU: dict[str, ActionSpec] = {
    "kill_process":   ActionSpec("process", Lane.AUTO),
    "revoke_key":     ActionSpec("key",     Lane.AUTO),
    "block_ip":       ActionSpec("ip",      Lane.AUTO),
    "close_sessions": ActionSpec("user",    Lane.AUTO),
    "suspend_user":   ActionSpec("user",    Lane.APPROVAL),
}
NO_ACTION = "none"
RECOMMEND_ACTION = "recommend"
CONFIDENCE_LEVELS = ("low", "medium", "high")

_ids = itertools.count(1)


def seed_ids(max_seen: int) -> None:
    """Continue proposal ids after `max_seen` (ids already in the audit log); never goes backwards."""
    global _ids
    _ids = itertools.count(max(next(_ids), max_seen + 1))


@dataclass
class Target:
    type: str
    value: str


@dataclass
class Proposal:
    action: str | None  # MENU key, "none" or "recommend"
    target: Target | None
    rationale: str
    evidence: list[str]  # log lines / metric facts the AI relies on
    confidence: str  # "low" | "medium" | "high"
    source: str  # "claude" | "forged"
    discarded: bool = False  # True when the reasoner output was unusable
    error: str | None = None
    id: int = field(default_factory=lambda: next(_ids))
    created_at: float = field(default_factory=time.time)
    latency_s: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Decision:
    proposal_id: int
    status: str  # executed | rejected | pending_approval | recommended | noop | failed
    reason: str
    layer: str | None = None  # layer that stopped it: "menu" | "policy" | "infra"; None if not stopped
    target: Target | None = None
    result: dict | None = None
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)
