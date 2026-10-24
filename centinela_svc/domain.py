"""Domain types for Centinela. No I/O here."""
from __future__ import annotations

import itertools
import time
from dataclasses import asdict, dataclass, field

# Closed response menu: the only actions the executor will ever perform.
MENU: frozenset[str] = frozenset({"matar_proceso"})
NO_ACTION = "ninguna"

# Processes the executor refuses to touch, regardless of what is proposed.
PROTECTED_NAMES: frozenset[str] = frozenset({"db-sim", "init", "systemd", "uvicorn"})
PROTECTED_CMDLINE_TOKENS: tuple[str, ...] = ("db-sim", "python -m uvicorn", "uvicorn")

_ids = itertools.count(1)


@dataclass
class Proposal:
    accion: str | None
    pid: int | None
    nombre: str | None
    justificacion: str
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
    status: str  # "executed" | "rejected" | "noop" | "failed"
    reason: str
    pid: int | None = None
    result: dict | None = None
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)
