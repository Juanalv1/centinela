"""Ports: the outbound interfaces the application layer depends on.

Only boundaries with a second implementation or a test fake get a Protocol:
the reasoner, the victim (HTTP kill channel and case-2 database) and the audit log.
`VictimRowMapper` is the victim's access-log adapter, injected so this layer never imports it.
"""
from __future__ import annotations

from typing import Protocol

from domain.access import AccessEvent
from domain.model import Proposal


class ReasonerPort(Protocol):
    async def propose(self, metrics: dict) -> Proposal: ...


class VictimPort(Protocol):
    """Least-privilege kill channel to the victim."""

    async def kill(self, pid: int) -> dict: ...


class VictimDbPort(Protocol):
    """Case-2 actions through the executor's least-privilege database role."""

    async def policy(self, action: str, target_id: int) -> str | None: ...

    async def act(self, action: str, value: str, why: str) -> dict: ...


class AuditPort(Protocol):
    """Append-only audit trail; `entries` is the in-memory tail shown on the panel."""

    entries: list[dict]

    def append(self, kind: str, data: dict) -> dict: ...


class VictimRowMapper(Protocol):
    """Maps one victim /access-log row to a normalized event (None for rows made without a key)."""

    def __call__(self, row: dict) -> AccessEvent | None: ...
