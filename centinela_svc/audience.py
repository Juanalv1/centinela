"""Live audience participation: QR join + real attacks, with rate limits.

Everything here drives the REAL executor/audit via the existing endpoints;
nothing is faked. The only concession to physics is that the CPU miner (case 1)
runs one job at a time on a 512MB host, so it is a rate-limited singleton; the
scalable real attack is the forged "compromised AI" proposal, which the real
executor really rejects (real layer, real audit entry).
"""
from __future__ import annotations

import re
import time
from collections import deque

HANDLE_RE = re.compile(r"^@?([A-Za-z0-9_]{2,15})$")

MAX_PARTICIPANTS = 200   # cap the in-memory registry
JOIN_COOLDOWN_S = 1.0    # per-ip min seconds between joins
ACTION_COOLDOWN_S = 2.0  # per-handle min seconds between attacks
MINER_COOLDOWN_S = 12.0  # min seconds between real CPU jobs (singleton-ish)
ACTIVITY_MAX = 60        # activity ring-buffer size


def normalize_handle(raw: object) -> str | None:
    """`@Vale`, `vale`, ` VALE ` -> `vale`; reject anything else."""
    if not isinstance(raw, str):
        return None
    m = HANDLE_RE.match(raw.strip())
    return m.group(1).lower() if m else None


class RateLimited(Exception):
    """Raised when a join/action is refused; `reason` is 'rate' or 'full'."""

    def __init__(self, retry_s: float, reason: str = "rate") -> None:
        super().__init__(reason)
        self.retry_s = round(max(retry_s, 0.0), 1)
        self.reason = reason


class AudienceState:
    """In-memory registry + activity feed for the live demo (one process)."""

    def __init__(self, *, clock=time.time) -> None:
        self._clock = clock
        self.participants: dict[str, dict] = {}
        self.activity: deque[dict] = deque(maxlen=ACTIVITY_MAX)
        self._last_join_by_ip: dict[str, float] = {}
        self._last_miner_at: float = 0.0

    # --- registration -----------------------------------------------------
    def join(self, handle: str, ip: str) -> dict:
        now = self._clock()
        last = self._last_join_by_ip.get(ip, 0.0)
        if now - last < JOIN_COOLDOWN_S:
            raise RateLimited(JOIN_COOLDOWN_S - (now - last))
        if handle not in self.participants and len(self.participants) >= MAX_PARTICIPANTS:
            raise RateLimited(0.0, reason="full")
        self._last_join_by_ip[ip] = now
        p = self.participants.get(handle)
        if p is None:
            p = {"handle": handle, "joined_at": now, "actions": 0,
                 "best_s": None, "last_action_at": 0.0}
            self.participants[handle] = p
        return p

    def known(self, handle: str) -> bool:
        return handle in self.participants

    # --- actions ----------------------------------------------------------
    def check_action(self, handle: str) -> dict:
        """Return the participant, or raise: KeyError (unknown) / RateLimited."""
        p = self.participants.get(handle)
        if p is None:
            raise KeyError(handle)
        now = self._clock()
        wait = ACTION_COOLDOWN_S - (now - p["last_action_at"])
        if wait > 0:
            raise RateLimited(wait)
        return p

    def miner_allowed(self) -> bool:
        return self._clock() - self._last_miner_at >= MINER_COOLDOWN_S

    def note_miner(self) -> None:
        self._last_miner_at = self._clock()

    def record(self, handle: str, attack: str, outcome: dict) -> dict:
        """Count the action, update best containment, append to the feed."""
        now = self._clock()
        p = self.participants.get(handle)
        if p is not None:
            p["actions"] += 1
            p["last_action_at"] = now
            cs = outcome.get("containment_s")
            if cs is not None and (p["best_s"] is None or cs > p["best_s"]):
                p["best_s"] = cs
        entry = {"ts": now, "handle": handle, "attack": attack, **outcome}
        self.activity.appendleft(entry)
        return entry

    # --- read model for the big screen ------------------------------------
    def live(self) -> dict:
        board = sorted(
            ({"handle": p["handle"], "best_s": p["best_s"], "actions": p["actions"]}
             for p in self.participants.values() if p["actions"] > 0),
            key=lambda r: (-r["actions"], r["best_s"] is None, -(r["best_s"] or 0.0)),
        )[:5]
        return {
            "people": len(self.participants),
            "activity": list(self.activity),
            "board": board,
        }
