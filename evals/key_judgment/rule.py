"""Deterministic baseline: count independent deviations from the profile, revoke at two or more.
Same idea as KeyWatch's score, written against the eval's scenario data."""
from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass

from .scenarios import ALL_DAYS, Scenario

REVOKE_AT = 2
PAGINATED_AT = 5  # distinct pages in the window


@dataclass(frozen=True)
class RuleDecision:
    decision: str  # "revoke" or "allow"
    deviations: tuple[str, ...]


def _in_networks(ip: str, networks: tuple[str, ...]) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(n, strict=False) for n in networks)


def deviations(s: Scenario) -> tuple[str, ...]:
    p, w = s.profile, s.window
    lo, hi = p.hours
    hourly_requests, hourly_bytes = Counter(), Counter()
    for r in w:
        slot = r.time.replace(minute=0, second=0, microsecond=0)
        hourly_requests[slot] += 1
        hourly_bytes[slot] += r.bytes
    found = {
        "new_network": any(not _in_networks(r.ip, p.networks) for r in w),
        "off_hours": any(ALL_DAYS[r.time.weekday()] not in p.weekdays or not lo <= r.time.hour <= hi for r in w),
        "new_endpoint": any(r.endpoint not in p.endpoints for r in w),
        "volume": (max(hourly_requests.values()) > p.max_hour_requests
                   or max(hourly_bytes.values()) > p.max_hour_bytes),
        "paginated": len({r.page for r in w if r.page is not None}) >= PAGINATED_AT,
    }
    return tuple(name for name, hit in found.items() if hit)


def decide(s: Scenario) -> RuleDecision:
    devs = deviations(s)
    return RuleDecision("revoke" if len(devs) >= REVOKE_AT else "allow", devs)
