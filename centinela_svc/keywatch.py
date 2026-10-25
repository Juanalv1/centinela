"""Deterministic per-API-key baseline. No AI here.

Each key's successful requests older than the current window form its profile
(ips, networks, usual hours on weekdays and weekends, endpoints, busiest hour
by bytes). The
window (last `window_s` seconds) is compared against it. A key is flagged only
when several independent deviations combine, never on one alone (a known user
on a new network is not an incident). Only activity older than `learn_after_s`
(default one day) is learned: anything more recent is judged, never learned, so
neither an attack ageing out of the window nor a restart re-reading the whole
log can turn today's misuse into "normal".
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

FLAG_SCORE = 2
_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def _network(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 48}", strict=False))


class _Profile:
    def __init__(self) -> None:
        self.ips: set[str] = set()
        self.networks: set[str] = set()
        self.slots: set[tuple[int, int]] = set()  # (weekday, hour), local time
        self.hour_range: dict[bool, tuple[int, int]] = {}  # is_weekend -> (first, last) hour seen
        self.endpoints: set[str] = set()
        self.hour_bytes: dict[tuple, int] = defaultdict(int)
        self.first_ts: float | None = None

    def add(self, e: dict, local: datetime) -> None:
        self.ips.add(e["ip"])
        self.networks.add(_network(e["ip"]))
        self.slots.add((local.weekday(), local.hour))
        weekend = local.weekday() >= 5
        lo, hi = self.hour_range.get(weekend, (local.hour, local.hour))
        self.hour_range[weekend] = (min(lo, local.hour), max(hi, local.hour))
        self.endpoints.add(e["path"])
        self.hour_bytes[(local.date(), local.hour)] += e.get("bytes") or 0
        self.first_ts = e["ts"] if self.first_ts is None else min(self.first_ts, e["ts"])

    def usual(self, local: datetime) -> bool:
        """Inside the hours this key keeps on this kind of day (weekday or weekend)?"""
        span = self.hour_range.get(local.weekday() >= 5)
        return span is not None and span[0] <= local.hour <= span[1]

    def summary(self, now: float) -> dict:
        hours = sorted({h for _, h in self.slots})
        return {
            "days": int((now - self.first_ts) // 86400) if self.first_ts else 0,
            "ips": sorted(self.ips)[:5],
            "networks": sorted(self.networks)[:5],
            "weekdays": [_DAYS[d] for d in sorted({d for d, _ in self.slots})],
            "hours": [hours[0], hours[-1]] if hours else None,
            "endpoints": sorted(self.endpoints),
            "max_hour_bytes": max(self.hour_bytes.values(), default=0),
        }


class KeyWatch:
    def __init__(self, window_s: float = 600, tz_offset_hours: float = -4,
                 learn_after_s: float = 86400) -> None:
        self.window_s = window_s
        self.learn_after_s = learn_after_s
        self.tz = timezone(timedelta(hours=tz_offset_hours))
        self.profiles: dict[int, _Profile] = defaultdict(_Profile)
        self.recent: dict[int, list[dict]] = defaultdict(list)

    def _local(self, ts: float) -> datetime:
        return datetime.fromtimestamp(ts, self.tz)

    def ingest(self, entries: list[dict], now: float) -> None:
        for e in entries:
            key = e.get("api_key_id")
            if key is None or not 200 <= (e.get("status") or 0) < 300:
                continue  # profiles describe what the key successfully did
            if e["ts"] < now - self.learn_after_s:
                self.profiles[key].add(e, self._local(e["ts"]))
            elif e["ts"] >= now - self.window_s:
                self.recent[key].append(e)
            # between the two: too recent to learn, too old to judge



    def _age(self, now: float) -> None:
        """Drop entries that left the window. They are not learned now; a later restart
        re-reads them as history only once they are older than learn_after_s."""
        for key, entries in self.recent.items():
            self.recent[key] = [e for e in entries if e["ts"] >= now - self.window_s]

    def evaluate(self, now: float, active_keys: set[int] | None = None) -> list[dict]:
        """Flagged keys, most anomalous first. `active_keys` limits it to keys still usable."""
        self._age(now)
        flags = []
        for key, window in self.recent.items():
            profile = self.profiles.get(key)
            if not window or profile is None or profile.first_ts is None:
                continue  # no history to compare against
            if active_keys is not None and key not in active_keys:
                continue
            flag = self._compare(key, window, profile, now)
            if flag["score"] >= FLAG_SCORE:
                flags.append(flag)
        return sorted(flags, key=lambda f: -f["score"])

    def _compare(self, key: int, window: list[dict], p: _Profile, now: float) -> dict:
        ips = sorted({e["ip"] for e in window})
        locals_ = [self._local(e["ts"]) for e in window]
        total = sum(e.get("bytes") or 0 for e in window)
        pages = {v for e in window for v in parse_qs(e.get("query") or "").get("page", [])}
        busiest = max(p.hour_bytes.values(), default=0)
        signals = {
            "new_ip": any(ip not in p.ips for ip in ips),
            "new_network": any(_network(ip) not in p.networks for ip in ips),
            "off_hours": not all(p.usual(t) for t in locals_),
            "new_endpoints": sorted({e["path"] for e in window} - p.endpoints),
            "pages": len(pages),
            "volume_ratio": round(total / max(busiest, 1), 1),
        }
        score = ((signals["new_ip"] or signals["new_network"]) + signals["off_hours"]
                 + bool(signals["new_endpoints"]) + (signals["volume_ratio"] >= 3 or signals["pages"] >= 5))
        last = max(locals_)
        return {
            "key_id": key,
            "score": score,
            "signals": signals,
            "window": {
                "seconds": round(self.window_s),
                "requests": len(window),
                "ips": ips[:5],
                "endpoints": sorted({e["path"] for e in window}),
                "bytes": total,
                "local_time": f"{_DAYS[last.weekday()]} {last:%H:%M}",
            },
            "profile": p.summary(now),
        }
