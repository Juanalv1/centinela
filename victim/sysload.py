"""Container load for the victim's real-time monitor.

psutil.cpu_percent() reports the whole physical host (16 shared cores on Render),
so this container's own load is lost in the neighbours' noise. We read cgroup v2
instead and report CPU/memory as a percentage of the container's OWN limits, so a
real miner pegging its slice reads ~100% and its death reads ~0%.
"""
from __future__ import annotations

import time
from pathlib import Path

_CPU_STAT = Path("/sys/fs/cgroup/cpu.stat")
_CPU_MAX = Path("/sys/fs/cgroup/cpu.max")
_MEM_CUR = Path("/sys/fs/cgroup/memory.current")
_MEM_MAX = Path("/sys/fs/cgroup/memory.max")
_cpu_prev: dict[str, float | None] = {"usage_usec": None, "t": None}


def _read_int(path: Path) -> int | None:
    try:
        return int(path.read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _usage_usec() -> int | None:
    try:
        for line in _CPU_STAT.read_text().splitlines():
            if line.startswith("usage_usec"):
                return int(line.split()[1])
    except (OSError, ValueError):
        return None
    return None


def _quota_cores() -> float | None:
    try:
        quota, period = _CPU_MAX.read_text().split()
        return None if quota == "max" else int(quota) / int(period)
    except (OSError, ValueError):
        return None


def container_cpu_percent() -> float | None:
    """CPU use as a percentage of the container's quota, measured between calls.

    Returns None when cgroup v2 is unavailable (e.g. local dev / macOS).
    """
    usage = _usage_usec()
    now = time.monotonic()
    prev_u, prev_t = _cpu_prev["usage_usec"], _cpu_prev["t"]
    _cpu_prev["usage_usec"], _cpu_prev["t"] = usage, now
    if usage is None or prev_u is None or prev_t is None or now <= prev_t:
        return None
    cores = _quota_cores() or 1.0
    avail = (now - prev_t) * cores
    return max(0.0, min(100.0, (usage - prev_u) / 1e6 / avail * 100.0)) if avail > 0 else None


def container_mem_percent() -> float | None:
    cur, mx = _read_int(_MEM_CUR), _read_int(_MEM_MAX)
    if cur is None or not mx:
        return None
    return round(min(100.0, cur / mx * 100.0), 1)
