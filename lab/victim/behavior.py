"""Per-process behavioral signals for /metrics: parent, network peers and disk I/O rate.

Kept cheap for the 512 MB plan: one psutil call per signal per process, at most
three remote peers per process, and one cached I/O sample per live pid.
"""
from __future__ import annotations

import psutil

MAX_REMOTES = 3
NO_RATE = {"read_bps": None, "write_bps": None}


def summarize_connections(conns) -> dict:
    """Count remote peers; list up to MAX_REMOTES distinct ones as 'ip:port STATUS'."""
    remotes: list[str] = []
    count = listening = 0
    for c in conns:
        if not c.raddr:
            listening += c.status == psutil.CONN_LISTEN
            continue
        count += 1
        peer = f"{c.raddr.ip}:{c.raddr.port} {c.status}"
        if len(remotes) < MAX_REMOTES and peer not in remotes:
            remotes.append(peer)
    return {"count": count, "listening": listening, "remotes": remotes}


class IoTracker:
    """Turns cumulative io_counters into bytes/second between two polls."""

    def __init__(self) -> None:
        self._prev: dict[int, tuple[float, float, int, int]] = {}  # pid -> (create_time, t, read, write)

    def rate(self, pid: int, create_time: float, counters, now: float) -> dict:
        if counters is None:
            self._prev.pop(pid, None)
            return dict(NO_RATE)
        prev = self._prev.get(pid)
        self._prev[pid] = (create_time, now, counters.read_bytes, counters.write_bytes)
        if prev is None or prev[0] != create_time or now <= prev[1]:
            return dict(NO_RATE)
        dt = now - prev[1]
        return {"read_bps": max(0, round((counters.read_bytes - prev[2]) / dt)),
                "write_bps": max(0, round((counters.write_bytes - prev[3]) / dt))}

    def forget(self, live_pids: set[int]) -> None:
        for pid in set(self._prev) - live_pids:
            del self._prev[pid]


def sample(proc: psutil.Process, io: IoTracker, now: float) -> dict:
    """Behavior of one process. Call inside proc.oneshot(); unreadable signals become None."""
    ppid = proc.ppid()
    try:
        parent = psutil.Process(ppid).name() if ppid else None
    except psutil.Error:
        parent = None
    try:
        net = summarize_connections(proc.net_connections(kind="inet"))
    except psutil.Error:
        net = None  # another user's process: the kernel hides its sockets
    try:
        counters = proc.io_counters()
    except (psutil.Error, AttributeError):  # AttributeError: platform without per-process I/O (macOS)
        counters = None
    return {"ppid": ppid, "parent": parent, "net": net,
            "io": io.rate(proc.pid, proc.create_time(), counters, now)}
