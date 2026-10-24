"""behavioral-signals A2: the monitor reads the victim's access log and wakes the reasoner on a flagged key."""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx

from conftest import SVC, load_module

monitor_mod = load_module("centinela_monitor_keys", SVC / "monitor.py")
domain = load_module("domain", SVC / "domain.py")
reasoner_mod = load_module("centinela_reasoner_keys", SVC / "reasoner.py")

NOW = datetime(2026, 10, 25, 15, 0, tzinfo=timezone(timedelta(hours=-4))).timestamp()  # Sunday


def _history():
    out, n = [], 0
    for day in range(1, 22):
        for hour in range(9, 17):
            ts = NOW - day * 86400 + (hour - 15) * 3600
            n += 1
            out.append({"id": n, "ts": ts, "ip": "203.0.113.1", "path": "/api/invoices", "query": None,
                        "status": 200, "bytes": 190, "api_key_id": 2, "username": "ana", "lab_seed": True})
    return out


ATTACK = [{"id": 100_000 + p, "ts": NOW - 200 + p * 5, "ip": "198.51.100.23", "path": "/api/customers",
           "query": f"page={p}", "status": 200, "bytes": 4000, "api_key_id": 2, "username": "ana",
           "lab_seed": False} for p in range(1, 21)]

KEYS = {"api_keys": [{"id": 1, "username": "admin", "role": "admin", "label": "admin-ops", "status": "active",
                      "protected": True},
                     {"id": 2, "username": "ana", "role": "staff", "label": "ana-integration",
                      "status": "active", "protected": False}],
        "ip_blocklist": [], "users": [], "sessions_by_user": {}}


class Victim:
    def __init__(self, log, access_status=200):
        self.log, self.access_status = log, access_status
        self.calls: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request.url.path)
        if request.url.path == "/metrics":
            return httpx.Response(200, json={"server_time": NOW, "cpu_percent": 3.0, "cpu_count": 2,
                                             "processes": []})
        if request.url.path == "/access-log":
            if self.access_status != 200:
                return httpx.Response(self.access_status, json={"error": "case 2 database not configured"})
            after, limit = int(request.url.params["after"]), int(request.url.params["limit"])
            return httpx.Response(200, json={"entries": [e for e in self.log if e["id"] > after][:limit]})
        if request.url.path == "/security-state":
            return httpx.Response(200, json=KEYS)
        return httpx.Response(404)


class FakeReasoner:
    def __init__(self):
        self.seen: list[dict] = []

    async def propose(self, metrics):
        self.seen.append(metrics)
        return domain.Proposal(action="none", target=None, rationale="", evidence=[], confidence="high",
                               source="claude")


class FakeExecutor:
    class audit:  # state() shows the audit tail
        entries: list = []

    async def handle(self, proposal, snapshot):
        return domain.Decision(proposal.id, "noop", "test")

    def pending(self):
        return []


async def _run(victim, ticks=1):
    reasoner = FakeReasoner()
    async with httpx.AsyncClient(transport=httpx.MockTransport(victim)) as http:
        mon = monitor_mod.Monitor("http://victim", 2, reasoner, FakeExecutor(), http)
        mon._last_reason_at = float("inf")  # silence the heartbeat: only key flags may wake the reasoner
        for _ in range(ticks):
            await mon.tick()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
        return mon, reasoner


def test_flagged_key_reaches_the_reasoner_with_its_label():
    mon, reasoner = asyncio.run(_run(Victim(_history() + ATTACK)))
    [flag] = mon.state()["key_activity"]
    assert flag["key_id"] == 2 and flag["label"] == "ana-integration" and flag["protected"] is False
    assert reasoner.seen and reasoner.seen[0]["key_activity"][0]["key_id"] == 2
    snap = reasoner_mod.compact_snapshot(reasoner.seen[0])
    assert snap["key_activity"][0]["signals"]["new_endpoints"] == ["/api/customers"]


def test_a_flagged_key_wakes_the_reasoner_once_not_every_tick():
    _, reasoner = asyncio.run(_run(Victim(_history() + ATTACK), ticks=3))
    assert len(reasoner.seen) == 1


def test_quiet_keys_do_not_wake_the_reasoner():
    mon, reasoner = asyncio.run(_run(Victim(_history())))
    assert mon.state()["key_activity"] == [] and reasoner.seen == []


def test_victim_without_case2_database_is_polled_once_then_skipped():
    victim = Victim([], access_status=503)
    mon, reasoner = asyncio.run(_run(victim, ticks=3))
    assert victim.calls.count("/access-log") == 1
    assert mon.state()["key_activity"] == [] and mon.last_error is None


def test_snapshot_without_key_activity_has_an_empty_list():
    assert reasoner_mod.compact_snapshot({"processes": []})["key_activity"] == []
