"""Monitor loop: polls the victim, calls the reasoner, hands proposals to the executor."""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque

import os

import httpx

from domain import Decision, Proposal
from executor import Executor
from reasoner import ClaudeReasoner

log = logging.getLogger("centinela.monitor")
HEARTBEAT_S = 30.0
BASELINE_S = float(os.environ.get("BASELINE_SECONDS", "60"))


def process_signature(proc: dict) -> str:
    """What a workload is, independent of pid and arguments: name plus the first
    non-flag argument (the script or module for interpreters)."""
    first = next((a for a in (proc.get("cmdline") or [])[1:] if not a.startswith("-")), None)
    return f"{proc['name']}:{first}" if first else proc["name"]


class Baseline:
    """Workloads seen during a warm-up window; afterwards, anything else is new."""

    def __init__(self, window_s: float, started_at: float) -> None:
        self.window_s = window_s
        self.started_at = started_at
        self.known: set[str] = set()

    def annotate(self, metrics: dict, now: float) -> None:
        ready = now - self.started_at >= self.window_s
        for proc in metrics.get("processes", []):
            sig = process_signature(proc)
            if not ready:
                self.known.add(sig)
            proc["new_since_baseline"] = (sig not in self.known) if ready else None
        metrics["baseline"] = {"ready": ready, "window_s": round(self.window_s)}


class Monitor:
    def __init__(self, victim_url: str, poll_s: float, reasoner: ClaudeReasoner,
                 executor: Executor, http: httpx.AsyncClient) -> None:
        self.victim_url = victim_url.rstrip("/")
        self.poll_s = poll_s
        self.reasoner = reasoner
        self.executor = executor
        self.http = http
        self.samples: deque[dict] = deque(maxlen=120)
        self.latest: dict | None = None
        self.clock_offset = 0.0  # local_time - victim_time
        self.proposals: deque[dict] = deque(maxlen=50)
        self.decisions: deque[dict] = deque(maxlen=50)
        self.incidents: list[dict] = []
        self._by_id: dict[int, Proposal] = {}  # proposals awaiting approval are looked up here
        self.last_error: str | None = None
        self.reasoner_busy = False
        self._known_pids: set[int] | None = None
        self._pending_new: set[int] = set()
        self._last_reason_at = 0.0
        self.baseline = Baseline(BASELINE_S, time.time())
        self._lock = asyncio.Lock()  # serializes executor use (monitor + simulate)

    async def run(self) -> None:
        while True:
            try:
                await self.tick()
                self.last_error = None
            except Exception as exc:  # keep the loop alive
                self.last_error = f"{type(exc).__name__}: {exc}"
                log.warning("tick failed: %s", self.last_error)
            await asyncio.sleep(self.poll_s)

    async def tick(self) -> None:
        resp = await self.http.get(f"{self.victim_url}/metrics", timeout=10)
        resp.raise_for_status()
        metrics = resp.json()
        now = time.time()
        self.clock_offset = now - metrics.get("server_time", now)
        self.baseline.annotate(metrics, now)
        self.latest = metrics
        pids = {p["pid"] for p in metrics["processes"]}
        self.samples.append({"t": now, "cpu": metrics["cpu_percent"], "n": len(pids)})
        self._confirm_kills(pids, now)

        # New pids are evaluated on the NEXT sample, so their cpu_percent is meaningful.
        due_new = self._pending_new & pids
        self._pending_new = (pids - self._known_pids) if self._known_pids is not None else set()
        self._known_pids = pids
        heartbeat = now - self._last_reason_at >= HEARTBEAT_S
        if due_new and self.reasoner_busy:
            self._pending_new |= due_new  # retry on the next sample
        elif (due_new or heartbeat) and not self.reasoner_busy:
            self._last_reason_at = now
            asyncio.create_task(self._reason(metrics))

    async def _reason(self, metrics: dict) -> None:
        self.reasoner_busy = True
        try:
            proposal = await self.reasoner.propose(metrics)
        finally:
            self.reasoner_busy = False
        await self.submit(proposal)

    async def submit(self, proposal: Proposal) -> dict:
        async with self._lock:
            self.proposals.appendleft(proposal.to_dict())
            decision = await self.executor.handle(proposal, self.latest)
            if decision.status == "pending_approval":
                self._by_id[proposal.id] = proposal
            return self._record(proposal, decision)

    async def resolve_approval(self, proposal_id: int, approve: bool) -> dict | None:
        async with self._lock:
            decision = await self.executor.resolve(proposal_id, approve, self.latest)
            if decision is None:
                return None
            return self._record(self._by_id.pop(proposal_id, None), decision)

    def _record(self, proposal: Proposal | None, decision: Decision) -> dict:
        self.decisions.appendleft(decision.to_dict())
        if decision.status == "executed" and proposal is not None and proposal.action == "kill_process":
            self._open_incident(proposal, decision)
        return decision.to_dict()

    def _open_incident(self, proposal: Proposal, decision: Decision) -> None:
        pid = int(proposal.target.value)
        proc = next((p for p in (self.latest or {}).get("processes", []) if p["pid"] == pid), {})
        start = proc.get("create_time", proposal.created_at) + self.clock_offset
        self.incidents.insert(0, {
            "pid": pid,
            "name": proc.get("name"),
            "cmdline": " ".join(proc.get("cmdline") or []),
            "attack_start": start,
            "proposal_at": proposal.created_at,
            "killed_at": decision.at,
            "gone_confirmed_at": None,
            "detection_s": round(proposal.created_at - start, 2),
            "containment_s": round(decision.at - start, 2),
            "model_latency_s": proposal.latency_s,
        })

    def _confirm_kills(self, pids: set[int], now: float) -> None:
        for inc in self.incidents:
            if inc["gone_confirmed_at"] is None and inc["pid"] not in pids:
                inc["gone_confirmed_at"] = now
                inc["confirmed_s"] = round(now - inc["attack_start"], 2)

    def state(self) -> dict:
        return {
            "now": time.time(),
            "victim_url": self.victim_url,
            "last_error": self.last_error,
            "reasoner_busy": self.reasoner_busy,
            "samples": list(self.samples),
            "processes": sorted((self.latest or {}).get("processes", []),
                                key=lambda p: p.get("cpu_percent", 0), reverse=True),
            "host_cpu": (self.latest or {}).get("cpu_percent"),
            "proposals": list(self.proposals),
            "decisions": list(self.decisions),
            "approvals": self.executor.pending(),
            "incidents": self.incidents,
            "audit": self.executor.audit.entries[-40:][::-1],
        }
