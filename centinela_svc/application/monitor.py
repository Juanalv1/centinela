"""Monitor loop: polls the victim, calls the reasoner, hands proposals to the executor."""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque

import os

import httpx

from application.executor import Executor
from application.ports import ReasonerPort, VictimRowMapper
from domain.access import VICTIM_SOURCE, AccessEvent
from domain.history import replay
from domain.keywatch import KeyWatch
from domain.model import Decision, Proposal, Target, seed_ids

log = logging.getLogger("centinela.monitor")
HEARTBEAT_S = 30.0
BASELINE_S = float(os.environ.get("BASELINE_SECONDS", "60"))
KEY_WINDOW_S = float(os.environ.get("KEY_WINDOW_SECONDS", "600"))
HOT_TRIGGER_S = 20.0    # a process this long above half the CPU budget wakes the reasoner once
KEY_REASON_S = 60.0     # an unchanged flagged key wakes the reasoner again only after this
KEY_WORSE_REQUESTS = 2  # ...but sooner once its window grows by this many requests
KEY_STATE_S = 10.0      # how often key status/labels are refreshed from /security-state
LOG_PAGES_PER_TICK = 10


def process_signature(proc: dict) -> str:
    """What a workload is, independent of pid and arguments: name plus the first
    non-flag argument (the script or module for interpreters)."""
    first = next((a for a in (proc.get("cmdline") or [])[1:] if not a.startswith("-")), None)
    return f"{proc['name']}:{first}" if first else proc["name"]


class SustainedCpu:
    """Seconds each process has stayed above `threshold`% of the server's CPU budget
    (quota_percent, or per-core cpu_percent when the victim reports no quota)."""

    def __init__(self, threshold: float = 50.0) -> None:
        self.threshold = threshold
        self._since: dict[tuple[int, float], float] = {}  # (pid, create_time) -> first hot sample

    def annotate(self, metrics: dict, now: float) -> None:
        live = set()
        for proc in metrics.get("processes", []):
            ident = (proc["pid"], proc.get("create_time", 0.0))
            live.add(ident)
            share = proc.get("quota_percent")
            share = proc.get("cpu_percent", 0.0) if share is None else share
            if share >= self.threshold:
                self._since.setdefault(ident, now)
            else:
                self._since.pop(ident, None)
            proc["cpu_sustained_s"] = round(now - self._since[ident]) if ident in self._since else 0
        for gone in set(self._since) - live:
            del self._since[gone]


class Baseline:
    """Workloads seen during a warm-up window; afterwards, anything else is new.

    Job-runner children (`managed`) are never learned: the job runner is the
    exposed foothold, so one running across a redeploy must not become normal.
    """

    def __init__(self, window_s: float, started_at: float) -> None:
        self.window_s = window_s
        self.started_at = started_at
        self.known: set[str] = set()

    def annotate(self, metrics: dict, now: float) -> None:
        ready = now - self.started_at >= self.window_s
        for proc in metrics.get("processes", []):
            sig = process_signature(proc)
            if not ready and proc.get("managed") is not True:
                self.known.add(sig)
            proc["new_since_baseline"] = (sig not in self.known) if ready else None
        metrics["baseline"] = {"ready": ready, "window_s": round(self.window_s)}


class Monitor:
    def __init__(self, victim_url: str, poll_s: float, reasoner: ReasonerPort,
                 executor: Executor, http: httpx.AsyncClient,
                 victim_events: VictimRowMapper | None = None) -> None:
        self.victim_url = victim_url.rstrip("/")
        self.poll_s = poll_s
        self.reasoner = reasoner
        self.executor = executor
        self.http = http
        self.victim_events = victim_events  # without it the victim's access log is not read
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
        self.sustained = SustainedCpu()
        self._hot_reasoned: set[tuple[int, float]] = set()  # (pid, create_time) already re-evaluated
        self.keywatch = KeyWatch(KEY_WINDOW_S, float(os.environ.get("LAB_TZ_OFFSET_HOURS", "-4")))
        self.key_activity: list[dict] = []
        self._keys_enabled = victim_events is not None  # turned off when the victim has no case-2 database
        self._log_after = 0
        self._keys: dict[int, dict] = {}
        self._labels: dict[int, str] = {}  # labels carried by events from sources other than the victim
        self._keys_at = 0.0
        self._key_reasoned_at: dict[int, float] = {}
        self._key_reasoned_on: dict[int, tuple[int, int, int]] = {}  # (score, pages, requests) last shown
        self._key_last_proposal: dict[int, int] = {}  # key -> id of the last proposal that saw it flagged
        self._lock = asyncio.Lock()  # serializes executor use (monitor + simulate)

    def restore(self, entries: list[dict]) -> None:
        """Refill the dashboard history from audit entries after a restart.

        Not restored: pending approvals (their pids are gone: shown as expired and
        audited as such), CPU samples, the baseline and the key watch, except the
        windows the owner marked as normal (re-learned from their audit entries).
        """
        past = replay(entries)
        seed_ids(past["max_id"])
        for item in past["proposals"]:
            self.proposals.appendleft(item)
        for item in past["decisions"]:
            self.decisions.appendleft(item)
        for item in past["unresolved"]:
            target = Target(**item["target"]) if item.get("target") else None
            expired = Decision(item["proposal_id"], "expired", "reinicio del servicio", target=target)
            self.executor.audit.append("decision", expired.to_dict())
            self.decisions.appendleft(expired.to_dict())
        self.incidents = past["incidents"]
        for entry in entries:
            data = entry.get("data")
            if entry.get("kind") == "key_feedback" and isinstance(data, dict):
                # rows audited before events had a source all came from the victim
                rows = [{**e, "source": e.get("source") or VICTIM_SOURCE} for e in data.get("entries") or []]
                self.keywatch.learn(data["key_id"], rows)

    def feed(self, events: list[AccessEvent], now: float) -> int:
        """The one path from any source into the per-key baseline. Returns how many events were new."""
        for e in events:
            if e.key_label:
                self._labels[e.key_id] = e.key_label
        return self.keywatch.ingest([e.entry() for e in events], now)

    def _label(self, key: int) -> str | None:
        return self._keys.get(key, {}).get("label") or self._labels.get(key)

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
        self.sustained.annotate(metrics, now)
        self.latest = metrics
        pids = {p["pid"] for p in metrics["processes"]}
        self.samples.append({"t": now, "cpu": metrics["cpu_percent"], "n": len(pids)})
        self._confirm_kills(pids, now)

        # New pids are evaluated on the NEXT sample, so their cpu_percent is meaningful.
        due_new = self._pending_new & pids
        self._pending_new = (pids - self._known_pids) if self._known_pids is not None else set()
        self._known_pids = pids
        due_keys = await self._watch_keys(metrics, now)
        # Sustained load is only judgeable after a while: re-evaluate when it gets there.
        self._hot_reasoned &= {(p["pid"], p.get("create_time", 0.0)) for p in metrics["processes"]}
        due_hot = {(p["pid"], p.get("create_time", 0.0)) for p in metrics["processes"]
                   if p.get("cpu_sustained_s", 0) >= HOT_TRIGGER_S} - self._hot_reasoned
        heartbeat = now - self._last_reason_at >= HEARTBEAT_S
        if (due_new or due_keys or due_hot) and self.reasoner_busy:
            self._pending_new |= due_new  # retry on the next sample
            for key in due_keys:
                self._key_reasoned_at.pop(key, None)
                self._key_reasoned_on.pop(key, None)
        elif (due_new or due_keys or due_hot or heartbeat) and not self.reasoner_busy:
            self._last_reason_at = now
            self._hot_reasoned |= due_hot
            asyncio.create_task(self._reason(metrics))

    async def _watch_keys(self, metrics: dict, now: float) -> set[int]:
        """Feed new access-log lines to the per-key baseline; return keys that should wake the reasoner.

        Never breaks the process loop: a victim without the case-2 database is
        skipped from then on, and transient errors only log.
        """
        if not self._keys_enabled:
            return set()
        victim_now = metrics.get("server_time", now)
        try:
            for _ in range(LOG_PAGES_PER_TICK):
                resp = await self.http.get(f"{self.victim_url}/access-log",
                                           params={"after": self._log_after, "limit": 500}, timeout=10)
                if resp.status_code in (404, 503):
                    self._keys_enabled = False
                    return set()
                resp.raise_for_status()
                entries = resp.json()["entries"]
                if not entries:
                    break
                self._log_after = entries[-1]["id"]
                self.feed([ev for ev in map(self.victim_events, entries) if ev is not None], victim_now)
            if now - self._keys_at >= KEY_STATE_S:
                state = (await self.http.get(f"{self.victim_url}/security-state", timeout=10)).json()
                self._keys = {k["id"]: k for k in state.get("api_keys", [])}
                self._keys_at = now
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log.warning("key watch failed: %s", exc)
            return set()
        self.key_activity = self.evaluate_keys(victim_now)[:3]
        metrics["key_activity"] = self.key_activity
        due = set()
        for f in self.key_activity:
            key, seen = f["key_id"], (f["score"], f["signals"]["pages"], f["window"]["requests"])
            last = self._key_reasoned_on.get(key)
            worse = last is not None and (seen[0] > last[0] or seen[1] > last[1]
                                          or seen[2] >= last[2] + KEY_WORSE_REQUESTS)
            if worse or now - self._key_reasoned_at.get(key, float("-inf")) >= KEY_REASON_S:
                due.add(key)
                self._key_reasoned_at[key] = now
                self._key_reasoned_on[key] = seen
        return due

    def evaluate_keys(self, now: float) -> list[dict]:
        """Flagged keys with their label. Skips only keys the victim reports as not active:
        keys seen by other sources are not in /security-state and are still judged."""
        inactive = {k for k, meta in self._keys.items() if meta.get("status") != "active"}
        flags = self.keywatch.evaluate(now, set(self.keywatch.recent) - inactive)
        for flag in flags:
            meta = self._keys.get(flag["key_id"], {})
            flag.update({k: meta.get(k) for k in ("username", "role", "protected")})
            flag["label"] = self._label(flag["key_id"])
        return flags

    async def _reason(self, metrics: dict) -> None:
        self.reasoner_busy = True
        try:
            proposal = await self.reasoner.propose(metrics)
        finally:
            self.reasoner_busy = False
        for flag in metrics.get("key_activity") or []:
            self._key_last_proposal[flag["key_id"]] = proposal.id
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
        incident = {
            "proposal_id": proposal.id,
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
        }
        self.incidents.insert(0, incident)
        # Audited so a restart can rebuild the incident (gone_confirmed_at/confirmed_s come later).
        self._audit_incident({k: v for k, v in incident.items() if k != "gone_confirmed_at"})

    def _audit_incident(self, facts: dict) -> None:
        try:
            self.executor.audit.append("incident", facts)
        except Exception as exc:  # the incident is already shown; a lost audit row must not break the loop
            log.warning("incident audit failed: %s", exc)

    def _confirm_kills(self, pids: set[int], now: float) -> None:
        for inc in self.incidents:
            if inc.get("restored"):
                continue  # the pid may belong to another process by now
            if inc["gone_confirmed_at"] is None and inc["pid"] not in pids:
                inc["gone_confirmed_at"] = now
                inc["confirmed_s"] = round(now - inc["attack_start"], 2)
                self._audit_incident({"proposal_id": inc.get("proposal_id"), "pid": inc["pid"],
                                      "gone_confirmed_at": now, "confirmed_s": inc["confirmed_s"]})

    def credentials(self) -> list[dict]:
        """Per-key view for the client dashboard: learned profile, current window, state
        and the latest AI analysis. Key id and label only: never values or user names."""
        rows = {r["key_id"]: r for r in self.keywatch.overview(time.time() - self.clock_offset)}
        out = []
        for key in sorted(set(rows) | set(self._keys)):
            row = rows.get(key) or {"key_id": key, "profile": None, "window": None, "signals": None,
                                    "score": 0, "flagged": False}
            meta = self._keys.get(key, {})
            state = ("revoked" if meta.get("status") == "revoked"
                     else "suspicious" if row["flagged"] else "active")
            out.append({**row, "label": self._label(key), "protected": meta.get("protected"),
                        "state": state, "analysis": self._key_analysis(key)})
        return out

    def mark_normal(self, key: int, by: str) -> dict | None:
        """Owner feedback: the key's flagged window was normal use, so learn it.

        Audited first (fails closed: nothing is learned if the write does not land).
        Never un-revokes: the key's status belongs to the executor and to humans.
        Returns None when the key has no flagged window right now.
        """
        victim_now = time.time() - self.clock_offset
        row = next((r for r in self.keywatch.overview(victim_now) if r["key_id"] == key), None)
        if row is None or not row["flagged"]:
            return None
        window = self.keywatch.recent.get(key, [])
        self.executor.audit.append("key_feedback", {
            "key_id": key, "label": self._label(key), "by": by,
            "score": row["score"], "signals": row["signals"],
            "entries": [{k: e.get(k) for k in ("source", "id", "ts", "ip", "path", "bytes")} for e in window],
        })
        learned = self.keywatch.learn_window(key, victim_now)
        self.key_activity = [f for f in self.key_activity if f["key_id"] != key]
        return {"key_id": key, "learned": len(learned)}

    def _key_analysis(self, key: int) -> dict | None:
        """Newest proposal that targeted this key or was made while it was flagged."""
        seen = self._key_last_proposal.get(key)
        for p in self.proposals:  # newest first
            target = p.get("target") or {}
            if p["id"] == seen or (target.get("type") == "key" and target.get("value") == str(key)):
                decision = next((d for d in self.decisions if d["proposal_id"] == p["id"]), None)
                return {"proposal_id": p["id"], "at": p.get("created_at"), "action": p.get("action"),
                        "rationale": p.get("rationale"), "confidence": p.get("confidence"),
                        "decision": decision and decision["status"]}
        return None

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
            "key_activity": self.key_activity,
            "audit": self.executor.audit.entries[-40:][::-1],
        }
