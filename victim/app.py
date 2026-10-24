"""Victim "company server" API.

Endpoints:
  GET  /health
  GET  /metrics  host CPU + process list (cpu_percent measured between calls)
  POST /jobs     exposed job runner (allowlisted scripts only) - the foothold
  POST /kill     SIGKILL a pid; requires X-Executor-Token
Case 2 (SME API on Postgres, enabled by DATABASE_URL): see pyme.py.
"""
import hmac
import os
import signal
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import psutil
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import pyme

JOBS_DIR = Path(__file__).resolve().parent / "jobs"
# Allowlist: job name -> extra argv. The fake pool string is an unused argv
# string that gives the AI a realistic signal; the job does no networking.
JOB_ARGS = {
    "report": ["--pool", "stratum+tcp://pool.example.invalid:3333", "--threads", "4"],
}
JOB_MAX_SECONDS = 600



@asynccontextmanager
async def lifespan(_app: FastAPI):
    dsn = os.environ.get("DATABASE_URL")
    if dsn:
        pyme.init(dsn)
    try:
        yield
    finally:
        pyme.close()


app = FastAPI(title="victim", lifespan=lifespan)
app.middleware("http")(pyme.middleware)
app.include_router(pyme.router)

_lock = threading.Lock()
_job: subprocess.Popen | None = None
_proc_cache: dict[int, psutil.Process] = {}

psutil.cpu_percent(interval=None)  # prime host CPU counter

# --- container CPU (cgroup v2) --------------------------------------------
# psutil.cpu_percent() reports the whole physical host (16 shared cores on
# Render), so this container's own load is lost in the neighbours' noise. We
# instead report CPU as a percentage of the container's OWN quota, so a miner
# pegging its slice reads ~100% and its death reads ~0% — a signal both the
# panel and the detector can trust.
_CPU_STAT = Path("/sys/fs/cgroup/cpu.stat")  # cgroup v2
_CPU_MAX = Path("/sys/fs/cgroup/cpu.max")
_cpu_prev: dict[str, float | None] = {"usage_usec": None, "t": None}


def _cgroup_quota_cores() -> float | None:
    """Cores the container may use, or None when uncapped/unavailable."""
    try:
        quota, period = _CPU_MAX.read_text().split()
        if quota == "max":
            return None
        return int(quota) / int(period)
    except (OSError, ValueError):
        return None


def _cgroup_usage_usec() -> int | None:
    try:
        for line in _CPU_STAT.read_text().splitlines():
            if line.startswith("usage_usec"):
                return int(line.split()[1])
    except (OSError, ValueError):
        return None
    return None


def _container_cpu_percent() -> float | None:
    """CPU use as a percentage of the container's quota, measured between calls.

    Returns None when cgroup v2 is unavailable (e.g. local dev / macOS), so the
    caller can fall back to another signal.
    """
    usage = _cgroup_usage_usec()
    now = time.monotonic()
    prev_u, prev_t = _cpu_prev["usage_usec"], _cpu_prev["t"]
    _cpu_prev["usage_usec"], _cpu_prev["t"] = usage, now
    if usage is None or prev_u is None or prev_t is None or now <= prev_t:
        return None  # unavailable, or first call priming the counter
    cores = _cgroup_quota_cores() or psutil.cpu_count() or 1
    used_s = (usage - prev_u) / 1e6
    avail_s = (now - prev_t) * cores
    if avail_s <= 0:
        return None
    return max(0.0, min(100.0, used_s / avail_s * 100.0))


_container_cpu_percent()  # prime the cgroup counter


def _reap_job() -> None:
    """Collect the job's exit status so it never lingers as a zombie."""
    global _job
    if _job is not None and _job.poll() is not None:
        _job = None


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.get("/metrics")
def metrics() -> dict:
    with _lock:
        _reap_job()
        job_pid = _job.pid if _job is not None else None
        seen: set[int] = set()
        processes = []
        for proc in psutil.process_iter():
            pid = proc.pid
            seen.add(pid)
            cached = _proc_cache.get(pid)
            if cached is None or not _same_process(cached, proc):
                cached = proc
                _proc_cache[pid] = proc
                try:
                    proc.cpu_percent(interval=None)  # prime; first reading is 0.0
                except psutil.Error:
                    continue
            try:
                with cached.oneshot():
                    if cached.status() == psutil.STATUS_ZOMBIE:
                        continue
                    processes.append({
                        "pid": pid,
                        "name": cached.name(),
                        "cmdline": cached.cmdline(),
                        "username": cached.username(),
                        "cpu_percent": cached.cpu_percent(interval=None),
                        "create_time": cached.create_time(),
                        # Allowlist signal: only job-runner children may be killed.
                        "managed": pid == job_pid,
                    })
            except psutil.Error:
                continue
        for gone in set(_proc_cache) - seen:
            _proc_cache.pop(gone, None)
    host_cpu = psutil.cpu_percent(interval=None)
    # Container CPU when cgroup is available; otherwise fall back to the sum of
    # this container's visible processes (local dev), then to the host.
    cpu = _container_cpu_percent()
    if cpu is None:
        cpu = min(100.0, sum(p["cpu_percent"] for p in processes)) or host_cpu
    return {
        "server_time": time.time(),
        "cpu_percent": round(cpu, 1),           # the victim's OWN load (0-100)
        "host_cpu_percent": host_cpu,           # whole shared host, for reference
        "cpu_count": psutil.cpu_count(),
        "processes": processes,
    }


def _same_process(a: psutil.Process, b: psutil.Process) -> bool:
    try:
        return a.create_time() == b.create_time()
    except psutil.Error:
        return False


class JobRequest(BaseModel):
    job: str


@app.post("/jobs")
def run_job(req: JobRequest):
    global _job
    extra = JOB_ARGS.get(req.job)
    if extra is None:
        return JSONResponse({"error": "unknown job", "allowed": sorted(JOB_ARGS)}, status_code=400)
    script = JOBS_DIR / f"{req.job}.py"
    with _lock:
        _reap_job()
        if _job is not None:
            return JSONResponse({"error": "a job is already running", "pid": _job.pid}, status_code=409)
        _job = subprocess.Popen(
            [sys.executable, str(script), *extra, "--max-seconds", str(JOB_MAX_SECONDS)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        pid = _job.pid
    return {"started": True, "job": req.job, "pid": pid, "max_seconds": JOB_MAX_SECONDS}


class KillRequest(BaseModel):
    pid: int


@app.post("/kill")
def kill(req: KillRequest, x_executor_token: str | None = Header(default=None)):
    expected = os.environ.get("EXECUTOR_TOKEN", "")
    if not expected:
        return JSONResponse({"error": "executor token not configured"}, status_code=503)
    if not x_executor_token or not hmac.compare_digest(x_executor_token.encode(), expected.encode()):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        os.kill(req.pid, signal.SIGKILL)
    except ProcessLookupError:
        return JSONResponse({"error": "no such pid"}, status_code=404)
    except PermissionError:
        return JSONResponse({"error": "kernel denied: EPERM"}, status_code=403)
    with _lock:
        if _job is not None and _job.pid == req.pid:
            _job.wait(timeout=5)
            _reap_job()
    return {"killed": True, "pid": req.pid}
