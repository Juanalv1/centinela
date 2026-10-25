"""behavioral-signals T2: baseline annotation in the monitor and behavior in the reasoner snapshot."""
from conftest import SVC, load_module

monitor_mod = load_module("centinela_monitor_behavior", SVC / "application" / "monitor.py")
reasoner = load_module("centinela_reasoner_behavior", SVC / "adapters" / "reasoner.py")


def _p(pid, name, cmdline, **extra):
    return {"pid": pid, "name": name, "cmdline": cmdline, "username": "app", "cpu_percent": 1.0,
            "create_time": 0.0, "managed": False, **extra}


def test_signature_ignores_interpreter_flags_and_arguments():
    sig = monitor_mod.process_signature
    assert sig(_p(1, "python", ["/usr/bin/python", "-m", "uvicorn", "app:app"])) == "python:uvicorn"
    assert sig(_p(2, "python", ["python", "/app/jobs/sync.py", "--interval", "15"])) == "python:/app/jobs/sync.py"
    assert sig(_p(3, "db-sim", [])) == "db-sim"


def test_baseline_learns_during_warmup_then_flags_only_new_workloads():
    baseline = monitor_mod.Baseline(window_s=60, started_at=1000.0)
    web = _p(10, "python", ["python", "-m", "uvicorn", "app:app"])
    warm = {"processes": [dict(web)]}
    baseline.annotate(warm, now=1010.0)
    assert warm["baseline"] == {"ready": False, "window_s": 60}
    assert warm["processes"][0]["new_since_baseline"] is None

    later = {"processes": [dict(web, pid=11), _p(20, "python", ["python", "/app/jobs/sync.py"])]}
    baseline.annotate(later, now=1070.0)
    assert later["baseline"]["ready"] is True
    flags = {p["pid"]: p["new_since_baseline"] for p in later["processes"]}
    assert flags == {11: False, 20: True}  # restarts of known workloads are not new


def test_snapshot_passes_behavior_and_keeps_existing_fields():
    metrics = {
        "server_time": 100.0, "cpu_percent": 55.0, "cpu_count": 2,
        "baseline": {"ready": True, "window_s": 60},
        "processes": [_p(20, "python", ["python", "/app/jobs/sync.py"], ppid=7, parent="python",
                         net={"count": 1, "listening": 0, "remotes": ["203.0.113.9:443 ESTABLISHED"]},
                         io={"read_bps": 0, "write_bps": 0}, new_since_baseline=True)],
    }
    snap = reasoner.compact_snapshot(metrics)
    assert snap["baseline"] == {"ready": True, "window_s": 60}
    proc = snap["processes"][0]
    assert proc["parent"] == "python (7)"
    assert proc["net"]["remotes"] == ["203.0.113.9:443 ESTABLISHED"]
    assert proc["io"] == {"read_bps": 0, "write_bps": 0}
    assert proc["new_since_baseline"] is True
    assert {"pid", "name", "user", "cpu_percent", "age_s", "cmdline"} <= proc.keys()


def test_snapshot_tolerates_victims_without_behavior_fields():
    snap = reasoner.compact_snapshot({"processes": [_p(5, "sh", ["sh"])]})
    proc = snap["processes"][0]
    assert proc["parent"] is None and proc["net"] is None and proc["io"] is None
    assert proc["new_since_baseline"] is None


def test_job_runner_children_never_become_baseline():
    """A workload started through the exposed job runner while the baseline is
    learning (e.g. right after a redeploy) must not be learned as normal."""
    baseline = monitor_mod.Baseline(window_s=60, started_at=1000.0)
    job = _p(30, "python", ["python", "/app/jobs/sync.py"], managed=True)
    baseline.annotate({"processes": [dict(job)]}, now=1010.0)
    later = {"processes": [dict(job)]}
    baseline.annotate(later, now=1070.0)
    assert later["processes"][0]["new_since_baseline"] is True


def test_sustained_cpu_counts_seconds_above_half_the_quota_and_resets():
    hot = monitor_mod.SustainedCpu(threshold=50.0)
    proc = lambda q: {"pid": 9, "create_time": 1.0, "quota_percent": q, "cpu_percent": 0.0}
    for t, q in ((100, 90), (110, 95), (130, 92)):
        m = {"processes": [proc(q)]}
        hot.annotate(m, now=t)
    assert m["processes"][0]["cpu_sustained_s"] == 30
    m = {"processes": [proc(10)]}
    hot.annotate(m, now=140)
    assert m["processes"][0]["cpu_sustained_s"] == 0


def test_sustained_cpu_falls_back_to_per_core_percent_without_quota():
    hot = monitor_mod.SustainedCpu(threshold=50.0)
    for t in (0, 20):
        m = {"processes": [{"pid": 3, "create_time": 1.0, "quota_percent": None, "cpu_percent": 99.0}]}
        hot.annotate(m, now=t)
    assert m["processes"][0]["cpu_sustained_s"] == 20


def test_snapshot_carries_quota_share_and_sustained_seconds():
    metrics = {"cpu_quota_cores": 0.5,
               "processes": [_p(20, "python", ["python"], quota_percent=92.0, cpu_sustained_s=75)]}
    snap = reasoner.compact_snapshot(metrics)
    assert snap["cpu_quota_cores"] == 0.5
    assert snap["processes"][0]["quota_percent"] == 92.0
    assert snap["processes"][0]["cpu_sustained_s"] == 75
