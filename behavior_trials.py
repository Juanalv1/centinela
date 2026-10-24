"""behavioral-signals T3: does Centinela tell a disguised workload from a legitimate heavy one?

Runs each job N times against live services and records what the AI proposed for its pid:
  sync    CPU + persistent outbound connection, no disk output, no telling string -> expect kill_process
  backup  CPU + real disk writes, no sockets                                       -> expect no kill_process

Usage:
  EXECUTOR_TOKEN=... python behavior_trials.py --victim https://<victim> --centinela https://<centinela>

The token is only used to stop a job the AI (correctly) left alone, since the
victim runs one job at a time. Stdlib only.
"""
import argparse
import json
import os
import time
import urllib.error
import urllib.request

EXPECT_KILL = {"sync": True, "backup": False}


def call(url: str, body: dict | None = None, token: str | None = None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Executor-Token"] = token
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def start_job(victim: str, job: str) -> int:
    deadline = time.time() + 120
    while True:
        status, body = call(f"{victim}/jobs", {"job": job})
        if status == 200:
            return body["pid"]
        if status != 409 or time.time() > deadline:
            raise SystemExit(f"cannot start {job}: {status} {body}")
        time.sleep(3)  # previous job still exiting


def proposals_for(state: dict, pid: int) -> list[dict]:
    return [p for p in state.get("proposals", [])
            if (p.get("target") or {}).get("type") == "process" and p["target"].get("value") == str(pid)]


def trial(args, job: str) -> dict:
    pid = start_job(args.victim, job)
    started = time.time()
    found: list[dict] = []
    while time.time() - started < args.window:
        time.sleep(2)
        found = proposals_for(call(f"{args.centinela}/api/state")[1], pid)
        if any(p["action"] == "kill_process" for p in found):
            break
    kill = next((p for p in found if p["action"] == "kill_process"), None)
    call(f"{args.victim}/kill", {"pid": pid}, args.token)  # no-op (404) if Centinela already killed it
    return {
        "job": job, "pid": pid, "kill_proposed": kill is not None,
        "pass": (kill is not None) == EXPECT_KILL[job],
        "detection_s": round(kill["created_at"] - started, 1) if kill else None,
        "confidence": kill["confidence"] if kill else None,
        "evidence": kill["evidence"] if kill else [],
        "rationale": kill["rationale"] if kill else "",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--victim", required=True)
    parser.add_argument("--centinela", required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--window", type=float, default=45.0,
                        help="seconds to wait for a proposal (covers new-pid evaluation and a heartbeat)")
    parser.add_argument("--token", default=os.environ.get("EXECUTOR_TOKEN"))
    args = parser.parse_args()
    if not args.token:
        raise SystemExit("set EXECUTOR_TOKEN (or --token) to stop jobs the AI leaves alone")
    args.victim, args.centinela = args.victim.rstrip("/"), args.centinela.rstrip("/")

    results = []
    for job in ("sync", "backup"):
        for n in range(1, args.runs + 1):
            r = trial(args, job)
            results.append(r)
            print(f"{job} #{n} pid={r['pid']} kill_proposed={r['kill_proposed']} "
                  f"pass={r['pass']} detection_s={r['detection_s']} confidence={r['confidence']}", flush=True)
    detected = sum(r["kill_proposed"] for r in results if r["job"] == "sync")
    false_pos = sum(r["kill_proposed"] for r in results if r["job"] == "backup")
    print(f"\nsync detected {detected}/{args.runs}; backup false positives {false_pos}/{args.runs}; "
          f"T3 {'PASS' if detected == args.runs and false_pos == 0 else 'FAIL'}")
    print(json.dumps(results, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
