"""behavioral-signals A3: does Centinela catch a valid key used by someone else (Snowflake 2024 pattern)?

  attack  ana's key (history: weekdays, office hours, office ip, /api/me + /api/invoices)
          used from this machine: slow paginated export of /api/customers   -> expect revoke_key
  legit   luis's reports key (history: every hour from LAB_KNOWN_IPS, invoices + a few
          customer pages) used the same way it always is                   -> expect no revoke_key

Run from an ip listed in the victim's LAB_KNOWN_IPS (so luis's use is normal) and outside
ana's usual office ip. Between attack runs the script waits for the key window to empty
so each run is judged on its own requests.

Usage:
  LAB_TOKEN=... ANA_KEY=... LUIS_KEY=... python credential_trials.py \\
      --victim https://<victim> --centinela https://<centinela> --key-window 120
Stdlib only.
"""
import argparse
import json
import os
import time
import urllib.error
import urllib.request


def call(url: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    h = {"Content-Type": "application/json", "User-Agent": "credential-trials/1.0", **(headers or {})}
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers=h, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def key_id(args, key: str) -> int:
    status, me = call(f"{args.victim}/api/me", headers={"X-API-Key": key})
    if status != 200:
        raise SystemExit(f"key does not work ({status} {me}); reset the lab first")
    keys = call(f"{args.victim}/security-state")[1]["api_keys"]
    return next(k["id"] for k in keys if k["username"] == me["username"] and not k["protected"])


def reset(args) -> None:
    status, body = call(f"{args.victim}/lab/reset", {}, {"X-Lab-Token": args.lab_token})
    if status != 200:
        raise SystemExit(f"lab reset failed: {status} {body}")


def proposals_for(args, kid: int, since: float) -> list[dict]:
    state = call(f"{args.centinela}/api/state")[1]
    offset = state.get("now", time.time()) - time.time()  # Centinela clock vs ours
    return [p for p in state.get("proposals", [])
            if p["created_at"] >= since + offset and (p.get("target") or {}).get("type") == "key"
            and p["target"].get("value") == str(kid)]


def run(args, kind: str, key: str, kid: int) -> dict:
    reset(args)
    started = time.time()
    revoke = None
    h = {"X-API-Key": key}
    if kind == "attack":
        requests = [("/api/me", None)] + [("/api/customers", f"page={p}") for p in range(1, args.pages + 1)]
    else:
        requests = [("/api/invoices", None), ("/api/customers", "page=1"), ("/api/customers", "page=2")]
    for path, query in requests:
        status, _ = call(f"{args.victim}{path}" + (f"?{query}" if query else ""), headers=h)
        if status != 200:
            break  # revoked (401) or blocked (403): containment already happened
        time.sleep(args.delay)
        revoke = next((p for p in proposals_for(args, kid, started) if p["action"] == "revoke_key"), None)
        if revoke:
            break
    deadline = time.time() + args.settle
    while not revoke and time.time() < deadline:
        time.sleep(3)
        revoke = next((p for p in proposals_for(args, kid, started) if p["action"] == "revoke_key"), None)
    reset(args)
    return {"kind": kind, "key_id": kid, "revoke_proposed": revoke is not None,
            "pass": (revoke is not None) == (kind == "attack"),
            "detection_s": round(revoke["created_at"] - started, 1) if revoke else None,
            "confidence": revoke["confidence"] if revoke else None,
            "evidence": revoke["evidence"] if revoke else [], "rationale": revoke["rationale"] if revoke else ""}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--victim", required=True)
    parser.add_argument("--centinela", required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--pages", type=int, default=20, help="customer pages the attacker downloads")
    parser.add_argument("--delay", type=float, default=4.0, help="seconds between requests (a slow export)")
    parser.add_argument("--settle", type=float, default=45.0, help="seconds to keep watching after the requests")
    parser.add_argument("--key-window", type=float, default=600.0,
                        help="Centinela's KEY_WINDOW_SECONDS; attack runs are spaced by it")
    args = parser.parse_args()
    args.victim, args.centinela = args.victim.rstrip("/"), args.centinela.rstrip("/")
    args.lab_token, ana, luis = os.environ.get("LAB_TOKEN"), os.environ.get("ANA_KEY"), os.environ.get("LUIS_KEY")
    if not (args.lab_token and ana and luis):
        raise SystemExit("set LAB_TOKEN, ANA_KEY and LUIS_KEY")

    reset(args)
    ana_id, luis_id = key_id(args, ana), key_id(args, luis)
    results = []
    for n in range(1, args.runs + 1):
        r = run(args, "legit", luis, luis_id)
        results.append(r)
        print(f"legit #{n} revoke_proposed={r['revoke_proposed']} pass={r['pass']}", flush=True)
    for n in range(1, args.runs + 1):
        r = run(args, "attack", ana, ana_id)
        results.append(r)
        print(f"attack #{n} revoke_proposed={r['revoke_proposed']} pass={r['pass']} "
              f"detection_s={r['detection_s']} confidence={r['confidence']}", flush=True)
        if n < args.runs:
            time.sleep(args.key_window + 10)  # let this run's requests leave the window
    caught = sum(r["revoke_proposed"] for r in results if r["kind"] == "attack")
    false_pos = sum(r["revoke_proposed"] for r in results if r["kind"] == "legit")
    print(f"\nattack detected {caught}/{args.runs}; legit false positives {false_pos}/{args.runs}; "
          f"A3 {'PASS' if caught == args.runs and false_pos == 0 else 'FAIL'}")
    print(json.dumps(results, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
