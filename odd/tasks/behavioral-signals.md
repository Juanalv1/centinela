# Feature: behavioral-signals

## Objective
Give the AI behavioral telemetry so Centinela detects attacks by behavior, not by obvious strings. It must detect both cases below; the demo uses case A.

## Priority
- **A (demo, first): stolen valid credential, Snowflake 2024 pattern.** A valid API key used by someone else: new IP, unusual hours, endpoints the key never used, slow paginated bulk download. No errors, no failed logins, no rate-limit hit.
- **B (second): hidden miner, Tesla 2017-2018 pattern.** Process-level signals below.

## Baseline measurement (before this feature)
`docs/evals/process-detection-baseline.md`: with obvious tells (pool string, `/tmp`) the AI caught 9/9; without them it auto-killed 0/9 (only human-review recommends); 0 false kills in 27 legit trials. Repeat this eval after B to compare.

## Problem
Today the victim's `/metrics` exposes per process only `name`, `cmdline`, `username`, `cpu_percent`, `create_time`, `managed` (`victim/app.py:97-104`). Apart from CPU there is no behavior. Without the fake pool string in the demo job's cmdline, the AI cannot tell a disguised workload from a legitimate heavy job. Product value depends on fixing this: obvious signals are caught by any tool.

## Scope A: per-key access behavior
| Signal | Lets the AI reason |
|---|---|
| Access log per request: key id, client IP (proxy-appended only), endpoint, response bytes, time | Raw evidence |
| Per-key baseline (deterministic): usual IPs/networks, hours, endpoints, volume | "This key never did this before" |
| Current window vs baseline | New IP + off-hours + never-used export endpoints + steady paginated volume |

Lab data: seed a clearly-marked normal usage history for the demo key (office IP, business hours). The live "attacker" uses the same key from another network (e.g. a phone hotspot).

## Scope B: per-process signals
Per-process signals (psutil, Linux), added to `/metrics` and passed to the reasoner:

| Signal | Lets the AI reason |
|---|---|
| Network connections (remote ip:port, count, state) | Persistent outbound connection to an unknown host |
| Disk I/O (read/write bytes, delta per poll) | A "backup" that writes nothing is not a backup |
| Parent process and runtime | Spawned by the web service and running far longer than usual |
| Baseline (processes seen during a warm-up window) | This process never existed on this server |

## Tasks
Owner: Christian (@ChristianVeneko) for all tasks.

### A — stolen credential (demo, do first)
- [ ] A1 (`victim/`): access log per request (key id, proxy-appended client IP, endpoint, bytes, time) + seeded lab history for the demo key; tests.
- [ ] A2 (`centinela_svc/`): deterministic per-key baseline; reasoner receives "key vs its history" and proposes `revoke_key`; prompt reasons on behavior, never on single signals.
- [ ] A3: live test — demo key used from another network with slow paginated export vs normal use of a legit key. Expected `revoke_key` for the first, `none` for the second, 5 runs each. Record results here.

### B — hidden miner (process signals; T1–T3 below)
- [x] T1 (Christian, `victim/`): expose the signals above in `/metrics`; keep the payload compact; tests. Route: inline. Done: `victim/behavior.py` (parent, net peers ≤3, io bps delta; `null` when unreadable/unsupported), `tests/test_victim_behavior.py`.
- [x] T2 (Christian, `centinela_svc/reasoner.py`, `monitor.py`): include the signals and the baseline in the snapshot; update the prompt to reason on behavior; never on names alone. Route: inline. Done: `monitor.Baseline` (`BASELINE_SECONDS`, default 60; signature = name + first non-flag arg), behavior-first prompt, `tests/test_behavior_snapshot.py`.
- [ ] T3 (Christian): demo job variant without the pool string in its cmdline, plus a legitimate heavy job. Expected: AI proposes `kill_process` for the first and `none` for the second, across 5 runs each. Record results here. Route: inline. Code done: jobs `sync` (CPU + keep-alive to `SYNC_ENDPOINT`, no disk) and `backup` (CPU + real disk writes, no sockets), runner `behavior_trials.py`. **Pending: cloud run** (needs deploy to Render + `SYNC_ENDPOINT` set on the victim service).

## Acceptance
A3 passes in the cloud (5/5 detected, 0/5 false positives) before the pitch claims "detects by behavior". T3 passes before claiming the miner case.

## Constraints
- Keep all workloads harmless (arithmetic loops, ordinary file writes, connections only to hosts we control).
- `domain.py` unchanged.
- Starter plan memory (512 MB): keep metrics collection cheap.

## Log

- L1 (2026-10-24, user, verbatim): "revisa la issue que esta que me asignaron en github para que veas ahi para que le heches bola ahi"
- L2 (2026-10-24): T1+T2+T3 code on `feat/behavioral-signals`; 109 tests pass locally (pgserver). Local smoke run found the `sync` channel vanished when the server closes each response; fixed (reconnect on `will_close`) and pinned by a test that fails without the fix. macOS has no per-process `io_counters`, so `backup`'s disk signal is only visible on Linux: T3 must run in the cloud. Real-model runs not done locally (no API key access).
