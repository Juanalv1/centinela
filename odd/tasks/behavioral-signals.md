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
- [x] A1 (`victim/`): access log per request (key id, proxy-appended client IP, endpoint, bytes, time) + seeded lab history for the demo key; tests. Route: inline. Done (9bd6b02): `bytes`, `query`, `lab_seed` columns; `/api/customers?page=`; 21-day seeded history (ana: weekdays 08-18 Caracas, office ip, `/api/me`+`/api/invoices`; luis: hourly from `LAB_KNOWN_IPS`); `POST /lab/reset` (`LAB_TOKEN`); `tests/test_victim_access_profile.py`.
- [x] A2 (`centinela_svc/`): deterministic per-key baseline; reasoner receives "key vs its history" and proposes `revoke_key`; prompt reasons on behavior, never on single signals. Route: inline. Done (a7d5842): `keywatch.py` (flag only at ≥2 combined deviations; flagged windows never learned; off-hours = outside the key's weekday/weekend hour range), monitor polls `/access-log` + `/security-state`, `key_activity` in snapshot, prompt section; `tests/test_keywatch.py`, `tests/test_monitor_keys.py`.
- [x] A3: live test — demo key used from another network with slow paginated export vs normal use of a legit key. Expected `revoke_key` for the first, `none` for the second, 5 runs each. Record results here. Runner: `credential_trials.py --key-window 120`.
  **Cloud result (2026-10-24 20:09–20:26 Caracas): stolen key `revoke_key` 5/5; legit key false positives 0/5 → PASS.** Deployed `6ba2f71` for the 5 legit runs and attacks #1–#2; a teammate deploy (`c5eaf24`, TTS only) restarted both services between attacks #2 and #3, so #3–#5 ran on a freshly restarted Centinela (no legit run overlapped it). Detection 9.1–38.4 s (2 high, 3 medium confidence). Ana's window also held requests with her key from `38.121.211.28` (not the runner); runs #2 and #4 were flagged on 2 runner requests alone. Verbatim rationales:
  - "La clave 2 (ana-integration) muestra varias desviaciones independientes a la vez: red e IP nunca vistas, uso en sábado fuera de horario, un endpoint nuevo (/api/customers) y descarga paginada con un volumen unas 63 veces superior a su máximo histórico. Es el patrón de una clave robada que exfiltra datos. Los procesos no muestran abuso de CPU."
  - "La clave 2 (ana-integration) muestra varias desviaciones independientes: IP y red nunca vistas, sábado fuera de sus días habituales, fuera de horario y un endpoint nuevo (/api/customers). Es un patrón compatible con una clave robada, aunque el volumen absoluto es pequeño (2 peticiones, 3.4 KB), por eso la confianza es media."
  - "La clave 2 muestra varias desviaciones independientes a la vez: IP y red nunca vistas, uso en sábado fuera de su horario habitual, un endpoint nuevo (/api/customers) y un volumen 26,7 veces su máximo histórico. Es el patrón de una clave robada que exfiltra datos, así que propongo revocarla."

### B — hidden miner (process signals; T1–T3 below)
- [x] T1 (Christian, `victim/`): expose the signals above in `/metrics`; keep the payload compact; tests. Route: inline. Done: `victim/behavior.py` (parent, net peers ≤3, io bps delta; `null` when unreadable/unsupported), `tests/test_victim_behavior.py`.
- [x] T2 (Christian, `centinela_svc/reasoner.py`, `monitor.py`): include the signals and the baseline in the snapshot; update the prompt to reason on behavior; never on names alone. Route: inline. Done: `monitor.Baseline` (`BASELINE_SECONDS`, default 60; signature = name + first non-flag arg), behavior-first prompt, `tests/test_behavior_snapshot.py`.
- [x] T3 (Christian): demo job variant without the pool string in its cmdline, plus a legitimate heavy job. Expected: AI proposes `kill_process` for the first and `none` for the second, across 5 runs each. Record results here. Route: inline. Code done: jobs `sync` (CPU + keep-alive to `SYNC_ENDPOINT`, no disk) and `backup` (CPU + real disk writes, no sockets), runner `behavior_trials.py`. Cloud run 1 (17227ca, 2026-10-24): **sync detected 0/5, backup false positives 0/5 → FAIL.** Rationales: "CPU moderada (45.8% de 16 núcleos)", "lleva solo 2-33 s", "job de sincronización acotado (--max-seconds 600)". Fix (bd7a7a1, a7d5842): `quota_percent` (share of the 0.5-core container quota, the process was ~92%), `cpu_sustained_s`, 120 s observation window. Cloud run 2 (2026-10-24 ~20:26–20:39 Caracas, deployed `c5eaf24`, which includes `6ba2f71`; no deploy during the run): **sync detected 5/5 (27.9–29.8 s, medium confidence); backup false positives 0/5 → PASS.** Verbatim rationales:
  - "El proceso 37 es una carga nueva que consume ~91% del presupuesto de CPU del servidor de forma sostenida (21 s), sin actividad de disco que justifique un trabajo normal y con una conexión externa persistente. Esto constituye abuso de recursos que deja sin capacidad al servicio legítimo."
  - "El proceso 43 es una carga nueva que consume ~93% del presupuesto de CPU del servidor durante 22 s, sin actividad de disco y con una conexión externa persistente. Esto coincide con abuso de recursos, no con un trabajo normal."

## Acceptance
A3 passes in the cloud (5/5 detected, 0/5 false positives) before the pitch claims "detects by behavior". T3 passes before claiming the miner case.

## Constraints
- Keep all workloads harmless (arithmetic loops, ordinary file writes, connections only to hosts we control).
- `domain.py` unchanged.
- Starter plan memory (512 MB): keep metrics collection cheap.

## Log

- L1 (2026-10-24, user, verbatim): "revisa la issue que esta que me asignaron en github para que veas ahi para que le heches bola ahi"
- L2 (2026-10-24): T1+T2+T3 code on `feat/behavioral-signals`; 109 tests pass locally (pgserver). Local smoke run found the `sync` channel vanished when the server closes each response; fixed (reconnect on `will_close`) and pinned by a test that fails without the fix. macOS has no per-process `io_counters`, so `backup`'s disk signal is only visible on Linux: T3 must run in the cloud. Real-model runs not done locally (no API key access).
- L3 (2026-10-24, Juan on issue #1): priority changed to case A (stolen credential, Snowflake 2024) first; baseline eval: obvious tells 9/9, without tells 0/9 auto-kills, 0 false kills in 27.
- L4 (2026-10-24): first victim deploy failed (Dockerfile COPY list lacked `behavior.py`); fixed in 2e368c1 with a regression test. A redeploy during T3 restarted the process baseline while `sync` ran, so it was learned as normal; job-runner children are no longer learned (17227ca). The two `kill_process` on `db-sim` seen in the panel came from the "simulate compromised AI" button, rejected at `policy`.
- L5 (2026-10-24): the live lab DB has 3 team smoke-test requests with ana's key on Sat 14:21-14:22 Caracas; they teach the profile a Saturday 14h slot. Harmless tonight (attack at ~19-20h), but must be cleared before a weekend demo near 14h. Pending decision.
- L6 (2026-10-24): fixes before the valid runs: keys learn only activity older than 24 h, since a restart re-read aborted attack runs as ana's normal use (36b9888); the behavior-first prompt spared even the obvious miner holding 94% of the CPU budget, so a new workload holding most of the budget for 20 s is now abuse unless its output matches an ordinary job (36b9888); a process crossing 20 s of sustained load wakes the reasoner (6ba2f71), cutting the obvious-miner containment from 37.6 s. Valid cloud results: A3 PASS (5/5, 0/5), T3 PASS (5/5, 0/5).
- L7 (2026-10-24): key detection takes ~38 s when the first look (5–8 s, 1–2 requests) proposes "none": `KEY_REASON_S = 60` blocks re-evaluation, so the 30 s heartbeat decides. Done in fe25d15: a higher score, more pages or two more requests re-evaluate the key at once; an unchanged window still waits 60 s. Not re-measured in the cloud yet. The L5 Saturday-14h smoke-test entries are now excluded only until they are 24 h old (Sunday 14:21).
- L8 (2026-10-24): after pulling teammates' merges (restart-persistence, dashboard auth), 3 tests fail on main independently of this feature: `test_app_wiring::test_approval_unchanged_without_token`, `test_auth::test_demo_mode_dashboard_open_and_me`, `test_restart_persistence::test_stale_approval_is_not_found_through_the_api`.
