# Feature: feasibility-miner

## Objective
Prove one end-to-end case in the cloud: a CPU-burning job on a "company server" is detected by Claude, proposed as `matar_proceso`, validated by a deterministic executor and killed. Public panel shows before/after.

## Constraints
- Everything deployed publicly on Render (paid plan via hackathon credits). Nothing runs locally as part of the system.
- AI only proposes structured JSON; it holds no credentials. Executor is deterministic with a closed menu: `matar_proceso` only.
- Attacker is a harmless CPU load generator. Secrets only from env vars.

## Tasks
- [x] T1 victim service (FastAPI + psutil; /health, /metrics, /jobs, /kill with executor token; API runs non-root, protected process runs as root) — route: delegated (2+ non-trivial files)
- [x] T2 centinela service (poller, Claude reasoner, executor, JSONL audit, panel) — route: delegated
- [x] T3 attack.py + render.yaml + local docker e2e check — route: delegated
- [x] T4 deploy both services to Render via API — route: inline
- [x] T5 cloud e2e run with measured times; VIABILIDAD.md — route: inline

## Acceptance
Cloud run shows CPU rising, AI proposing `matar_proceso`, executor validating and killing, CPU dropping; attack-to-containment time recorded.

## Progress
- Branch `feat/feasibility-miner` created.
- T1-T3 written by delegated writer (not committed). Local docker e2e observed: Claude (claude-sonnet-5-5) proposed `matar_proceso` on the report job, executor validated and killed it (2 runs: detection 7.12 s / 9.31 s, containment 7.13 s / 9.32 s, model latency 3.1 s / 4.8 s). `/api/simulate-compromised` rejected ("target 'db-sim' is a protected process"); direct `/kill` on db-sim with valid token returned 403 EPERM; wrong token 401; unknown pid 404.

## Next step
T4: deploy both services to Render, set `VICTIM_URL` on centinela to the victim's public URL and a shared random `EXECUTOR_TOKEN`.

- T4: deployed via Render API (centinela-victim, centinela; starter, oregon).
- T5: cloud e2e OK, containment 6.22 s / 5.49 s; forged proposal rejected. See VIABILIDAD.md.
- Next: switch protected blacklist to killable allowlist; persist audit; await user confirmation before case 2.
