# Restart persistence

Objective: a Render deploy (every push to main) must not wipe the dashboard's history or the `/unirse` audience.

Problem / why: `Monitor.proposals/decisions/incidents` and `AudienceState` live only in process memory; the hash-chained audit log in Postgres (`centinela-audit-db`) survives but is never read back into them. Also `domain._ids` restarts at 1, so new proposal ids collide with ids already in the audit log.

Scope: `centinela_svc/` (monitor, audit, executor, domain, audience, app) and tests. Victim untouched.

Constraints:
- Audience data goes to the audit DB in its own table, never to `centinela-db` (the victim holds that DB's owner credential) and never into the security audit chain.
- Do NOT restore: pending approvals (stale pid targets; show them as expired in history), CPU samples, `Baseline.known`, `SustainedCpu`, KeyWatch cursor, rate-limit timers.
- Two containers overlap during a Render deploy and both write (see `audit.py` `_pg_resync`).
- JSONL fallback (no `AUDIT_DATABASE_URL`) keeps working.

TDD: off (no configured mode); runner `PGSERVER_DATA=$(mktemp -d) python -m pytest -q tests centinela_svc` (Python 3.12 venv; pgserver has no 3.14 wheel).
Delivery: ask-on-risk; branch `feat/restart-persistence`, work-unit commits, merge to main is the user's call (main deploys).

## Tasks

- [ ] T1 Rehydrate Monitor history from the audit log at startup; seed proposal ids to max+1; unresolved `pending_approval` shown as expired, not re-queued; incidents rebuilt from kill_process + executed action_result. Route: delegated (writer trigger).
- [ ] T2 Record incident facts (process name, cmdline, attack_start, detection_s, containment_s, confirmed_s) in the audit data going forward so restored incidents are complete. Route: delegated with T1.
- [ ] T3 Persist `AudienceState` (participants, activity, board) in a separate `audience_event` table in the audit DB; rebuild on startup. Route: delegated.

## Acceptance

- After a restart the dashboard shows previous decisions, incidents and the attackers count; no stale approval can be approved; new proposal ids don't collide.
- Full test suite passes.

## Progress

- Exploration done (mapper): state inventory and recommendation recorded in conversation; branch created and published (the pull hook needs an upstream).
