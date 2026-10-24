# Feature: domain-contract

## Objective
Replace the Spanish case-1 domain contract with the agreed English contract (`Lane`, `ActionSpec`, `MENU`, `Target`, `Proposal`, `Decision` with `layer`) and migrate every usage, keeping case 1 working end to end. Rationale text and panel labels stay in Spanish.

## Tasks
- [x] T1 `domain.py` + deterministic executor layers (menu → policy → lane → infra), allowlist via `managed: true`, approval queue, tests first — route: inline (contract given verbatim). Evidence: `test_executor.py` RED (ImportError `Lane`) → GREEN 24 passed.
- [x] T2 reasoner tool schema in English (`action`, `target{type,value}`, `rationale` in Spanish, `evidence`, `confidence`), monitor, app (`/api/approvals`), panel (shows `layer`) — route: inline.
- [x] T3 docs (`README.md`, `docs/REPARTO.md`) — route: inline.
- [ ] T4 victim publishes `managed` in `/metrics` — outside this writer's edit surface; diff handed to the parent. Until applied, `kill_process` is rejected by policy for every pid.

## Verification
- `python -m pytest centinela_svc -q`: 24 passed.
- Local docker e2e (victim built from a scratch copy with the T4 diff applied): Claude proposed `kill_process` → `process 9`, confidence `medium`; executor `executed`; pid gone (containment 10.6 s). `/api/simulate-compromised` → `rejected`, layer `policy`.

## Next step
Apply the T4 victim diff on this branch, re-run the e2e, then PR to `main`.

## Cloud verification
- Deployed d46974a to Render (manual API trigger; GitHub app was not installed yet). Cloud e2e: kill_process executed, containment 7.57 s; forged proposal rejected with layer policy.
