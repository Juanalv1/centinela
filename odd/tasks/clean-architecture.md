# Clean architecture refactor (centinela_svc)

## Objective
Reorganize `centinela_svc/` into light layers without behavior change.

## Scope
- In: `centinela_svc/`, its Dockerfile, `tests/` imports, `render.yaml` if the start command changes.
- Out: `victim/` (demo environment).

## Target layout
- `domain/`: domain, history, keywatch (pure, no I/O)
- `application/`: monitor, executor policy
- `adapters/`: Claude reasoner, victim HTTP/DB clients, audit log, audience store, members store
- `web/`: routes, auth, wiring, HTML

## Constraints
- Ports (Protocol) only where a second implementation or test fake exists: reasoner, victim, audit.
- No DI framework. No behavior change.

## Baseline
Re-measured on main 7437620 by the writer before moving files (previous main: 120 passed, 5 victim/ failures, 5 pgserver collection errors).

## Tasks
- [x] T1 Move modules into layers, split executor I/O into adapters, split app.py into web/ (route: delegated, 2+ non-trivial files). Evidence: cfc1cd3 (captured by the auto-sync commit, not a dedicated work-unit commit)
- [x] T2 Update tests, Dockerfile, deploy config; suite matches baseline. Evidence: cfc1cd3; after: 123 passed, 5 failed (victim/ only), 6 pgserver collection errors = baseline on 7437620; tests/test_executor.py 24 passed; `python -c "import web.app"` ok

## Follow-ups
- application/executor.py still lazy-imports psycopg to classify DB errors (kept to avoid unverifiable behavior change; pg tests need pgserver).
- Monitor still polls the victim through an injected httpx client (constructor kept for tests).
- HANDOFF.md / docs/REPARTO.md still name old flat paths.

## Next step
Review and PR (user decision).
