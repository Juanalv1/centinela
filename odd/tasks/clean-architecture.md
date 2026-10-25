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
- [ ] T1 Move modules into layers, split executor I/O into adapters, split app.py into web/ (route: delegated, 2+ non-trivial files)
- [ ] T2 Update tests, Dockerfile, deploy config; suite matches baseline

## Next step
T1.
