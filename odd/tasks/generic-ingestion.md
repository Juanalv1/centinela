# Feature: generic-ingestion

## Objective
Centinela reads credential access activity from any source through one normalized event format, instead of only polling the demo victim's own endpoints.

## Problem
`centinela_svc/monitor.py` polls `VICTIM_URL` endpoints (`/access-log`, `/metrics`, `/security-state`) whose shapes are specific to `victim/`. A customer cannot connect their proxy, CloudTrail or app logs, so Centinela is a demo, not a product.

## Why
Product first, demo follows: `docs/INTEGRACION.md` promises read-only ingestion from existing logs; this makes it real for the access-log path (the stolen-credential case).

## Scope
- A normalized `AccessEvent` (source, event id unique per source, ts, key id, key label, client ip, method, path, status, bytes) and one place that feeds those events into the per-key baseline (`keywatch.py`).
- The victim becomes one source adapter that maps its `/access-log` rows to `AccessEvent` (behavior unchanged).
- Push ingestion: `POST /api/ingest/access` with a batch of events, authenticated by `INGEST_TOKEN` (constant-time compare; disabled when unset). Idempotent by (source, event id). Bounded batch size.
- A reference forwarder (stdlib, repo root) that reads an nginx JSON access log and posts batches to that endpoint.
- `docs/INTEGRACION.md`: document the format, the endpoint and the forwarder.

## Out of scope
Process metrics (`/metrics`) and key status (`/security-state`) stay on the victim adapter. CloudTrail or SaaS connectors. `domain.py` unchanged.

## Constraints
- Ingested data is metadata only: never key values, request bodies or customer data.
- Existing tests and the live demo flow keep working (victim adapter path unchanged in behavior).
- Do not push to `main` until the feature is done and merged (pushes redeploy Render).

## Tasks
- [x] E1: `AccessEvent` + victim adapter + single feed path into keywatch, with tests. Route: delegated (2+ non-trivial files). Done: `ingest.py`, `Monitor.feed`/`evaluate_keys`, dedupe by (source, id); tests/test_ingest.py green.
- [x] E2: `POST /api/ingest/access` with `INGEST_TOKEN`, idempotency and batch limit, with tests. Route: delegated. Done: Bearer token (constant-time), 404 when unset, 413 over 1000 events or 1 MB, 422 all-or-nothing; E1 commit 67dfef1.
- [x] E3: nginx JSON forwarder + tests; `docs/INTEGRACION.md` updated. Route: delegated. Done: `forward_nginx.py` (offset state, batches, rotation), end-to-end test flags like the victim; E2 commit 2e564a0. Full suite: 222 passed, only the known environmental failures.

- [x] E4: the key watch does not depend on the victim. Route: inline (one bounded writer, `application/monitor.py` + tests). Done: when `/metrics` fails, `Monitor.tick` still judges keys fed from any source, wakes the reasoner with a snapshot without processes (nothing invented, no heartbeat on an empty snapshot) and hands `revoke_key` proposals to the executor; the `/metrics` error is re-raised so the loop still reports the victim as down. `/access-log` and `/security-state` failures no longer skip key evaluation. Process monitoring unchanged while the victim is up. Tests: `tests/test_monitor_keys.py` (victim unreachable, push-only and with the victim adapter; nothing flagged keeps the reasoner quiet). Commit 55073b8.

## Acceptance
- Events pushed through `/api/ingest/access` produce the same flag as the same activity read from the victim (test).
- Replaying the same batch learns nothing twice (test).
- Missing or wrong token → 401; batch over the limit → 413.

## Checks
`python -m pytest tests -q` with the scratch venv and `PGSERVER_DATA` (see credentials-view verification).

## Progress
Branch `feat/generic-ingestion` from main at 25a95b4 (old flat layout; commits 67dfef1, 2e564a0, a62a49c).

Ported to the layered layout on `feat/generic-ingestion-layered` from main at ad9d3a4 (behavior unchanged):
- `domain/access.py`: `AccessEvent`, `parse_event`, `InvalidEvent`, `SOURCE_RE`, `VICTIM_SOURCE`, `page_of` (stdlib only).
- `domain/keywatch.py`: dedupe by (source, id), `ingest` returns how many entries were new.
- `adapters/victim.py`: `from_victim_row`. It is injected into `Monitor(..., victim_events=...)` through the `VictimRowMapper` port (`application/ports.py`), so the application layer never imports an adapter; `web/app.py` wires it. Without it the victim's access log is not read (pushed events still work).
- `application/monitor.py`: `feed`, `evaluate_keys`, labels from pushed events, `key_feedback` entries carry `source` (legacy rows default to `victim`).
- `web/api.py`: `POST /api/ingest/access`; `web/config.py`: `Settings.ingest_token` (`INGEST_TOKEN`), `INGEST_MAX_EVENTS`, `INGEST_MAX_BYTES`.
- `forward_nginx.py`, `render.yaml`, `docs/INTEGRACION.md`: unchanged from the original branch.
- Commits: c5d3f7f (events + endpoint), d5534dd (forwarder + docs), 55073b8 (E4).
- Full suite on the layered branch: 249 passed; 7 failed and 13 errors, the same set as on clean main (Windows psycopg/ProactorEventLoop and victim subprocess fixtures).
