# Feature: credentials-view

## Objective
Show the customer, in the client dashboard (`/dashboard`), what Centinela learned about each credential, its current state, and let them correct a false alert ("this was normal") so the behavior joins the baseline.

## Problem
The product's core value is behavioral detection of stolen credentials (Snowflake 2024 pattern), but `/dashboard` only shows servers, CPU, processes, AI decisions, incidents, approvals, policy and audit. The per-key baseline computed by `centinela_svc/keywatch.py` is invisible, and there is no feedback loop (`docs/INTEGRACION.md` lists it as not implemented).

## Why
Product first, demo follows: a customer would use this view daily; the demo's "this is Ana's key" step needs it.

## Scope
- Backend: expose per-key profile (usual IPs/networks, hours, endpoints, volume), current window deviations, state (active / suspicious / revoked) and the latest AI rationale for that key.
- Feedback: an authenticated action "mark as normal" for a flagged key window; that window is learned into the baseline and the key stops being flagged for that same behavior. Recorded in the audit log.
- Frontend: a "Credenciales" section in `centinela_svc/dashboard.html`, consistent with existing sections, Spanish UI copy.

## Constraints
- `domain.py` unchanged; the AI still only proposes from the menu.
- Feedback never un-revokes a key (revocation stays an executor/human action); it only changes what is learned.
- Feedback endpoint protected the same way approvals are (`APPROVER_TOKEN` / dashboard session).
- No customer data or key values in the payload: key id/label only.
- Do not push to `main` (pushes redeploy Render).

## Tasks
- [x] C1: backend profile + state exposure (keywatch/monitor/app) with tests. Route: delegated (2+ non-trivial files). Done (58dcdf0): `KeyWatch.overview`, `Monitor.credentials` (state active/suspicious/revoked, latest AI analysis per key), `GET /api/keys`; `tests/test_credentials_view.py`.
- [x] C2: "mark as normal" feedback endpoint + baseline learning + audit entry, with tests. Route: delegated. Done (4a14d69): `POST /api/keys/{id}/normal` (same auth as approvals via shared `_approver`; 409 when not flagged), `KeyWatch.learn_window`/`learn` (dedup by entry id), `key_feedback` audit entry written before learning and replayed on restart; never touches key status.
- [ ] C3: "Credenciales" section in the dashboard wired to C1/C2. Route: delegated.

## Acceptance
- `/dashboard` lists each key with learned profile, state and latest rationale.
- Marking a flagged window as normal makes the same behavior not flag again (test).
- New tests pass; the 3 pre-existing failures on main (L8 of `behavioral-signals.md`) are not counted against this feature.

## Checks
`python -m pytest tests -q` (Postgres-backed tests use `tests/pg.py`).

## Progress
Branch `feat/credentials-view` (from main at 2eb2fd0).
