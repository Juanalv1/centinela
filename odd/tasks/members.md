# Members and roles

Objective: replace the `ADMIN_EMAILS` env list with invite-only members whose roles are managed from the dashboard and audited in the hash chain.

Problem / why: an env var that changes who can approve high-impact actions by redeploying, with no trace, contradicts the product's pitch and looks improvised to a technical jury.

Scope: `centinela_svc/` (new members store, app routes, dashboard "Equipo" section, login gate) and tests. Victim untouched.

Decisions (user, 2026-10-24):
- Invite-only: a Google account that is not a member gets a "sin acceso" page; it never sees the dashboard.
- Roles: `admin` (approve/reject, manage members) and `viewer` (read-only).
- `ADMIN_EMAILS` is only a bootstrap seed: when the members table is empty, those emails become the first admins.

Constraints:
- Members table lives in the audit DB (Centinela's), never the victim DB. Every add / role change / removal is also appended to the hash-chained audit log (`kind: member`), with actor and target.
- Guards: never remove or demote the last admin; nobody changes their own role or removes themselves; only admins manage members; session + CSRF as approvals (`_csrf_ok`).
- The executor / AI path has no route to the members table.
- Demo mode (no Google auth configured) keeps today's behavior.
- JSONL fallback (no `AUDIT_DATABASE_URL`): members in memory seeded from `ADMIN_EMAILS`; documented.
- Google OAuth app is in Testing: a new member also needs to be a Google test user.

TDD: off; runner `PGSERVER_DATA=$(mktemp -d) python -m pytest -q tests centinela_svc` (Python 3.12 venv).
Delivery: ask-on-risk; branch `feat/members`, work-unit commits; merge to main (deploys) is the user's call.

## Tasks

- [x] T1 Members store (audit DB table + in-memory fallback), bootstrap from `ADMIN_EMAILS`, audit events. Route: delegated (writer trigger).
- [x] T2 Login gate (non-members → "sin acceso"), `/api/me` role, approvals authorized by role instead of `ADMIN_EMAILS`. Route: delegated with T1.
- [x] T3 API + dashboard "Equipo" section: list, invite by email, change role, remove, with guards. Route: delegated with T1.
- [x] T4 Member change and audit entry commit atomically. Route: delegated writer.

## Acceptance

- Inviting, promoting and removing a member works from the dashboard and each change appears in the audit log.
- A non-member Google account cannot see the dashboard; a viewer cannot approve or manage members.
- The last admin cannot be removed or demoted; nobody can change their own role.
- Full test suite passes.

## Progress

- Branch created and published.
- T1-T3 implemented and committed on the feature branch. Route: delegated direct (one writer). New `centinela_svc/members.py` (store, SQL-guarded), `noaccess.html`; edits in `app.py`, `dashboard.html`; new `tests/test_members.py`, updated one `/api/me` assertion in `tests/test_auth.py`.
- Design: non-member keeps a session but gets 303 to `/sin-acceso` (403 page with escaped email, switch account, logout); role re-read from the store each request, fail closed on DB error; `GET /api/members` is admin-only; last-admin guard via `SELECT ... FOR UPDATE` on admin rows in a transaction; bootstrap under `LOCK TABLE`; member writes raise (503) instead of being swallowed.
- Verification: baseline `pytest -q tests centinela_svc` 181 passed; after changes 213 passed.
- Deploy note: `ADMIN_EMAILS` is bootstrap-only (used only while the `member` table is empty); no new env vars.
- T4 (uncommitted): `AuditLog.append_in(conn, ...)` + `adopt(entry)` insert the hash-chained entry in the member transaction (advisory xact lock on the chain tail, savepoint retry on seq collision with plain `append`); all `MemberStore` writes use it, so an audit failure rolls the change back (503). In-memory/JSONL fallbacks append the audit entry first and mutate only on success. Verification: `pytest -q tests centinela_svc` 220 passed (baseline 213; +7 tests: rollback x4 ops, both-rows+chain, concurrent two-AuditLog gap-free chain, fallback no-mutate).
