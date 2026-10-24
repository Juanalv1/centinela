# Client dashboard (`/dashboard`)

Objective: a product-oriented client dashboard with sidebar navigation, served by the `centinela` service at `/dashboard`, backed only by real data.

Problem / why: the live monitor at the victim root looks like a demo, and the hackathon is product oriented. The dashboard belongs on `centinela` (not the victim): the victim is the attacked machine, and the data (`/api/state`, `/api/approvals`, audit) already lives on `centinela` (same origin, no CORS).

Design reference: https://claude.ai/artifact/9sBBmcCDMy66mgTdxcUSRo (Resumen + Detalle de incidente). Match the landing's fonts (Urbanist + JetBrains Mono) and palette.

Scope: new `centinela_svc/dashboard.html`, a `GET /dashboard` route in `centinela_svc/app.py`, tests. No changes to the landing, portal, legacy panel or victim.

Constraints: real data only (no invented numbers; show an empty or "sin datos" state when a field is missing); UI copy in Spanish (project convention); vanilla HTML/CSS/JS, no build step; works at phone width.

TDD: off (no configured mode); runner `PGSERVER_DATA=$(mktemp -d) python -m pytest -q tests centinela_svc`.
Delivery: ask-on-risk; feature branch `feat/client-dashboard`, work-unit commits, PR left to the user.

## Tasks

- [x] T1 `GET /dashboard` serves `dashboard.html`: sidebar, status banner, KPIs, server activity, AI analysis, incidents, approvals, response policy, polling real `/api/state` and `/api/approvals`. Route: delegated (writer trigger: 2+ non-trivial files).
- [x] T2 Tests: route returns the page; page only consumes existing endpoints.

- [x] T3 Real data gaps: dashboard reads `/api/live` (attackers, activity) and a new `GET /api/server-stats` that proxies the victim's `/monitor/stats` (container CPU/memory) server-side. Route: delegated.
- [x] T4 Google login: `/login`, OAuth code flow with `state`, signed session cookie, `/logout`; `/dashboard` requires a session when `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`/`SESSION_SECRET` are set, otherwise demo mode with a visible banner (pitch fallback). Route: delegated.
- [x] T5 Approvals from the dashboard: a logged-in user whose email is in `ADMIN_EMAILS` can approve/reject; the existing `X-Approver-Token` path keeps working. Route: delegated.
- [x] T6 Product flow: landing CTA "Entrar" → `/login` → `/dashboard`; dashboard links back to `#acceso`. Route: delegated.

Accepted change (2026-10-24): user chose real Google login over a demo-only CTA (benchmark: team 22 ships Google login with orgs). Single demo org: any Google account sees the monitored server; approving is restricted to `ADMIN_EMAILS`. Known limit: `/api/state` stays public (landing and victim monitor read it), so login gates the product surface, not the raw data.

## Acceptance

- `/dashboard` renders with live data from the deployed service; no hardcoded metrics.
- Full test suite passes.

## Progress

- T1+T2 done (delegated writer). Page polls only `/api/state` every 2 s; DOM built with textContent (no innerHTML).
- Not backed by real data, so omitted or "sin datos": memory, hostname (uses `victim_url`), blocked-sources count. Policy card mirrors `MENU` in `domain.py` (state doesn't expose it).
- Approvals are read-only: `POST /api/approvals/{id}` needs `X-Approver-Token`; no page holds it.
- Verification: `PGSERVER_DATA=$(mktemp -d) python -m pytest -q tests centinela_svc` (Python 3.12 venv): 98 passed. System Python 3.14 can't install `pgserver`. Not checked visually in a browser.
- Next: visual check on the deployed service; decide whether approvals get an in-page token flow.

### T3-T6 (delegated writer)

- T3: `GET /api/server-stats` proxies `{VICTIM_URL}/monitor/stats` via `monitor.http` (3 s timeout); failure returns 502 with `cpu_percent`/`mem_percent` null plus `error` (exception class only, no URL). Dashboard shows container CPU, memory, an "Atacantes" KPI (`/api/live` `people`) and an activity list (textContent only). The CPU sparkline is now a client-side history of container CPU readings (not the host samples).
- T4: `login.html`, `/login`, `/auth/google`, `/auth/callback` (state constant-time compare, single use; `email_verified` required), `POST /logout`, `GET /api/me`. SessionMiddleware only when client id + secret + `SESSION_SECRET` are all set. Unconfigured: `/dashboard` open with "Modo demo" banner. Login errors are codes (`denied|state|email|failed`) mapped to Spanish text client-side.
- T5: `POST /api/approvals/{id}` accepts a valid `X-Approver-Token` (unchanged) or, when auth is configured, an `ADMIN_EMAILS` session plus CSRF (`X-Requested-With: centinela` and `Origin` equal to `PUBLIC_URL`, or same host if unset). Configured mode: no session 401, non-admin or bad CSRF 403 (also when no `APPROVER_TOKEN` is set, so configured mode is never open). Demo mode: legacy behavior exactly. Dashboard shows Aprobar/Rechazar only when `/api/me` says `can_approve`.
- T6: landing nav "Entrar" and hero CTA "Ver mi panel" go to `/dashboard`; dashboard sidebar link "Quiero esto para mi empresa" goes to `/#acceso`.
- Known limits: `/api/state`, `/api/live`, landing, `/unirse` stay public (login gates the product page, not raw data). In demo mode `/api/me` reports `can_approve` true unless `APPROVER_TOKEN` is set (matches the open legacy API). `/logout` has no CSRF check (low impact).
- Verification: `PGSERVER_DATA=$(mktemp -d) venv12/bin/python -m pytest -q tests centinela_svc`: 123 passed (baseline 98; +25 in `tests/test_auth.py` and the extended `tests/test_dashboard.py`). Not exercised against real Google or in a browser.
