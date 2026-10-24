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

## Acceptance

- `/dashboard` renders with live data from the deployed service; no hardcoded metrics.
- Full test suite passes.

## Progress

- T1+T2 done (delegated writer). Page polls only `/api/state` every 2 s; DOM built with textContent (no innerHTML).
- Not backed by real data, so omitted or "sin datos": memory, hostname (uses `victim_url`), blocked-sources count. Policy card mirrors `MENU` in `domain.py` (state doesn't expose it).
- Approvals are read-only: `POST /api/approvals/{id}` needs `X-Approver-Token`; no page holds it.
- Verification: `PGSERVER_DATA=$(mktemp -d) python -m pytest -q tests centinela_svc` (Python 3.12 venv): 98 passed. System Python 3.14 can't install `pgserver`. Not checked visually in a browser.
- Next: visual check on the deployed service; decide whether approvals get an in-page token flow.
