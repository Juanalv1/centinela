# Feature: control-layer-case2

Objective: Persona A work items from `docs/REPARTO.md` (control layer and lab) for case 2, on top of the English domain contract merged to `main`. Branch: `feat/control-layer-case2` (not pushed; Render auto-deploys `main`).
Delivery: single branch, work-unit commits, PR left to the user. Test runner: `PGSERVER_DATA=$(mktemp -d) python -m pytest -q tests centinela_svc` (embedded PostgreSQL 16 via `pgserver`; no Docker on this machine).

## Specs

- S1 "**Lista blanca en el ejecutor (urgente):** solo se pueden matar procesos lanzados por el job runner. Hoy es una lista negra, y en Render habría permitido matar `portdetectorv2`."
- S2 "**Bitácora persistente:** pasarla de `/tmp` a Postgres de Render, manteniendo la cadena de hashes."
- S3 "**Víctima del caso 2:** una API de PyME con usuarios, claves de API y sesiones en Postgres. Un log de acceso HTTP que guarde el User-Agent."
- S4 "**Credencial mínima:** un rol de Postgres para el ejecutor con `GRANT` solo sobre `api_keys.status`, `ip_blocklist` y `sessions`. Nunca sobre `users`. Verificar que `permission denied` llegue a la bitácora."
- S5 "**Ejecutor del caso 2:** implementar las acciones nuevas del menú y la cola de aprobación humana para las acciones de alto riesgo."
- S6 Shared contract (REPARTO, as updated on `main`): "Menú (`MENU`, identificadores en inglés): `kill_process` (process), `revoke_key` (key), `block_ip` (ip), `close_sessions` (user) en el carril `auto`, y `suspend_user` (user) en el carril `approval`." `domain.py` is not modified by this feature.

Decisions / assumptions (to confirm with the team):
- A1 `target.value` for `key` and `user` is the numeric id (the access log exposes `api_key_id` and `user_id`); the executor role cannot read `users`, so usernames cannot be resolved.
- A2 `suspend_user` writes a `user_suspensions` row (and closes that user's sessions) instead of touching `users`. This widens S4's grant list by one table, to honor the agreed menu without breaking "nunca sobre `users`".
- A3 Admin keys, admin users and the office network (`OFFICE_CIDR`) are protected in the policy layer and again by database triggers (they refuse even a bypassed executor).
- A4 `POST /api/approvals/{id}` (Persona B's endpoint) requires `X-Approver-Token` when `APPROVER_TOKEN` is set; unchanged when unset. The panel is public, so without it anyone could approve.

## Tasks

| ID | Specs | Route | Status | Commit |
|---|---|---|---|---|
| T1 | S1 | superseded | done on `main` (`47f2b29`, `d46974a`); added victim test `tests/test_victim_managed.py` | 47b8c83 |
| T2 | S2 | inline | done | 7491606 |
| T3 | S3 | inline | done | a6ca5fe |
| T4 | S4 | inline | done | a6ca5fe, 47b8c83 |
| T5 | S5, S6 | inline | done | 47b8c83 |
| T6 | all | inline | done (render.yaml, README, REPARTO) | 82e3f9c |
| T7 | all | delegated verifier | done: 2 blockers fixed in one correction batch, recheck green | 5917e35 |

Route evidence: no Writer trigger (units share one contract and depend on each other). Verification trigger fires: T4/T5 touch credentials and guards (item 2), T6 touches deploy config (item 5).

## Log

- L1 (2026-10-24) User request, verbatim: "'/Users/christianmendoza/Downloads/Centinela (Copy).html' mira echale bola ahi con que podes desarrollar y probar, ahi meti un ANTHROPIC_API_KEY en el .env para que uses la api de claude por si acaso, dale guaya con lo que me toca en docs, utiliza odd para esto, documenta todo en el obsidian porfa"
- L2 "Lo que me toca en docs" = Persona A (Christian) in `docs/REPARTO.md`. The HTML is the landing/demo mockup (menu `kill_process`, `block_ip`, `disable_credential (no admin)`, `isolate_host` with a human).
- L3 Environment: no Docker, no system Postgres. `uv` venv (Python 3.12) + `pgserver` gives a real PostgreSQL 16.2.
- L4 First pass (Spanish contract) built T1-T5 with 33 tests green; kept locally as branch `backup/control-layer-case2-es`.
- L5 (2026-10-24) User, verbatim: "mira, pullea main, y traete los cambios porfa ahi haces el ajuste necesario porfa". `main` had 4 new commits: English contract, layered executor with `managed` allowlist and approval queue, reasoner/panel/app updates. Rebased T2 and T3/T4 onto `main`, dropped my T1 and approval queue (superseded), rewrote T5 on the upstream executor. Upstream tests adapted: `suspend_user` value `"alice"` -> `"2"`; rule 7 now asserts "EXECUTOR_DATABASE_URL not configured" with layer `infra`.
- L6 Evidence: 56 passed (`tests` + `centinela_svc`). RED observed before each GREEN (allowlist, audit, victim, executor, approval token). Live run with real Claude (`claude-sonnet-5-5`): reasoner answered, audit rows landed in Postgres (7), unauthenticated approval returned 401. Claude chose `none` locally because the 200-char cmdline cut in `reasoner.py` hid `stratum+tcp` behind the long macOS venv path; not an issue in Docker (short path). Reported to Persona B's area, not changed.
- L7 Unverified: whether Render's managed Postgres user has CREATEROLE (needed to create `centinela_executor`); the victim logs an error and keeps running if not. `basic-256mb` plan name taken from Render's current plan list, not checked against the account.
- L8 Independent verifier (S1, S2, S3, S5, S6 met; S4 partial). Blockers: (1) victim trusted the left-most `X-Forwarded-For` entry, so `X-Forwarded-For: 1.2.3.4, <blocked ip>` or `::ffff:<blocked ip>` returned 200; (2) `render.yaml` gave Centinela the victim's owner credential through `AUDIT_DATABASE_URL`, and the victim owner could `TRUNCATE audit_log` with `verify()` still passing. Fixes (`5917e35`): `TRUSTED_PROXY_HOPS` (right-most entries only, IPv4-mapped normalized), separate `centinela-audit-db`, BEFORE TRUNCATE trigger; advisories fixed too: mapped/unspecified IPs in policy, trigger refuses ranges and `::ffff:` addresses, executor reads only `sessions(id, user_id)`. Recheck: 62 passed, the spoof probes now return 403.
- L9 Advisories left open: `/access-log` and `/security-state` are public by design (monitor); approvals are open if `APPROVER_TOKEN` is blank (deploy checklist); pending approvals live in memory; `revoke_key` protection relies on the `protected` flag.
