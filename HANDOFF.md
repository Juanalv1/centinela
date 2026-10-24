# Handoff: Centinela — demo design for Platanus Hack (AI Security)

**Generated**: 2026-10-24 14:53 (updated after pulling Christian's demo work)
**Branch**: main
**Status**: In Progress — demo format chosen (QR portal with real attacks); polishing and validation

## Goal

Win Platanus Hack Caracas (AI Security track) with Centinela: AI-assisted incident response where the AI only *proposes* actions from a closed menu and a deterministic executor with least-privilege credentials decides. Current focus: an interactive 3-minute live demo where the audience participates via QR.

## Completed

- [x] Repo `Juanalv1/centinela` (public); collaborators: CalitoTech, maikCyphlock, ChristianVeneko (accepted); Josemigg16 (pending at last check).
- [x] Case 1 (CPU-burning job) works end to end on Render: Claude proposes `kill_process`, executor validates, victim kills. Cloud containment 5.5–7.6 s. See `VIABILIDAD.md`.
- [x] English domain contract (`centinela_svc/domain.py`): closed MENU with lanes, `layer` on decisions, process allowlist (`managed` flag from victim). 24 executor tests pass.
- [x] Work split in `docs/REPARTO.md`: A = Christian (control layer/lab), B = Maikol (AI/panel/demo).
- [x] Christian already pushed case-2 control layer (Postgres victim API, least-privilege executor role, persistent audit). See `odd/tasks/control-layer-case2.md`.
- [x] Auto-deploy: GitHub Action `.github/workflows/deploy.yml` calls Render deploy hooks on push to `main` (secrets `RENDER_HOOK_VICTIM`, `RENDER_HOOK_CENTINELA`). Verified: trigger `deploy_hook`.
- [x] Interactive mock of demo proposal 1: `docs/demo-mocks/01-empresa.html` (also published as private artifact https://claude.ai/artifact/JiWrRZ4j4yqnsnQo6U3vUP).
- [x] **Demo format chosen by the team and built by Christian** (see `odd/tasks/audience-live-portal.md`): QR → `/unirse` phone portal → `@handle` → real attack. Nothing simulated (user rule: "NADA ES SIMULADO TODO ES REAL EN ESE ENTORNO CONTROLADO").
  - Endpoints: `POST /api/join`, `POST /api/participate`, `GET /api/live` (`centinela_svc/audience.py`, in-memory).
  - Big screen `#envivo`: real shared feed, leaderboard and people count.
  - Miner (`/api/attack`) is a rate-limited singleton: taps during an active incident attach to it. Scalable per-person attack reuses `/api/simulate-compromised` (real forged proposal → real executor deny + layer + audit).
  - `victim/monitor.html`: real-time victim monitor page.

## Not Yet Done

- [ ] Run a full rehearsal on Render with several phones and check feed, leaderboard and containment times.
- [ ] Confirm whether the CPU visibility issue is resolved: Christian committed `b64e482` ("report the container's own CPU so attacks are visible") and reverted it in `84c82ef`. Ask him why before touching it.
- [ ] Mock proposals 2–3 (approval vote, injection vote) are now optional ideas for extending the live demo, not the plan.
- [ ] Measure real Claude API token cost (not measured; ~120 calls/h from 30 s heartbeat).

## Failed Approaches (Don't Repeat These)

- **kind/Kubernetes for real permission enforcement**: Render can't run privileged/Docker-in-Docker containers, and it's heavy locally. Replaced by Linux privilege separation (API as non-root, protected process as root → kernel EPERM) and Postgres GRANTs.
- **LocalStack IAM enforcement**: `ENFORCE_IAM` appears to be a Pro feature. Not used.
- **Render free plan**: sleeps after 15 min and has 0.1 CPU. Using Starter (hackathon credits; workspace needed a card first — `402 Payment information is required`).
- **Render native auto-deploy**: services were created via public repo URL; installing the Render GitHub app and relinking still produced no deploys on push. Solved with deploy hooks + GitHub Action.
- **Forced `tool_choice` on `claude-sonnet-5-5`** returned 400. Use `tool_choice: auto` + strict tool + prompt instruction.
- **Telling the model which pids the job runner started** biased it toward "legitimate". Removed; the executor enforces the allowlist.
- **"One process per audience tap" demos (miner/ransomware)**: 100 Python processes don't fit Starter's 512 MB, and plan upgrade is not an option. A shell-based worker might fit but was never measured. Also judges can say "a CPU threshold does this". Moved toward HTTP-based audience participation.
- **"Engaña a Centinela" with audience-written disguises**: too much effort for the audience in a 3-minute demo. Rejected by user.
- **One large HTML file with all 4 mocks at once**: generation was cut off. Build one small mock per proposal.

## Key Decisions

| Decision | Rationale |
|----------|-----------|
| Centinela over "Ventana Cero" | User bets on a visual live demo; Centinela has the stronger demo |
| Lane comes only from MENU; AI can only tighten (low confidence → approval) | An injection can't relax its own lane |
| `layer` on each Decision (`menu`/`policy`/`infra`) | Pitch metric: which layer stopped each injection |
| Process allowlist (`managed`) instead of blacklist | Render injected `portdetectorv2`, which the blacklist would have allowed killing |
| Code identifiers in English; jury-facing text in Spanish | User requirement |
| Recommended demo: proposal 1 (+2) | Answers the rate-limit objection (cut 1 of 50), lightweight HTTP, reuses case 2. Superseded: the team chose the QR portal with real attacks |
| Live demo: miner as singleton, forged-proposal attack per person | Fits 512 MB; every tap still hits the real executor and audit |

## Current State

**Working**: Panel https://centinela-lyiy.onrender.com · Victim https://centinela-victim.onrender.com · case 1 e2e · `/api/simulate-compromised` rejected with layer `policy`.

**Uncommitted Changes**: none (only this file).

## Files to Know

| File | Why It Matters |
|------|----------------|
| `centinela_svc/domain.py` | Shared contract (MENU, Lane, Proposal, Decision). Changes need both A and B to agree |
| `centinela_svc/executor.py` | Deterministic checks: menu → policy → lane → infra |
| `centinela_svc/reasoner.py` | Claude call, `propose_action` tool |
| `victim/app.py` | Job runner, `/metrics` (`managed` flag), `/kill` (token) |
| `docs/REPARTO.md` | Work split and team rules |
| `centinela_svc/audience.py` | Audience join/participate/live state and rate limits |
| `centinela_svc/portal.html` | Phone portal served at `/unirse` (QR target) |
| `victim/monitor.html` | Real-time victim monitor page |
| `odd/tasks/audience-live-portal.md` | Specs and evidence for the live demo |
| `docs/demo-mocks/01-empresa.html` | Demo mock 1 (open by double-click) |
| `VIABILIDAD.md` | Feasibility report with cloud timings |
| `odd/tasks/*.md` | Per-feature task docs with evidence |

## Code Context

```python
MENU = {
    "kill_process":   ActionSpec("process", Lane.AUTO),
    "revoke_key":     ActionSpec("key",     Lane.AUTO),
    "block_ip":       ActionSpec("ip",      Lane.AUTO),
    "close_sessions": ActionSpec("user",    Lane.AUTO),
    "suspend_user":   ActionSpec("user",    Lane.APPROVAL),
}
# Decision.status: executed | rejected | pending_approval | recommended | noop | failed
# Decision.layer:  "menu" | "policy" | "infra" | None
```

Render service IDs: victim `srv-dbeevj3rjlhs73fg5ong`, centinela `srv-dbeevjvb9u1s739gc7eg`, workspace `tea-csppmdd6l47c73f6afmg`.

## Resume Instructions

1. `git pull` on `main`; read `docs/REPARTO.md` and `odd/tasks/control-layer-case2.md` (teammate work may have moved on).
2. Open `https://centinela-lyiy.onrender.com/unirse` on a phone, join with a `@handle`, launch an attack, and watch the `#envivo` section on the panel.
   - Expected: your handle appears in the feed and leaderboard; the attack result shows on the phone.
3. Verify cloud still works: `python attack.py --target https://centinela-victim.onrender.com`, then `curl https://centinela-lyiy.onrender.com/api/state`.
   - Expected: a new incident with `containment_s` ≈ 5–8 s.
   - If no incident: check the latest Action run (`gh run list -R Juanalv1/centinela`) and Render deploy status.

## Setup Required

- Secrets live in `../.env` (outside repo): `ANTHROPIC_API_KEY`, `RENDER_API_KEY`, `RENDER_HOOK_VICTIM`, `RENDER_HOOK_CENTINELA`. Never commit them.
- `gh` is logged in as `Juanalv1`.

## Warnings

- Every push to `main` redeploys Render. Use branches + PR for code.
- The auto-mode classifier blocks destructive commands and secret-store writes (e.g. `gh secret set`); ask the user to run those with `! <command>`.
- User preferences: reply in Spanish, concise, one question at a time; validate ideas honestly; no AI attribution in commits; Conventional Commits.
- Demo is 3 minutes: one audience action type only.
