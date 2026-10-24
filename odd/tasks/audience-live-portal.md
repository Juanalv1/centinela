# Audience live portal (QR → @handle → real attack)

- Objective: audience scans the QR, registers with a simple `@handle`, and launches a REAL attack from their phone against the controlled victim; the big screen shows a REAL shared feed/leaderboard. Rate limits keep it from blowing up.
- Branch: `feat/audience-live-portal` (do NOT push: push to main redeploys Render).
- Delivery: feature-branch work-unit commits; test runner `pytest` (TestClient, pgserver only if touching DB).

## Specs

- S1 (user, verbatim): "dale guaya con lo del qr y el registro del usuario con un @ snecillo para que haga el hackeo desde ahi, revisa bien la vaina, cualer cosa me preguntas". Interpreted: the QR must lead to a real phone portal with simple `@handle` registration, from which the participant launches the attack.
- S2 (user choice, verbatim): "Portal + feed real compartido". The `@handle` and each action appear LIVE on the big-screen feed/leaderboard, shared across all phones; backed by real backend state.
- S3 (user, verbatim): "NADA ES SIMULADO TODO ES REAL EN ESE ENTORNO CONTROLADO". No simulated feed, no random names. Every attack really hits the real executor/audit; feed/board read real backend data.
- S4 (user, verbatim): "TRATA DE METER UNOS LIMITES PAA QUE NO EXPLOTE DEL TODO pero que sea tipo situacion real". Add rate limits / caps so dozens of phones do not exhaust Render (512MB, victim runs one job at a time), while staying realistic (real systems rate-limit too).
- S5 (evidence-based constraint): the CPU miner (`/api/attack`, case 1) cannot be per-person real at scale — `monitor.py` polls only `/metrics`, victim runs one job at a time, HANDOFF documents 512MB can't fit many processes. So the miner action is a rate-limited singleton (cooldown; taps during an active incident attach to it); scalable real attacks reuse `/api/simulate-compromised` (real forged proposal → real executor DENY + layer + audit), which is cheap and already end-to-end real.
- S6: reuse existing real endpoints (`/api/attack`, `/api/simulate-compromised`) and real state (`incidents`, `audit`); do NOT change the shared contract `domain.py` (team rule: needs A+B agreement).

## Tasks

- T1 [S2,S3,S4,S5] inline — backend `audience.py`: participant registry + activity ring + leaderboard + rate limits; endpoints `POST /api/join`, `POST /api/participate`, `GET /api/live`. Tests with TestClient. Commit.
- T2 [S1] inline — `/unirse` serves a real mobile portal (replace the redirect): `@handle` input → attack menu → real result. Commit.
- T3 [S2,S3] inline — big-screen `#envivo`: replace simulated feed/board/people JS with real `GET /api/live` polling. Commit.

## Log

- L1 (2026-10-24, user, verbatim): "dale guaya con lo del qr y el registro del usuario con un @ snecillo para que haga el hackeo desde ahi, revisa bien la vaina, cualer cosa me preguntas"
- L2 (2026-10-24): clarified scope via two questions — chose "Portal + feed real compartido", then "NADA ES SIMULADO TODO ES REAL", then "mete límites para que no explote, tipo situación real". Verified against code: monitor only polls `/metrics`; `/api/simulate-compromised` is the scalable real attack; miner is a rate-limited singleton. No `domain.py` change needed.
