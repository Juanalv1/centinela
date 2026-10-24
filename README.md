# Centinela (working name)

AI-assisted incident response for small teams without a 24/7 SOC — designed so the AI can never be turned against you.

> The AI thinks, the code acts, the human decides what is serious.

## Core idea

- **Open detection:** the model reasons over logs and proposes a response.
- **Closed response menu:** the model can only *propose* actions from a fixed menu; it holds no credentials.
- **Deterministic executor:** validates each proposal (action allowlist, risk level, protected resources) and executes it with least-privilege credentials.
- **Response lanes:** automatic (reversible), human-approved (high impact), free-form recommendation (never executed), and forbidden (destructive actions do not exist).

## Status

Hackathon project — Platanus Hack 26 Caracas, AI Security track. Work in progress.

## Feasibility prototype

One end-to-end case: a CPU-burning job on a "company server" is detected by Claude, proposed as `kill_process`, validated by a deterministic executor and killed.

```
attack.py ──POST /jobs──▶ victim (FastAPI, runs as user `app`)
                            ├─ db-sim (protected, runs as root)
                            └─ report.py (harmless CPU loop, fake `--pool stratum+tcp://...` argv)
centinela ──GET /metrics (every 2 s)──▶ victim
   ├─ reasoner.py  Claude → one `propose_action` tool call {action, target{type,value}, rationale, evidence, confidence}; no credentials
   ├─ executor.py  deterministic layers: menu (action + target type) → policy (allowlist: only pids the
   │               victim marks `managed: true`, i.e. job-runner children) → lane from MENU (low confidence
   │               escalates to human approval) → POST /kill with X-Executor-Token (infra: 403 EPERM for root)
   ├─ audit.py     hash-chained JSONL (each entry carries sha256 of the previous line)
   └─ app.py       GET / panel, GET /api/state, POST /api/simulate-compromised (forged proposal → rejected, layer `policy`),
   │               GET /api/approvals, POST /api/approvals/{id} {"approve": bool}
```

Defense in depth: the model can only propose; the executor rejects anything off-menu or outside its allowlist; and even a bypassed executor cannot kill `db-sim`, because the victim API runs unprivileged and the kernel returns EPERM.

### Run locally with Docker

```sh
docker build -t centinela-victim victim
docker build -t centinela-svc centinela_svc
docker network create centinela-net
export EXECUTOR_TOKEN=$(python -c "import secrets;print(secrets.token_hex(16))")
export ANTHROPIC_API_KEY=...   # never commit it
docker run -d --name victim --network centinela-net -p 18000:8000 -e EXECUTOR_TOKEN centinela-victim
docker run -d --name centinela --network centinela-net -p 18080:8000 \
  -e VICTIM_URL=http://victim:8000 -e EXECUTOR_TOKEN -e ANTHROPIC_API_KEY centinela-svc
```

Open http://localhost:18080 for the panel. Optional env: `MODEL` (default `claude-sonnet-5-5`), `POLL_SECONDS` (default 2).

### Run the attack

```sh
python attack.py --target http://localhost:18000
```

The job is a pure arithmetic loop (no networking, stops itself after 10 minutes, at most one at a time). Within a few seconds the panel shows the proposal, the executor decision and the detection/containment times. The "Simular IA comprometida" button sends a forged proposal targeting `db-sim` to show the executor's rejection.

`render.yaml` deploys both services to Render (secrets declared with `sync: false`).
