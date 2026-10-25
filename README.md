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

## Behavioral detection (no telling strings)

`/metrics` also reports, per process, its parent (`ppid`, `parent`), network peers (`net`: count, listening sockets, up to 3 `ip:port STATE`) and disk I/O rate (`io`: `read_bps`/`write_bps` between polls; `null` where the platform does not expose it, e.g. macOS). Centinela keeps a baseline of the workloads seen during its first `BASELINE_SECONDS` (default 60) and marks later ones `new_since_baseline`. The prompt asks the model to judge behavior, never names alone.

Two harmless jobs differ only in behavior: `sync` burns CPU and keeps a keep-alive connection to `SYNC_ENDPOINT` (a host we control) without writing to disk; `backup` burns CPU compressing data and writes real files (≤ 2 MB/s, three rotating 8 MB files) with no sockets. Neither carries a pool string.

```sh
EXECUTOR_TOKEN=... python behavior_trials.py --victim https://<victim> --centinela https://<centinela> --runs 5
```

The script starts each job N times and records whether the AI proposed `kill_process` for it (expected: every `sync`, no `backup`). Each process also carries `quota_percent` (its share of the container's own CPU budget, `cpu_quota_cores` from cgroup v2; per-core `cpu_percent` on a shared 16-core host understates it) and, in Centinela, `cpu_sustained_s` (seconds above half that budget).

### Stolen API key (Snowflake 2024 pattern)

The access log records response `bytes`, the `query` string and a `lab_seed` marker. A clearly marked 21-day history is seeded once: ana's key (`DEMO_LEAKED_KEY`) on weekdays, office hours, from the office network, on `/api/me` and `/api/invoices`; luis's reports key (`DEMO_LUIS_KEY`) every hour from `LAB_KNOWN_IPS`. `/api/customers?page=N` is the paginated data an attacker would export.

Centinela reads `/access-log` incrementally and keeps a deterministic profile per key (`centinela_svc/keywatch.py`). The last `KEY_WINDOW_SECONDS` (default 600) are compared against it: new ip/network, outside the key's usual days and hours, endpoints it never used, pages and volume against its busiest past hour. A key is flagged only when two or more independent deviations combine; flagged windows are never learned. Flagged keys wake the reasoner, which may propose `revoke_key`. Timezone for "usual hours": `LAB_TZ_OFFSET_HOURS` (default -4, Caracas).

```sh
LAB_TOKEN=... ANA_KEY=... LUIS_KEY=... python credential_trials.py \
    --victim https://<victim> --centinela https://<centinela> --key-window 120
```

Run it from an ip in `LAB_KNOWN_IPS`. It runs 5 normal uses of luis's key (expected: no `revoke_key`) and 5 slow paginated exports with ana's key (expected: `revoke_key`), calling `POST /lab/reset` (`X-Lab-Token`, only when `LAB_TOKEN` is set) between runs.

To run just the attack against any installation you own (slow paginated export that stops itself when the key is revoked, one line per request):

```sh
ANA_KEY=<leaked key> python stolen_key_attack.py --victim https://<victim> --pages 30 --delay 4
```

## Case 2: leaked API key on a small company's API (control layer)

The victim also runs a small company's API on Postgres (enabled by `DATABASE_URL`): users, API keys, sessions and an HTTP access log that stores the User-Agent (attacker-controlled text). See `victim/pyme.py` and `victim/schema.sql`.

| Endpoint | Purpose |
|---|---|
| `POST /api/login`, `GET /api/me`, `GET /api/invoices` | the business API (`X-API-Key` or `Authorization: Bearer <session>`) |
| `GET /access-log?after=<id>` | access log with `user_agent`, `ip`, `username`, `api_key_id` for the monitor |
| `GET /security-state` | keys, blocked IPs, users (role, suspended) and sessions per user |

The executor acts on that database with its own role, `centinela_executor` (`victim/roles.sql`):

| Action | Target value | What the role may do |
|---|---|---|
| `revoke_key` | key id | `UPDATE (status) ON api_keys` |
| `block_ip` | ip | `INSERT, DELETE ON ip_blocklist` |
| `close_sessions` | user id | `DELETE ON sessions` |
| `suspend_user` (approval lane) | user id | `INSERT ON user_suspensions` + close sessions |

It has no privileges on `users`, `access_log` or `protected_networks`. Admin keys, admin users and the office network (`OFFICE_CIDR`) are protected twice: the executor's policy layer rejects them, and database triggers refuse them even if the executor is bypassed (`Executor.bypass_demo`). The refusal (`permission denied: ...`) lands in the audit log as an `infra` failure.

Centinela env for case 2: `EXECUTOR_DATABASE_URL` (the executor role, never the owner URL), `AUDIT_DATABASE_URL` (Postgres audit log in its own database, which the victim cannot reach; append-only, TRUNCATE refused; falls back to `AUDIT_PATH`), `OFFICE_CIDR`, `APPROVER_TOKEN` (when set, `POST /api/approvals/{id}` requires `X-Approver-Token`; set it on every public deploy).

Victim env: `TRUSTED_PROXY_HOPS` (default `0`: ignore `X-Forwarded-For`; `2` on Render, where Cloudflare and Render's load balancer each append one entry; with `1` the victim would see a Cloudflare edge ip). Client-written entries are ignored, so a blocked IP cannot get back in by sending the header.

### Tests

```sh
uv venv -p 3.12 .venv && uv pip install -p .venv/bin/python -r centinela_svc/requirements.txt -r victim/requirements.txt pgserver pytest
PGSERVER_DATA=$(mktemp -d) .venv/bin/python -m pytest -q tests
```

`pgserver` starts a real embedded PostgreSQL, so the grants and triggers are tested for real (no Docker needed).
