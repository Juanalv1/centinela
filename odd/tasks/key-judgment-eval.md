# Feature: key-judgment-eval

## Objective
Validate the idea, independent of the current implementation: can an AI judge tell "the same owner doing something unusual" from "someone else using the key", better than a deterministic rule?

## Problem
A3 only compared an attack against ordinary use, which a rule also solves. The product thesis ("a rule sees what is unusual; the AI understands whether it is theft") is untested. A founder-customer said they would accept automatic revocation only if detection is good.

## Approach
An offline eval harness, not tied to `centinela_svc`: hand-written scenarios (key profile + current window), a deterministic rule baseline, and a fresh LLM judge with its own prompt. Same inputs to both; compare decisions against the expected label.

## Scenario families (each with several variants)
- Legit unusual (expect no revoke): travel (new IP, odd hour, usual endpoints and volume); new integration (same IP and hours, new endpoint, low volume); month-end (same IP and endpoints, 5x volume); infra change (new cloud IP range for a machine key, same cadence and endpoints); weekend on-call (off-hours, usual endpoints).
- Theft (expect revoke): bulk export (new IP, new endpoint, paginated download); low-and-slow (new IP, usual endpoints, steady paging over hours); mimic (new IP, usual endpoints and hours, but a resource scope the key never touched); off-hours scrape.
- Honest hard cases are kept even if both fail.

## Metrics
Per method: theft caught, legit false revokes, per family; plus the AI's rationale for every miss. Several runs per AI scenario to measure consistency.

## Constraints
- API key only from `ANTHROPIC_API_KEY` env or the gitignored `.env`; never printed or logged.
- Model `claude-sonnet-5-5` (same as the service).
- Results written as Markdown under `docs/evals/`.

## Tasks
- [x] V1: scenarios + rule baseline + LLM judge + runner, with tests using a fake judge. Route: delegated (2+ non-trivial files).
  Done: `evals/key_judgment/` (27 scenarios, 9 families x 3, one hard each); rule catches 8/12 theft with 10/15 legit false revokes; 12 tests green, dry run OK; real model not run.
- [ ] V2: real run with the model; record results in `docs/evals/key-judgment.md`. Route: inline (needs the API key).

## Acceptance
The idea is supported only if the AI revokes the large majority of theft variants and makes clearly fewer legit false revokes than the rule. Otherwise the result is recorded as a failed validation.
