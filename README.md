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
