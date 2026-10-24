# Centinela detection evaluation (read-only)

Model: claude-sonnet-5-5 (exact project reasoner.py, unmodified). 3 reps/scenario.
Setup: real victim Docker image built from repo; real harmless workloads (pure
arithmetic CPU loops / temp-file writes) injected via `docker exec` as user `app`;
REAL /metrics snapshots captured and fed to the actual reasoner. Repo untouched.
Metric of a "catch" = reasoner proposes `kill_process` on the injected pid.
`recommend` = flagged to a human, never executed. `none` = ignored.

## Round 1 — WITH tells (single core ~100%, host ~8% of 12 cores)
| scenario | class | result (3 reps) |
|---|---|---|
| S1 obvious_miner (fake stratum+tcp in cmdline, /tmp) | suspicious | kill x3 (high) |
| S2 stealth_generic (python3, /tmp, no pool string)   | suspicious | kill x3 (med/high) |
| S3 masquerade (kworkerd name, /tmp)                  | suspicious | kill x3 (high) |
| L1 ffmpeg transcode (/tmp binary)                    | legit | none x3 |
| L2 etl pipeline (/tmp binary)                        | legit | recommend x3 |
| L3 backup gzip (/tmp binary)                         | legit | recommend/none |

Suspicious caught 9/9; legit auto-killed 0/9. BUT rationales lean on two lexical/
environmental tells: the `stratum+tcp` string AND the `/tmp` execution path
(cited for suspicious AND legit procs).

## Round 2 — tells removed (binaries in /usr/local/bin, scripts in /opt/jobs)
| scenario | class | result (3 reps) |
|---|---|---|
| S2b stealth_generic (python3)   | suspicious | none x3 |
| S3b masquerade (kworkerd)       | suspicious | recommend x3 (low) |
| S4b randname (x7fq2)            | suspicious | recommend x3 (med) |
| L1b ffmpeg | legit | none x3 |
| L2b etl    | legit | none x3 |
| L3b backup | legit | none x3 |

Suspicious auto-killed 0/9. Without the /tmp + pool tells the model ignores a
nondescript high-CPU python entirely and only soft-flags the masquerade/opaque
names. Legit spared 9/9 (clean).

## Round 3 — multi-core behavioral abuse, no tell (11 generic python3 pegging host 92%)
S5 multicore_stealth: recommend x3 (med/low), kill 0/3.
Even clear host-wide CPU saturation by 11 identical nondescript processes is not
enough to auto-contain; model recommends human review ("matar un solo pid no
resolveria la saturacion").

## Conclusion
- The AI SPARES legitimate heavy workloads reliably (0 false auto-kills in 27 trials).
- The AI's confident auto-containment (`kill_process`) is driven by lexical/
  environmental tells (fake `stratum+tcp`, `/tmp` path), NOT by workload behavior.
  Remove the tells and auto-containment drops to 0/12 across stealth, masquerade,
  opaque-name and multi-core-saturation cases; it degrades to human-review recommends.
- Single-core 100% on a 12-core idle host is genuinely weak evidence, and the model
  reasonably treats it so; but even full host saturation did not trigger auto-kill.

## Caveats / limitations
- Residual tell: the worker script arg `worker_cpu.py` under `/opt/jobs` reads as a
  legit "jobs" dir, which may bias round 2/3 toward leniency.
- `managed` flag is not in the compacted snapshot, so detection is purely
  name/cmdline/cpu/age/user driven (as intended).
- Workloads are CPU/IO loops; no memory, network or disk-pattern signals were tested.
