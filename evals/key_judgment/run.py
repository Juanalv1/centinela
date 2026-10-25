"""Run the rule and the LLM judge over every scenario and write a Markdown report.

    python -m evals.key_judgment.run --dry-run            # fake judge, no key, report to stdout
    python -m evals.key_judgment.run --runs 3 --out docs/evals/key-judgment.md
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from . import rule
from .judge import MODEL, ClaudeJudge, Verdict
from .scenarios import FAMILIES, SCENARIOS, Scenario

OUTCOMES = ("revoke", "ask_human", "allow", "error")


@dataclass(frozen=True)
class Result:
    scenario: Scenario
    rule: rule.RuleDecision
    ai: tuple[Verdict, ...]


class FakeJudge:
    """Dry-run stand-in: leans on the rule's deviation count so the report has every outcome."""

    def __call__(self, s: Scenario) -> Verdict:
        n = len(rule.deviations(s))
        if n >= 3:
            return Verdict("revoke", "high", f"fake: {n} deviations")
        if n == 2:
            return Verdict("ask_human", "low", "fake: two deviations")
        return Verdict("allow", "medium", f"fake: {n} deviation(s)")


def evaluate(scenarios, judge, runs: int) -> list[Result]:
    return [Result(s, rule.decide(s), tuple(judge(s) for _ in range(runs))) for s in scenarios]


def summarize(results: list[Result]) -> dict[str, dict[str, Counter]]:
    """method -> family -> Counter of outcomes. The rule is deterministic: one run per scenario."""
    out: dict[str, dict[str, Counter]] = {"rule": defaultdict(Counter), "ai": defaultdict(Counter)}
    for r in results:
        out["rule"][r.scenario.family][r.rule.decision] += 1
        for v in r.ai:
            out["ai"][r.scenario.family][v.decision] += 1
    return out


def inconsistent(results: list[Result]) -> list[str]:
    return [r.scenario.id for r in results if len({v.decision for v in r.ai}) > 1]


def _wrong(expected: str, decision: str) -> bool:
    return (expected, decision) in {("revoke", "allow"), ("allow", "revoke")}


def _headline(per_family: dict[str, Counter]) -> str:
    theft = sum((c for f, c in per_family.items() if FAMILIES[f] == "revoke"), Counter())
    legit = sum((c for f, c in per_family.items() if FAMILIES[f] == "allow"), Counter())
    t, l_ = sum(theft.values()), sum(legit.values())
    return (f"Theft caught {theft['revoke']}/{t}, theft allowed {theft['allow']}/{t}; "
            f"legit false revokes {legit['revoke']}/{l_}; "
            f"ask_human {theft['ask_human']} theft + {legit['ask_human']} legit; "
            f"errors {theft['error'] + legit['error']}")


def _family_table(per_family: dict[str, Counter]) -> list[str]:
    lines = ["| Family | Expected | Runs | " + " | ".join(OUTCOMES) + " |",
             "|---|---|---|" + "---|" * len(OUTCOMES)]
    for family, expected in FAMILIES.items():
        c = per_family.get(family, Counter())
        if c:
            lines.append(f"| {family} | {expected} | {sum(c.values())} | "
                         + " | ".join(str(c[o]) for o in OUTCOMES) + " |")
    return lines


def _tally(verdicts) -> str:
    c = Counter(v.decision for v in verdicts)
    return ", ".join(f"{d} x{n}" for d, n in c.most_common())


def render(results: list[Result], runs: int, model: str) -> str:
    summary = summarize(results)
    ai_runs = sum(len(r.ai) for r in results)
    unstable = inconsistent(results)
    lines = [
        "# Key judgment eval: rule vs LLM judge",
        "",
        f"Scenarios: {len(results)}. Judge: `{model}`, {runs} run(s) per scenario. "
        f"Rule: revoke at >= {rule.REVOKE_AT} deviations, one deterministic run.",
        "`ask_human` is counted apart: it is neither a revoke nor a silent allow.",
        "",
        "## Headline",
        "",
        f"- Rule: {_headline(summary['rule'])}",
        f"- AI: {_headline(summary['ai'])}",
        f"- AI consistency: {len(results) - len(unstable)}/{len(results)} scenarios gave the same decision "
        f"on every run" + (f" (unstable: {', '.join(unstable)})" if unstable else ""),
        "",
        "## Rule per family", "", *_family_table(summary["rule"]), "",
        f"## AI per family ({ai_runs} runs)", "", *_family_table(summary["ai"]), "",
        "## Per scenario", "",
        "| Scenario | Hard | Expected | Rule | Rule deviations | AI |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        s = r.scenario
        lines.append(f"| {s.id} | {'yes' if s.hard else ''} | {s.expected} | {r.rule.decision} | "
                     f"{', '.join(r.rule.deviations) or '-'} | {_tally(r.ai)} |")

    sections = (
        ("AI misses (theft allowed, legit revoked)", lambda r, v: _wrong(r.scenario.expected, v.decision)),
        ("AI deferred to a human", lambda r, v: v.decision == "ask_human"),
        ("AI errors", lambda r, v: v.decision == "error"),
    )
    for title, keep in sections:
        rows = [(r, i, v) for r in results for i, v in enumerate(r.ai, 1) if keep(r, v)]
        lines += ["", f"## {title}", ""]
        if not rows:
            lines.append("None.")
            continue
        lines += ["| Scenario | Run | Expected | Decision | Confidence | Rationale |", "|---|---|---|---|---|---|"]
        for r, i, v in rows:
            rationale = v.rationale.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {r.scenario.id} | {i} | {r.scenario.expected} | {v.decision} | {v.confidence} | "
                         f"{rationale} |")

    lines += ["", "## Scenarios", ""]
    lines += [f"- `{s.id}` ({s.expected}{', hard' if s.hard else ''}): {s.description}" for s in
              (r.scenario for r in results)]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rule vs LLM judge on hand-written API key scenarios.")
    parser.add_argument("--runs", type=int, default=3, help="judge runs per scenario (default 3)")
    parser.add_argument("--dry-run", action="store_true", help="use a fake judge; no API key, no network")
    parser.add_argument("--effort", default="low", choices=("low", "medium", "high", "xhigh", "max"))
    parser.add_argument("--only", nargs="*", help="scenario ids to run (default: all)")
    parser.add_argument("--out", type=Path, help="write the report here instead of stdout")
    args = parser.parse_args(argv)

    scenarios = [s for s in SCENARIOS if not args.only or s.id in args.only]
    if args.dry_run:
        judge, model = FakeJudge(), "fake (dry run)"
    else:
        try:
            judge = ClaudeJudge(effort=args.effort)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        model = f"{MODEL}, effort {args.effort}"

    def progress(s: Scenario) -> Verdict:
        v = judge(s)
        print(f"{s.id}: {v.decision}", file=sys.stderr)
        return v

    report = render(evaluate(scenarios, progress, args.runs), args.runs, model)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"report written to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
