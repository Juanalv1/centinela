"""key-judgment-eval V1: offline harness (scenarios, rule baseline, judge, report). No network."""
import sys
from collections import Counter
from types import SimpleNamespace

from conftest import ROOT

sys.path.insert(0, str(ROOT))

from evals.key_judgment import judge as jd  # noqa: E402
from evals.key_judgment import rule, run  # noqa: E402
from evals.key_judgment.scenarios import FAMILIES, SCENARIOS, by_id  # noqa: E402

SECRET = "sk-ant-test-DO-NOT-LEAK-0123456789"


def test_every_family_has_three_variants_with_its_label():
    counts = Counter(s.family for s in SCENARIOS)
    assert set(counts) == set(FAMILIES)
    assert all(n == 3 for n in counts.values())
    assert all(s.expected == FAMILIES[s.family] for s in SCENARIOS)
    assert len({s.id for s in SCENARIOS}) == len(SCENARIOS)


def test_rule_revokes_a_traveller_on_two_deviations():
    """Legit travel: new network + odd hour is already two deviations, a false revoke."""
    d = rule.decide(by_id("travel-1"))
    assert d.decision == "revoke"
    assert set(d.deviations) == {"new_network", "off_hours"}


def test_rule_allows_a_new_endpoint_alone():
    d = rule.decide(by_id("new_integration-1"))
    assert d.decision == "allow"
    assert d.deviations == ("new_endpoint",)


def test_rule_misses_a_mimic_on_the_usual_endpoints():
    assert rule.decide(by_id("mimic-1")).decision == "allow"


def test_rule_catches_a_bulk_export():
    d = rule.decide(by_id("bulk_export-1"))
    assert d.decision == "revoke"
    assert {"new_network", "new_endpoint", "paginated"} <= set(d.deviations)


class ScriptedJudge:
    """Returns decisions from a per-scenario script, cycling across runs."""

    def __init__(self, script: dict[str, list[str]], default: str = "allow"):
        self.script, self.default, self.calls = script, default, Counter()

    def __call__(self, scenario):
        seq = self.script.get(scenario.id, [self.default])
        decision = seq[self.calls[scenario.id] % len(seq)]
        self.calls[scenario.id] += 1
        return jd.Verdict(decision, "medium", f"scripted {decision} for {scenario.id}")


def test_report_counts_methods_per_family_and_keeps_ask_human_apart():
    judge = ScriptedJudge({
        "travel-1": ["revoke"],  # legit false revoke
        "travel-2": ["ask_human"],  # neither a revoke nor a silent allow
        "mimic-1": ["revoke", "allow", "revoke"],  # inconsistent
        "bulk_export-1": ["revoke"],
    })
    results = run.evaluate([by_id(i) for i in ("travel-1", "travel-2", "mimic-1", "bulk_export-1")], judge, runs=3)
    summary = run.summarize(results)

    ai_travel, ai_mimic = summary["ai"]["travel"], summary["ai"]["mimic"]
    assert ai_travel == Counter({"revoke": 3, "ask_human": 3})
    assert ai_mimic == Counter({"revoke": 2, "allow": 1})
    assert summary["rule"]["travel"] == Counter({"revoke": 2})  # one deterministic run per scenario

    report = run.render(results, runs=3, model="fake")
    assert "scripted revoke for travel-1" in report  # rationale of a false revoke
    assert "scripted allow for mimic-1" in report  # rationale of a missed theft
    assert "scripted ask_human for travel-2" in report
    assert "scripted revoke for bulk_export-1" not in report  # correct decisions are not listed
    assert "mimic-1" in run.inconsistent(results)
    assert "travel-1" not in run.inconsistent(results)


def test_judge_sees_only_profile_and_window():
    s = by_id("mimic-2")
    text = jd.render_case(s)
    assert s.id not in text and s.family not in text and s.description not in text
    assert "company:agro-llanos" in text


class FakeClient:
    def __init__(self, tool_input):
        self.sent = []
        self.messages = SimpleNamespace(create=self._create)
        self.tool_input = tool_input

    def _create(self, **kwargs):
        self.sent.append(kwargs)
        block = SimpleNamespace(type="tool_use", name="decide", input=self.tool_input)
        return SimpleNamespace(stop_reason="tool_use", content=[block], model=kwargs["model"])


def test_claude_judge_parses_the_tool_call_with_an_injected_client():
    client = FakeClient({"decision": "ask_human", "confidence": "low", "rationale": "ambiguous"})
    verdict = jd.ClaudeJudge(client=client)(by_id("travel-1"))
    assert verdict == jd.Verdict("ask_human", "low", "ambiguous")
    sent = client.sent[0]
    assert sent["model"] == "claude-sonnet-5-5"
    assert sent["tools"][0]["strict"] is True
    assert sent["tool_choice"]["type"] == "auto"


def test_claude_judge_marks_a_malformed_answer_as_error():
    client = FakeClient({"decision": "nuke", "confidence": "high", "rationale": "x"})
    assert jd.ClaudeJudge(client=client)(by_id("travel-1")).decision == "error"


def test_api_key_is_read_from_env_first_then_dotenv(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(f'OTHER=1\nANTHROPIC_API_KEY="{SECRET}"\n', encoding="utf-8")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert jd.load_api_key(env_file) == SECRET
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-env")
    assert jd.load_api_key(env_file) == "from-env"
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    assert jd.load_api_key(tmp_path / "missing.env") is None


def test_dry_run_never_prints_the_key(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    out_file = tmp_path / "report.md"
    assert run.main(["--dry-run", "--runs", "2", "--out", str(out_file)]) == 0
    printed = capsys.readouterr()
    report = out_file.read_text(encoding="utf-8")
    assert SECRET not in printed.out + printed.err + report
    assert "Theft caught" in report and "travel-1" in report


def test_judge_repr_does_not_expose_the_key():
    j = jd.ClaudeJudge(api_key=SECRET)
    assert SECRET not in repr(j) and SECRET not in str(vars(j))
