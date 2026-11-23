"""Starter policies and offline rule disposition overrides."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from jev_reflex.audit import AuditLog
from jev_reflex.cli import app
from jev_reflex.config import EvaluatorConfig, ReflexConfig, load_config
from jev_reflex.evaluator import evaluate_context
from jev_reflex.models import EvaluationContext, ProposedAction
from jev_reflex.policy import decide
from jev_reflex.policy_lint import lint_policy
from jev_reflex.policy_rollout import simulate


@pytest.mark.parametrize("preset", ["dev-safe", "strict-ci", "enterprise"])
def test_init_writes_valid_local_policy(tmp_path, preset):
    path = tmp_path / "custom.yaml"
    runner = CliRunner()
    result = runner.invoke(app, ["init", "--preset", preset, "--output", str(path)])
    assert result.exit_code == 0, result.output
    lint = runner.invoke(app, ["policy", "lint", "--config", str(path), "--json"])
    assert lint.exit_code == 0, lint.output
    assert json.loads(lint.output)["valid"]
    config = load_config(path)
    assert config.evaluator.provider == "local"
    assert config.mode == "enforce"
    assert config.audit.enabled
    if preset == "dev-safe":
        assert config.thresholds.review == 0.72
        assert config.rule_modes["execution_risk"] == "advisory"
        assert config.rule_modes["known_destructive"] == "enforce"
    if preset == "enterprise":
        assert config.jev.transport == "broker"
        assert config.access is not None
        assert config.signing.require_signature
        assert config.signing.private_key_path


def test_init_default_path_and_overwrite_guard(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    path = Path("reflex.yaml")
    path.write_text("original\n", encoding="utf-8")
    runner = CliRunner()
    rejected = runner.invoke(app, ["init", "--preset", "dev-safe"])
    assert rejected.exit_code != 0
    assert "--force" in rejected.output
    assert path.read_text(encoding="utf-8") == "original\n"
    written = runner.invoke(app, ["init", "--preset", "dev-safe", "--force"])
    assert written.exit_code == 0, written.output
    assert load_config(path).evaluator.provider == "local"


@pytest.mark.parametrize(
    "yaml",
    [
        b"evaluator: {provider: invalid}",
        b"evaluator: {max_tokens: 513}",
        b"evaluator: {hybrid_uncertain_low: 0.7, hybrid_uncertain_high: 0.4}",
        b"evaluator: {local_base_url: 'http://example.org:11435'}",
        b"evaluator: {local_base_url: 'http://user:secret@127.0.0.1'}",
        b"evaluator: {local_model: 'coba:68m-ternary'}",
        b"rule_modes: {missing_rule: enforce}",
        b"rule_modes: {git_risk: ignore}",
        b"rule_modes: {tamper_guard: advisory}",
    ],
)
def test_policy_lint_rejects_invalid_evaluator_or_override(yaml):
    assert not lint_policy(yaml)["valid"]


def test_evaluator_defaults_and_explicit_http_opt_in():
    config = ReflexConfig.model_validate({"jev": {"transport": "broker"}})
    assert config.evaluator.provider == "jev"
    assert config.evaluator.max_tokens == 512
    assert "evaluator" not in config.model_dump()
    assert "rule_modes" not in config.model_dump()
    for endpoint in ("http://127.0.0.1:11435", "http://[::1]:11435", "http://localhost:11435"):
        assert lint_policy(f'evaluator: {{local_base_url: "{endpoint}"}}'.encode())["valid"]
    assert lint_policy(
        b"evaluator: {local_base_url: 'http://example.org:11435', allow_non_loopback_http: true}"
    )["valid"]
    http_config = EvaluatorConfig(
        provider="local", local_base_url="http://127.0.0.1:11435", local_model="coba:68m-ternary"
    )
    assert http_config.local_model == "coba:68m-ternary"


def test_local_review_default_uses_calibrated_threshold_without_overriding_policy():
    assert ReflexConfig().thresholds.review == 0.70
    for provider in ("local", "hybrid"):
        data = {"evaluator": {"provider": provider}}
        default = ReflexConfig.model_validate(data)
        assert default.thresholds.review == 0.72 and default.thresholds.strong == 0.95
        assert decide([], {"secret_exposure": 0.71}, default).decision == "ALLOW"
        assert decide([], {"prompt_injection": 0.73}, default).decision == "REVIEW"
        explicit = ReflexConfig.model_validate(
            {**data, "thresholds": {"review": 0.70, "hold": 0.95}}
        )
        assert decide([], {"secret_exposure": 0.71}, explicit).decision == "REVIEW"


def test_rule_modes_affect_decisions_and_keep_findings_in_audit(tmp_path):
    audit = tmp_path / "audit.jsonl"
    config = ReflexConfig.model_validate(
        {
            "mode": "enforce",
            "logging": {"enabled": False},
            "audit": {"enabled": True, "path": str(audit)},
            "rule_modes": {"git_risk": "advisory", "known_destructive": "enforce"},
        }
    )

    def evaluate(command, policy=config):
        context = EvaluationContext(
            working_directory=str(tmp_path),
            repository_root=str(tmp_path),
            proposed_action=ProposedAction(command=command),
        )
        return evaluate_context(context, config=policy, use_jev=False)

    advisory = evaluate("git push --force")
    assert advisory.decision == "ALLOW"
    assert "git_risk:FORCE_PUSH" in advisory.triggered_rules
    review = config.model_copy(update={"rule_modes": {"git_risk": "review"}})
    assert evaluate("git push --force", review).decision == "REVIEW"
    assert evaluate("git reset --hard").decision == "HOLD"

    entries = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert entries[0]["policy_decision"] == "ALLOW"
    assert any(
        finding["check"] == "git_risk" and finding["triggered"]
        for finding in entries[0]["hard_rule_findings"]
    )
    assert AuditLog(config).verify()[0]


def test_check_combines_advisory_and_enforce_rules(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        "mode: enforce\nrule_modes: {git_risk: advisory, known_destructive: enforce}\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    common = ["check", "--config", str(path), "--cwd", str(tmp_path), "--no-jev", "--json"]
    advisory = runner.invoke(app, [*common, "--command", "git push --force"])
    assert advisory.exit_code == 0, advisory.output
    assert json.loads(advisory.stdout)["decision"] == "ALLOW"
    hold = runner.invoke(app, [*common, "--command", "git reset --hard"])
    assert hold.exit_code == 2, hold.output
    assert json.loads(hold.stdout)["decision"] == "HOLD"


@pytest.mark.parametrize("provider, changed_provider", [("jev", "local"), ("local", "jev")])
def test_policy_impact_replays_rule_modes_and_rejects_new_evaluator(
    tmp_path, provider, changed_provider
):
    audit = tmp_path / "audit.jsonl"
    baseline = ReflexConfig.model_validate(
        {
            "mode": "enforce",
            "evaluator": {"provider": provider},
            "audit": {"enabled": True, "path": str(audit)},
        }
    )
    context = EvaluationContext(
        working_directory=str(tmp_path),
        repository_root=str(tmp_path),
        proposed_action=ProposedAction(command="git push --force"),
    )
    assert evaluate_context(context, config=baseline, use_jev=False).decision == "HOLD"
    candidate = baseline.model_copy(update={"rule_modes": {"git_risk": "advisory"}})
    replay = simulate(audit, baseline, candidate)
    assert replay["replayed"] == 1
    assert replay["changes"]["HOLD_to_ALLOW"] == 1

    new_evaluator = baseline.model_copy(
        update={"evaluator": EvaluatorConfig(provider=changed_provider)}
    )
    with pytest.raises(ValueError, match="cannot replay configuration changes: evaluator"):
        simulate(audit, baseline, new_evaluator)


@pytest.mark.parametrize("provider", ["local", "hybrid"])
def test_policy_impact_rejects_changes_to_local_semantic_collection(tmp_path, provider):
    baseline = ReflexConfig.model_validate(
        {"evaluator": {"provider": provider}, "review_on": ["needs_tests", "tests_needed"]}
    )
    audit = tmp_path / "unused.jsonl"
    for candidate in (
        baseline.model_copy(update={"review_on": ["needs_tests"]}),
        baseline.model_copy(update={"rule_modes": {"scope_creep": "review"}}),
    ):
        with pytest.raises(ValueError, match="evaluator.active_signals"):
            simulate(audit, baseline, candidate)


def test_policy_impact_rejects_changes_to_hybrid_fallback_collection(tmp_path):
    baseline = ReflexConfig(evaluator=EvaluatorConfig(provider="hybrid"))
    candidate = baseline.model_copy(update={"rule_modes": {"destructive": "advisory"}})
    with pytest.raises(ValueError, match="evaluator.hybrid_fallback_signals"):
        simulate(tmp_path / "unused.jsonl", baseline, candidate)


def test_semantic_rule_modes_apply_to_requested_and_default_signals():
    config = ReflexConfig.model_validate(
        {
            "mode": "enforce",
            "evaluator": {"provider": "local"},
            "rule_modes": {
                "destructive": "advisory",
                "prompt_injection": "review",
                "goal_hijack_diff": "enforce",
            },
        }
    )
    observed = decide([], {"destructive": 0.98}, config)
    assert observed.decision == "ALLOW"
    assert observed.triggered_rules
    assert decide([], {"prompt_injection": 0.98}, config).decision == "REVIEW"
    assert decide([], {"goal_hijack_diff": 0.98}, config).decision == "HOLD"


def test_rule_modes_preserve_conservative_threshold_review():
    config = ReflexConfig.model_validate(
        {
            "mode": "enforce",
            "stability_policy": {"mode": "conservative"},
            "stability": {"boundary_margin": 0.025},
            "rule_modes": {"destructive": "enforce"},
        }
    )
    for probability in (0.69, 0.91):
        result = decide([], {"destructive": probability}, config)
        assert result.decision == "REVIEW"
        assert result.triggered_rules[0].startswith("BOUNDARY_UNCERTAIN")
