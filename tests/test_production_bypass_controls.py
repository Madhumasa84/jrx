"""Controlled-runner acceptance checks through the public command entry points."""

from __future__ import annotations

import json
import os
import shlex
import sys
import uuid
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import yaml
from typer.testing import CliRunner

from jev_reflex import cli
from jev_reflex.audit import AuditLog
from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig, load_config
from jev_reflex.evaluator import JUDGMENT_NAMES, direct_semantic_backend
from jev_reflex.model_files import pull_model
from jev_reflex.models import RiskInfo, SemanticSignals
from test_broker import running_broker
from test_enterprise_approval import _repo
from test_enterprise_approval import oidc as oidc
from test_local_models import hf as hf

runner = CliRunner()


@pytest.fixture
def directory(monkeypatch):
    with TemporaryDirectory(prefix="jrx-production-") as directory:
        root = Path(directory).resolve()
        monkeypatch.setenv("HOME", str(root))
        monkeypatch.setenv("JRX_SESSION_ID", "runner-session")
        monkeypatch.delenv("JRX_APPROVAL_ID", raising=False)
        monkeypatch.delenv("JRX_ENVIRONMENT", raising=False)
        yield root


@pytest.fixture
def production(directory):
    repo = _repo(directory)
    path = directory / "reflex.yaml"
    result = runner.invoke(app, ["init", "--preset", "production", "--output", str(path)])
    assert result.exit_code == 0, result.output
    settings = yaml.safe_load(path.read_text())
    settings["audit"]["path"] = str(directory / "audit.jsonl")
    settings["session"]["path"] = str(directory / "sessions.sqlite3")
    settings["access"].update(
        issuer="https://idp.example",
        jwks_uri="https://idp.example/jwks",
        approval_db=str(directory / "approvals.sqlite3"),
    )
    for rule in settings["access"]["rules"]:
        rule["repositories"] = [str(repo)]
    settings["sandbox"]["image"] = f"runner/worker@sha256:{'12' * 32}"
    path.write_text(yaml.safe_dump(settings))
    return path, repo, settings


def lint(path):
    result = runner.invoke(
        app, ["policy", "lint", "--profile", "production", "-c", str(path), "--json"]
    )
    return result.exit_code, json.loads(result.stdout)


def test_production_preset_lints_after_filling_placeholders(production, directory):
    path, _, _ = production
    code, report = lint(path)
    assert code == 0, report
    assert report["valid"]
    scaffold = directory / "scaffold.yaml"
    assert (
        runner.invoke(app, ["init", "--preset", "production", "--output", str(scaffold)]).exit_code
        == 0
    )
    code, report = lint(scaffold)
    assert code == 1
    assert {"production_oidc_endpoint", "production_review_scope", "production_sandbox_image"} <= {
        issue["code"] for issue in report["issues"]
    }


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("mode", "review", "production_mode"),
        ("audit.enabled", False, "production_audit_disabled"),
        ("audit.fail_closed", False, "production_audit_fail_open"),
        ("audit.path", "", "production_audit_path"),
        ("policy.strict_review", False, "production_strict_review"),
        ("policy.allow_hold_override", True, "production_hold_override"),
        ("session.enabled", False, "production_session_disabled"),
        ("session.pin_protected_files", False, "production_protected_file_drift"),
        ("session.track_secret_taint", False, "production_secret_taint"),
        ("session.max_semantic_spend_usd", 0.001, "production_session_budget"),
        ("session.max_risky_attempts", 0, "invalid_value"),
        ("access", None, "production_oidc_required"),
        ("access.jwks_uri", None, "invalid_value"),
        ("access.issuer", "https://idp.example.com", "production_oidc_endpoint"),
        ("access.roles_claim", "", "production_oidc_claims"),
        ("access.production_environments", [], "production_dual_review"),
        (
            "access.rules",
            [
                {
                    "role": "jrx-operator",
                    "actions": ["execute"],
                    "repositories": ["*"],
                    "environments": ["production"],
                }
            ],
            "production_review_scope",
        ),
        ("sandbox.enabled", False, "production_sandbox_disabled"),
        ("sandbox.image", "runner/worker:latest", "production_sandbox_image"),
        ("jev.transport", "direct", "production_broker_required"),
        ("evaluator.require_semantic", False, "production_semantic_required"),
        ("evaluator.allow_non_loopback_http", True, "production_evaluator_http"),
        ("evaluator.local_base_url", "http://receiver.invalid", "invalid_value"),
        ("evaluator.provider", "demo", "invalid_value"),
        ("privacy.redact_secrets", False, "production_redaction_disabled"),
        ("rule_modes.tamper_guard", "advisory", "host_guard_mode"),
        (
            "local_checks.protected_path_allowlist",
            ["AGENTS.md"],
            "production_protected_path_exception",
        ),
    ],
)
def test_lint_rejects_weakened_controls(production, field, value, code):
    path, _, settings = production
    parent, _, key = field.rpartition(".")
    target = settings.setdefault(parent, {}) if parent else settings
    target[key] = value
    path.write_text(yaml.safe_dump(settings))
    exit_code, report = lint(path)
    assert exit_code == 1 and not report["valid"]
    assert code in {issue["code"] for issue in report["issues"]}, report


def test_lint_hides_invalid_credentials_and_unknown_field_names(production):
    path, _, settings = production
    sample = uuid.uuid4().hex
    settings["evaluator"]["local_base_url"] = f"https://fixture:{sample}@receiver.invalid"
    settings[sample] = sample
    path.write_text(yaml.safe_dump(settings))
    exit_code, report = lint(path)
    assert exit_code == 1
    assert sample not in json.dumps(report)


def test_explicit_hold_exception_is_lintable(production):
    path, _, settings = production
    settings["policy"].update(
        allow_hold_override=True, hold_override_exception="Break-glass incident approval"
    )
    path.write_text(yaml.safe_dump(settings))
    assert lint(path)[0] == 0


def test_production_lint_flags_standard_profile(production):
    path, _, settings = production
    settings.pop("profile")
    path.write_text(yaml.safe_dump(settings))
    exit_code, report = lint(path)
    assert exit_code == 0
    assert any(issue["code"] == "production_profile_inactive" for issue in report["issues"])


def test_production_lint_accepts_exactly_funded_batch(production):
    path, _, settings = production
    settings["jev"]["samples"] = 35
    settings["session"]["max_semantic_spend_usd"] = 0.35
    path.write_text(yaml.safe_dump(settings))
    assert lint(path)[0] == 0


def test_production_lint_rejects_matching_relative_scopes(production):
    path, _, settings = production
    for rule in settings["access"]["rules"]:
        rule["repositories"] = ["team/checkout"]
    path.write_text(yaml.safe_dump(settings))
    exit_code, report = lint(path)
    assert exit_code == 1
    assert any(issue["code"] == "production_checkout_scope" for issue in report["issues"])


def test_production_lint_rejects_dotted_oidc_placeholders(production):
    path, _, settings = production
    settings["access"].update(
        issuer="https://idp.example.com.", jwks_uri="https://idp.example.com./keys"
    )
    path.write_text(yaml.safe_dump(settings))
    exit_code, report = lint(path)
    assert exit_code == 1
    assert {
        issue["path"] for issue in report["issues"] if issue["code"] == "production_oidc_endpoint"
    } == {
        "access.issuer",
        "access.jwks_uri",
    }


def test_doctor_reports_missing_production_controls(production, monkeypatch):
    path, repo, settings = production
    monkeypatch.setattr("jev_reflex.workspace.ui.detect_providers", lambda _: ())
    args = ["doctor", "--workspace", str(repo), "--config", str(path), "--json"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["production_policy"]["valid"]
    settings["audit"]["fail_closed"] = False
    path.write_text(yaml.safe_dump(settings))
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "production_audit_fail_open" in result.stdout


def test_explicit_strict_review_denies_without_enterprise_identity(directory, monkeypatch):
    path = directory / "reflex.yaml"
    path.write_text("mode: enforce\npolicy: {strict_review: true}\n")
    dispatched = []
    monkeypatch.setattr(cli, "_execute_argv", lambda *args: dispatched.append(args) or 0)
    with running_broker(evaluator=SemanticJudge(risk="medium")) as (broker, _):
        with path.open("a") as config:
            config.write(
                yaml.safe_dump({"jev": {"transport": "broker", "socket": broker.jev.socket}})
            )
        args = ["exec", "--config", str(path), "--cwd", str(directory)]
        review = runner.invoke(app, [*args, "--json", "--", "echo", "ok"], input="yes\n")
        assert review.exit_code == 2
        assert json.loads(review.stdout)["decision"] == "REVIEW"
        for flag in (["--yes"], ["-y"], ["--approver", "test-label"], ["--non-interactive"]):
            denied = runner.invoke(app, [*args, *flag, "--", "echo", "ok"])
            assert denied.exit_code == 2
            assert "strict review" in denied.output.lower()
        hook = runner.invoke(
            app,
            ["claude-code-hook", "--config", str(path)],
            input=json.dumps(
                {"cwd": str(directory), "tool_name": "Bash", "tool_input": {"command": "echo ok"}}
            ),
        )
        assert json.loads(hook.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert not dispatched


def test_required_override_write_failure_blocks_execution(directory, monkeypatch):
    path = directory / "reflex.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "mode": "review",
                "audit": {
                    "enabled": True,
                    "fail_closed": True,
                    "path": str(directory / "audit.jsonl"),
                },
            }
        )
    )
    dispatched = []
    monkeypatch.setattr(cli, "_execute_argv", lambda *args: dispatched.append(args) or 0)

    def disk_full(*args, **kwargs):
        raise OSError("injected failure")

    monkeypatch.setattr(AuditLog, "write_human_override", disk_full)
    result = runner.invoke(
        app,
        [
            "exec",
            "--config",
            str(path),
            "--cwd",
            str(directory),
            "--no-jev",
            "--yes",
            "--approver",
            "test-label",
            "--",
            "echo",
            "ok",
        ],
    )
    assert result.exit_code == 2, result.output
    assert "audit" in result.output.lower()
    assert not dispatched


class SemanticJudge:
    def __init__(self, *, risk="low"):
        self.risk = risk

    def evaluate(self, context):
        return SemanticSignals(
            probabilities=dict.fromkeys(JUDGMENT_NAMES, 0.01),
            risk=RiskInfo(choice=self.risk, confidence=0.99),
            source="jev",
        )


@pytest.fixture
def dispatched(monkeypatch):
    dispatched = []
    monkeypatch.setattr(cli, "_execute_argv", lambda *args: dispatched.append(args) or 0)
    return dispatched


def use_jev(settings):
    settings["evaluator"]["provider"] = "jev"
    settings["hold_on"].remove("goal_hijack_diff")


@pytest.fixture
def reviewed(production, dispatched):
    path, repo, settings = production
    use_jev(settings)
    with running_broker(evaluator=SemanticJudge(risk="medium")) as (broker, _):
        settings["jev"]["socket"] = broker.jev.socket
        path.write_text(yaml.safe_dump(settings))
        yield path, repo


def scope_for(path, repo):
    return ["--config", str(path), "--cwd", str(repo), "--environment", "production"]


def request_approval(scope, oidc, command):
    oidc("requester", ["jrx-operator", "jrx-reviewer"])
    request = runner.invoke(app, ["approval", "request", *scope, "--command", shlex.join(command)])
    assert request.exit_code == 0, request.output
    return request.stdout.strip()


def grant_command(path, approval_id):
    return ["approval", "grant", approval_id, "--config", str(path)]


def fully_approved(path, repo, oidc, command):
    approval_id = request_approval(scope_for(path, repo), oidc, command)
    for reviewer in ("reviewer-one", "reviewer-two"):
        oidc(reviewer, ["jrx-reviewer"])
        assert runner.invoke(app, grant_command(path, approval_id)).exit_code == 0
    oidc("requester", ["jrx-operator"])
    return approval_id


def test_production_approval_is_independent_single_use_and_audited(
    reviewed, dispatched, oidc, directory, monkeypatch
):
    path, repo = reviewed
    command = ["echo", "ok"]
    scope = scope_for(path, repo)
    oidc("requester", ["jrx-operator", "jrx-reviewer"])
    args = ["exec", *scope, "--json"]
    missing = runner.invoke(app, [*args, "--", *command])
    assert missing.exit_code == 2
    assert json.loads(missing.stdout)["decision"] == "REVIEW"
    for flag in (
        ["--yes"],
        ["--approver", "test-label"],
        ["--no-jev"],
        ["--demo"],
        ["--mode", "advisory"],
    ):
        assert runner.invoke(app, [*args, *flag, "--", *command]).exit_code == 2
    approval_id = request_approval(scope, oidc, command)
    grant = grant_command(path, approval_id)
    assert runner.invoke(app, grant).exit_code == 2
    oidc("reviewer-one", ["jrx-reviewer"])
    assert runner.invoke(app, grant).exit_code == 0
    assert runner.invoke(app, grant).exit_code == 2
    oidc("requester", ["jrx-operator", "jrx-reviewer"])
    monkeypatch.setenv("JRX_APPROVAL_ID", approval_id)
    assert runner.invoke(app, [*args, "--", *command]).exit_code == 2
    oidc("reviewer-two", ["jrx-reviewer"])
    assert runner.invoke(app, grant).exit_code == 0
    oidc("requester", ["jrx-operator", "jrx-reviewer"])
    assert runner.invoke(app, [*args, "--", *command]).exit_code == 0
    assert runner.invoke(app, [*args, "--", *command]).exit_code == 2
    assert len(dispatched) == 1
    records = [json.loads(line) for line in (directory / "audit.jsonl").read_text().splitlines()]
    assert [
        record["approval_id"] for record in records if record.get("event_type") == "human_override"
    ] == [approval_id]
    assert AuditLog(load_config(path)).verify()[0]


def test_approval_binds_command_directory_environment_and_git(
    reviewed, dispatched, oidc, monkeypatch
):
    path, repo = reviewed
    command = ["echo", "ok"]
    alternate = repo / "alternate"
    alternate.mkdir()
    approval_id = fully_approved(path, repo, oidc, command)

    def invoke(argv=command, cwd=repo, environment="production"):
        return runner.invoke(
            app,
            [
                "exec",
                "--config",
                str(path),
                "--cwd",
                str(cwd),
                "--environment",
                environment,
                "--approval-id",
                approval_id,
                "--",
                *argv,
            ],
        )

    assert invoke(argv=["echo", "changed"]).exit_code == 2
    assert invoke(cwd=alternate).exit_code == 2
    assert invoke(environment="development").exit_code == 2
    with monkeypatch.context() as changed:
        changed.setenv("FIXTURE_EXECUTION_MODE", "changed")
        assert invoke().exit_code == 2
    tracked = repo / "tracked.txt"
    original = tracked.read_bytes()
    tracked.write_bytes(b"changed")
    assert invoke().exit_code == 2
    assert not dispatched
    tracked.write_bytes(original)
    assert invoke().exit_code == 0
    assert len(dispatched) == 1


@pytest.mark.parametrize("failure", ["decision", "approval", "corrupt_chain"])
def test_audit_error_blocks_review_and_leaves_approval_unspent(
    reviewed, dispatched, oidc, directory, monkeypatch, failure
):
    path, repo = reviewed
    command = ["echo", "ok"]
    approval_id = fully_approved(path, repo, oidc, command)
    args = ["exec", *scope_for(path, repo), "--approval-id", approval_id, "--", *command]
    audit = directory / "audit.jsonl"

    def unavailable(*args, **kwargs):
        raise OSError("injected failure")

    with monkeypatch.context() as failing:
        if failure == "corrupt_chain":
            audit.write_text("damaged\n")
            audit.chmod(0o600)
        else:
            method = "write_entry" if failure == "decision" else "write_human_override"
            failing.setattr(AuditLog, method, unavailable)
        result = runner.invoke(app, args)
        assert result.exit_code == 2, result.output
        assert "audit write failed" in result.output.lower()
        assert not dispatched
    if failure == "corrupt_chain":
        audit.unlink()
    assert runner.invoke(app, args).exit_code == 0
    assert len(dispatched) == 1


@pytest.mark.parametrize("failure", ["read_only", "write_error"])
def test_failed_required_audit_blocks_an_allowed_action(
    production, dispatched, oidc, directory, monkeypatch, failure
):
    path, repo, settings = production
    use_jev(settings)
    oidc("requester", ["jrx-operator"])
    audit = directory / "audit.jsonl"
    if failure == "read_only":
        audit.touch(mode=0o400)
        if os.geteuid() == 0:
            pytest.skip("root can write owner-read-only files")
    else:

        def unavailable(*args, **kwargs):
            raise OSError("injected failure")

        monkeypatch.setattr(AuditLog, "write_entry", unavailable)
    with running_broker(evaluator=SemanticJudge()) as (broker, _):
        settings["jev"]["socket"] = broker.jev.socket
        path.write_text(yaml.safe_dump(settings))
        result = runner.invoke(app, ["exec", *scope_for(path, repo), "--json", "--", "echo", "ok"])
    assert result.exit_code == 2
    assert "audit_unavailable" in json.loads(result.stdout)["triggered_rules"]
    assert not dispatched


@pytest.mark.parametrize("program", ["touch", "rm"])
@pytest.mark.parametrize(
    "protected",
    [
        ".claude/settings.json",
        ".codex/hooks.json",
        ".agents/hooks.json",
        "CLAUDE.md",
        "AGENTS.md",
        "reflex.yaml",
        ".git/hooks/pre-commit",
    ],
)
def test_production_never_dispatches_protected_file_writes(
    production, dispatched, oidc, program, protected
):
    path, repo, _ = production
    oidc("requester", ["jrx-operator"])
    result = runner.invoke(
        app, ["exec", *scope_for(path, repo), "--json", "--", program, protected]
    )
    assert result.exit_code == 2, result.output
    report = json.loads(result.stdout)
    assert report["decision"] == "HOLD"
    assert any(rule.startswith("tamper_guard:") for rule in report["triggered_rules"])
    assert not dispatched


def test_protected_file_drift_in_production_session(production, dispatched, oidc):
    path, repo, settings = production
    use_jev(settings)
    oidc("requester", ["jrx-operator"])
    protected = repo / "AGENTS.md"
    protected.write_text("original")
    with running_broker(evaluator=SemanticJudge()) as (broker, _):
        settings["jev"]["socket"] = broker.jev.socket
        path.write_text(yaml.safe_dump(settings))
        args = ["exec", *scope_for(path, repo), "--json", "--", "echo", "ok"]
        assert runner.invoke(app, args).exit_code == 0
        protected.write_text("modified")
        result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "tamper_guard:PROTECTED_PATH_DRIFT" in json.loads(result.stdout)["triggered_rules"]
    assert len(dispatched) == 1


def test_host_credentials_stay_out_of_broker_mediated_execution(
    production, oidc, directory, monkeypatch
):
    path, repo, settings = production
    use_jev(settings)
    oidc("requester", ["jrx-operator"])
    keys = ("TYPESAFE_API_KEY", "JRX_BROKER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN")
    for key in keys:
        monkeypatch.setenv(key, uuid.uuid4().hex)
    report = directory / "docker-invocations.jsonl"
    probe = directory / "docker-probe"
    probe.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"keys = {(*keys, 'JRX_ID_TOKEN')!r}\n"
        f"with open({str(report)!r}, 'a') as stream:\n"
        "    stream.write(json.dumps([sys.argv[1:], [key for key in keys if key in os.environ]]) + '\\n')\n"
    )
    probe.chmod(0o700)
    settings["sandbox"]["docker_binary"] = str(probe)
    with running_broker(evaluator=SemanticJudge()) as (broker, _):
        settings["jev"]["socket"] = broker.jev.socket
        path.write_text(yaml.safe_dump(settings))
        result = runner.invoke(app, ["exec", *scope_for(path, repo), "--json", "--", "echo", "ok"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["semantic_source"] == "broker/live"
    (run_argv, leaked), (cleanup_argv, cleanup_leaked) = [
        json.loads(line) for line in report.read_text().splitlines()
    ]
    assert not leaked and not cleanup_leaked
    assert run_argv[run_argv.index("--network") + 1] == "none"
    assert {"--read-only", "no-new-privileges"} <= set(run_argv)
    assert run_argv.count("--mount") == 1
    assert run_argv[run_argv.index("--mount") + 1] == f"type=bind,src={repo},dst={repo}"
    assert "--env" not in run_argv
    assert cleanup_argv[:2] == ["rm", "--force"]


def test_post_tool_use_taint_blocks_direct_and_indirect_execution(production, dispatched, oidc):
    path, repo, _ = production
    oidc("requester", ["jrx-operator"])
    sample = f"fixture-{uuid.uuid4().hex}"
    recorded = runner.invoke(
        app,
        ["post-tool-use", "--config", str(path)],
        input=json.dumps(
            {
                "cwd": str(repo),
                "tool_name": "Read",
                "tool_input": {"file_path": ".env"},
                "tool_response": {"stdout": f"APP_CREDENTIAL={sample}"},
            }
        ),
    )
    assert recorded.exit_code == 0
    cases = [
        (["echo", sample], "RECORDED_SECRET_MATCH"),
        (["curl", "https://receiver.invalid"], "TAINTED_SESSION_EGRESS"),
        (["python", "-c", "import subprocess"], "TAINTED_SESSION_EXECUTION"),
        (["sh", "script.sh"], "TAINTED_SESSION_EXECUTION"),
    ]
    for command, reason in cases:
        result = runner.invoke(app, ["exec", *scope_for(path, repo), "--json", "--", *command])
        assert result.exit_code == 2, result.output
        report = json.loads(result.stdout)
        assert (
            report["decision"] == "HOLD"
            and f"taint_exfiltration:{reason}" in report["triggered_rules"]
        )
        assert sample not in result.output
    assert not dispatched


class MalformedJudge:
    def evaluate(self, context):
        return SemanticSignals(probabilities={}, risk=RiskInfo(choice="low"), source="jev")


@pytest.mark.parametrize("failure", ["unreachable", "malformed", "corrupt_onnx"])
def test_degraded_semantic_evaluation_cannot_be_approved(
    production, dispatched, oidc, directory, hf, failure
):
    path, repo, settings = production
    if failure == "corrupt_onnx":
        cache = directory / "models"
        settings["evaluator"].update(model_dir=str(cache), provider="hybrid")
        installed = pull_model(
            settings["evaluator"].get("local_model", ReflexConfig().evaluator.local_model), cache
        )
        installed.graph.write_bytes(b"corrupted weights")
        config = ReflexConfig.model_validate(settings)
        judge = direct_semantic_backend(config)
    else:
        use_jev(settings)
        config = ReflexConfig.model_validate(settings)
        judge = MalformedJudge()
    broker = (
        nullcontext(None)
        if failure == "unreachable"
        else running_broker(evaluator=judge, config=config)
    )
    with broker as listening:
        settings["jev"]["socket"] = (
            listening[0].jev.socket if listening else str(directory / "missing.sock")
        )
        path.write_text(yaml.safe_dump(settings))
        command = ["echo", "ok"]
        approval_id = fully_approved(path, repo, oidc, command)
        result = runner.invoke(
            app,
            [
                "exec",
                *scope_for(path, repo),
                "--approval-id",
                approval_id,
                "--json",
                "--",
                *command,
            ],
        )
    assert result.exit_code == 2, result.output
    report = json.loads(result.stdout)
    assert report["degraded"] and "evaluation_unavailable" in report["triggered_rules"]
    assert not dispatched
