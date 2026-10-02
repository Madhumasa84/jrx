"""Disposable full-path reproductions from the production audit."""

from io import BytesIO
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from jev_reflex.audit import AuditLog
from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig, load_config
from jev_reflex.context import RepositoryContextProvider
from jev_reflex.evaluator import evaluate_context
from jev_reflex.mcp_gateway import MCPGateway
from jev_reflex.models import ProposedAction
from jev_reflex.policy import PolicyDecision, execution_allowed


def test_enforce_unavailable_judge_cannot_be_overridden_with_yes(tmp_path, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    marker = tmp_path / "executed"
    result = CliRunner().invoke(
        app,
        ["exec", "--mode", "enforce", "--cwd", str(tmp_path), "--yes", "--", "touch", str(marker)],
    )
    assert result.exit_code == 2, result.output
    assert not marker.exists()


def test_redaction_failure_remains_degraded_without_semantic(tmp_path, monkeypatch):
    import jev_reflex.evaluator as evaluator

    context = RepositoryContextProvider(cwd=tmp_path).build(
        user_task="", proposed_action=ProposedAction(command="echo hello")
    )
    monkeypatch.setattr(evaluator, "_redacted_context_with_gitleaks", lambda ctx: (ctx, True))
    config = ReflexConfig(mode="enforce")
    result = evaluate_context(context, config=config, use_jev=False)
    assert result.degraded
    assert not execution_allowed(result.decision, mode="enforce", degraded=result.degraded)


def test_audit_append_rejects_symlink(tmp_path):
    target = tmp_path / "target"
    target.touch(mode=0o600)
    link = tmp_path / "audit"
    link.symlink_to(target)
    log = AuditLog(ReflexConfig(audit={"enabled": True, "path": str(link)}))
    with pytest.raises((OSError, ValueError)):
        log.write_entry("echo hello", [], {}, PolicyDecision("ALLOW", (), ()))
    assert not target.read_bytes()


def test_config_rejects_duplicate_security_keys(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("mode: enforce\nmode: advisory\n")
    with pytest.raises(ValueError):
        load_config(path)


def test_config_rejects_misspelled_security_keys(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("mode: enforce\npolicy:\n  allow_hold_overide: true\n")
    with pytest.raises(ValueError):
        load_config(path)


@pytest.mark.parametrize(
    "command",
    [
        "git -c color.ui=false reset --hard",
        "git branch --force --delete old",
        "git -c color.ui=false branch -D old",
        "git -c color.ui=false push --force",
    ],
)
def test_destructive_git_variants_hold_in_full_pipeline(tmp_path, command):
    context = RepositoryContextProvider(cwd=tmp_path).build(
        user_task="", proposed_action=ProposedAction(command=command)
    )
    result = evaluate_context(context, config=ReflexConfig(mode="enforce"), use_jev=False)
    assert result.decision == "HOLD"


def test_mcp_duplicate_method_cannot_bypass_gateway(tmp_path):
    # A parser accepting the last duplicate sees ping; another upstream parser
    # may see tools/call. Ambiguous protocol messages must never be forwarded.
    instance = MCPGateway(ReflexConfig(), "test", ["unused"], sink=BytesIO())
    downstream = BytesIO()
    process = SimpleNamespace(stdin=downstream, poll=lambda: None)
    instance._handle(process, b'{"id":1,"method":"tools/call","method":"ping"}\n')
    assert not downstream.getvalue()


def test_required_audit_failure_blocks_enforce(tmp_path, monkeypatch):
    context = RepositoryContextProvider(cwd=tmp_path).build(
        user_task="", proposed_action=ProposedAction(command="echo hello")
    )
    monkeypatch.setattr(AuditLog, "write_entry", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    config = ReflexConfig(mode="enforce", audit={"enabled": True, "path": str(tmp_path / "audit")})
    result = evaluate_context(context, config=config, use_jev=False)
    assert result.degraded
    assert result.decision == "HOLD"


@pytest.mark.parametrize(
    "command",
    [
        "echo ready\nrm -rf ./cache",
        "find . -exec rm -r {} +",
        "echo $(rm -rf ./cache)",
        "sh -c 'git -c color.ui=false reset --hard'",
    ],
)
def test_explicit_nested_destructive_commands_hold(tmp_path, command):
    context = RepositoryContextProvider(cwd=tmp_path).build(
        user_task="", proposed_action=ProposedAction(command=command)
    )
    assert (
        evaluate_context(context, config=ReflexConfig(mode="enforce"), use_jev=False).decision
        == "HOLD"
    )


def test_docker_context_excludes_local_credentials():
    from pathlib import Path

    ignore = (Path(__file__).resolve().parents[1] / ".dockerignore").read_text().splitlines()
    assert ".env" in ignore or ".env*" in ignore
    assert ".aws" in ignore
