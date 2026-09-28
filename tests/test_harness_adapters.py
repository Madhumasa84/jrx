from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from jev_reflex.adapters.antigravity import (
    antigravity_hooks_json,
    evaluate_antigravity_hook,
)
from jev_reflex.adapters.claude_code import evaluate_claude_code_hook
from jev_reflex.adapters.codex import evaluate_codex_hook
from jev_reflex.adapters.deepseek import deepseek_hooks_json, evaluate_deepseek_hook
from jev_reflex.adapters.generic import context_from_hook_payload
from jev_reflex.adapters.openrouter import evaluate_openrouter_hook
from jev_reflex.adapters.pi import evaluate_pi_hook
from jev_reflex.audit import AuditLog
from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig
from jev_reflex.evaluator import evaluate_context

runner = CliRunner()


def _adapter_payload(name: str, command: str) -> dict[str, object]:
    if name == "antigravity":
        return {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": command, "Cwd": "."},
            }
        }
    if name == "openrouter":
        return {
            "hookName": "PermissionRequest",
            "toolName": "bash",
            "toolInput": {"command": command},
            "cwd": ".",
        }
    if name == "pi":
        return {"toolName": "bash", "input": {"command": command}, "cwd": "."}
    return {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": ".",
    }


ADAPTERS = (
    ("codex", evaluate_codex_hook),
    ("claude", evaluate_claude_code_hook),
    ("antigravity", evaluate_antigravity_hook),
    ("openrouter", evaluate_openrouter_hook),
    ("pi", evaluate_pi_hook),
    ("deepseek", evaluate_deepseek_hook),
)


def test_antigravity_cli_maps_nested_tool_call_to_deny() -> None:
    event = {
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "rm -rf ./cache", "Cwd": "."},
        },
        "workspacePaths": ["."],
    }
    result = runner.invoke(
        app,
        ["antigravity-hook", "--demo", "--mode", "enforce"],
        input=json.dumps(event),
    )
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)
    assert body["decision"] == "deny"
    assert body["reason"]


def test_antigravity_hook_loads_policy_from_documented_workspace_paths(
    tmp_path, monkeypatch
) -> None:
    decoy = tmp_path / "decoy"
    workspace = tmp_path / "workspace"
    decoy.mkdir()
    workspace.mkdir()
    (decoy / "reflex.yaml").write_text("mode: advisory\n", encoding="utf-8")
    (workspace / "reflex.yaml").write_text("mode: enforce\n", encoding="utf-8")
    monkeypatch.chdir(decoy)
    event = {
        "conversationId": "synthetic-antigravity-session",
        "workspacePaths": [str(workspace)],
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "rm -rf ./cache",
                "Cwd": str(workspace),
            },
        },
    }

    result = runner.invoke(
        app,
        ["antigravity-hook", "--demo"],
        input=json.dumps(event),
    )

    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["decision"] == "deny"


def test_antigravity_hook_fails_closed_without_workspace_identity() -> None:
    event = {
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "echo harmless"},
        }
    }
    result = runner.invoke(app, ["antigravity-hook"], input=json.dumps(event))
    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["decision"] == "deny"


def test_openrouter_permission_request_can_ask_for_review() -> None:
    result, output = evaluate_openrouter_hook(
        {
            "hookName": "PermissionRequest",
            "toolName": "bash",
            "toolInput": {"command": "pip install package"},
        },
        config=ReflexConfig(mode="enforce"),
        demo=True,
    )
    assert result.decision == "REVIEW"
    assert output["decision"] == "ask_user"


def test_antigravity_review_uses_uncached_user_confirmation() -> None:
    _result, output = evaluate_antigravity_hook(
        {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "pip install package"},
            }
        },
        config=ReflexConfig(mode="enforce"),
        demo=True,
    )
    assert output["decision"] == "force_ask"


def test_native_hook_audit_correlation_is_hashed_and_excluded_from_jev_state(
    tmp_path,
) -> None:
    session_id = "synthetic-codex-session-reference"
    config = ReflexConfig(
        mode="enforce",
        audit={"enabled": True, "path": str(tmp_path / "audit.jsonl")},
    )
    event = {
        "session_id": session_id,
        "tool_use_id": "synthetic-call-1",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf .jrx-delete-fixture && touch marker"},
        "cwd": str(tmp_path),
    }

    context = context_from_hook_payload(event, config=config, provider_key="codex")
    serialized = json.dumps(
        {"model": context.model_dump(mode="json"), "jev": context.to_jev_state()}
    )
    assert session_id not in serialized
    assert "hook_audit" not in context.model_dump(mode="json")
    assert context.hook_audit is not None

    result = evaluate_context(context, config=config, use_jev=False)
    assert result.decision == "HOLD"
    entry = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    correlation = entry["hook_correlation"]
    assert correlation["provider"] == "codex"
    assert (
        correlation["session_sha256"]
        == __import__("hashlib").sha256(session_id.encode()).hexdigest()
    )
    assert correlation["tool_name"] == "Bash"
    assert len(correlation["action_sha256"]) == 64
    assert correlation["call_sha256"]
    assert session_id not in json.dumps(entry)
    assert AuditLog(config).verify()[0]


@pytest.mark.parametrize(
    ("provider_key", "event", "tool_name"),
    [
        (
            "antigravity",
            {
                "conversationId": "synthetic-antigravity-conversation",
                "stepIdx": 4,
                "toolCall": {
                    "name": "write_to_file",
                    "args": {"TargetFile": "fixture.py", "CodeContent": "safe"},
                },
                "workspacePaths": ["."],
            },
            "write_to_file",
        ),
    ],
)
def test_antigravity_hook_correlation_uses_native_session_shape(
    tmp_path, provider_key, event, tool_name
) -> None:
    event["workspacePaths"] = [str(tmp_path)]
    context = context_from_hook_payload(event, config=ReflexConfig(), provider_key=provider_key)
    assert context.hook_audit is not None
    assert context.hook_audit.provider == provider_key
    assert context.hook_audit.tool_name == tool_name
    assert "synthetic-antigravity-conversation" not in json.dumps(context.to_jev_state())


def test_openrouter_pre_tool_blocks_review_without_approval_surface() -> None:
    _result, output = evaluate_openrouter_hook(
        {"toolName": "bash", "toolInput": {"command": "pip install package"}},
        config=ReflexConfig(mode="enforce"),
        demo=True,
    )
    assert "block" in output


def test_pi_cli_maps_tool_call_to_block() -> None:
    result = runner.invoke(
        app,
        ["pi-hook", "--demo", "--mode", "enforce"],
        input=json.dumps({"toolName": "bash", "input": {"command": "rm -rf ./cache"}, "cwd": "."}),
    )
    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["block"] is True


def test_deepseek_cli_keeps_codex_bridge_response_shape() -> None:
    result = runner.invoke(
        app,
        ["deepseek-hook", "--demo", "--mode", "enforce"],
        input=json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf ./cache"}, "cwd": "."}
        ),
    )
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_native_config_helpers_target_the_new_hook_commands() -> None:
    antigravity = antigravity_hooks_json()
    deepseek = deepseek_hooks_json()
    assert antigravity["jev-reflex"]["PreToolUse"][0]["hooks"][0]["command"] == (
        "jev-reflex antigravity-hook"
    )
    assert deepseek["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == ("jev-reflex deepseek-hook")


@pytest.mark.parametrize("name,evaluator", ADAPTERS)
def test_all_adapters_hold_the_same_destructive_action(name, evaluator) -> None:
    result, output = evaluator(
        _adapter_payload(name, "rm -rf ./cache"),
        config=ReflexConfig(mode="enforce"),
        demo=True,
    )
    assert result.decision == "HOLD"
    if name in {"codex", "claude", "deepseek"}:
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    elif name == "antigravity":
        assert output["decision"] == "deny"
    elif name == "openrouter":
        assert output["decision"] == "deny"
    else:
        assert output["block"] is True


@pytest.mark.parametrize("name,evaluator", ADAPTERS)
def test_all_adapters_review_the_same_dependency_action(name, evaluator) -> None:
    result, output = evaluator(
        _adapter_payload(name, "pip install package"),
        config=ReflexConfig(mode="enforce"),
        demo=True,
    )
    assert result.decision == "REVIEW"
    if name == "claude":
        assert output["hookSpecificOutput"]["permissionDecision"] == "ask"
    elif name == "antigravity":
        assert output["decision"] == "force_ask"
    elif name == "codex":
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    elif name == "openrouter":
        assert output["decision"] == "ask_user"
    elif name == "pi":
        assert output["block"] is True
    else:
        assert "additionalContext" in output["hookSpecificOutput"]


def test_codex_review_fails_closed_when_native_hook_cannot_ask() -> None:
    result, output = evaluate_codex_hook(
        _adapter_payload("codex", "pip install package"),
        config=ReflexConfig(mode="enforce"),
        demo=True,
    )
    assert result.decision == "REVIEW"
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize(
    "command",
    [
        "codex-hook",
        "claude-code-hook",
        "antigravity-hook",
        "openrouter-hook",
        "pi-hook",
        "deepseek-hook",
    ],
)
def test_empty_native_hook_event_is_denied(command: str) -> None:
    result = runner.invoke(app, [command, "--demo", "--mode", "enforce"], input="{}")
    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert "deny" in json.dumps(body) or "block" in json.dumps(body)
