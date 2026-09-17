from __future__ import annotations

import json

from typer.testing import CliRunner

from jev_reflex.adapters.antigravity import antigravity_hooks_json, evaluate_antigravity_hook
from jev_reflex.adapters.deepseek import deepseek_hooks_json
from jev_reflex.adapters.openrouter import evaluate_openrouter_hook
from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig

runner = CliRunner()


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
