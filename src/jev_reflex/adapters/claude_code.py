"""Native Claude Code PreToolUse adapter."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..config import ReflexConfig
from ..evaluator import DefaultEvaluator, DemoEvaluator
from ..formatters import hook_context
from ..models import EvaluationResult
from .generic import context_from_hook_payload


def _hook_error() -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "JEV Reflex could not parse the hook input; action denied safely.",
        }
    }


def claude_code_hook_response(result: EvaluationResult, config: ReflexConfig) -> dict[str, Any]:
    reason = hook_context(result)
    output: dict[str, Any] = {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
    specific = output["hookSpecificOutput"]

    if config.mode == "advisory":
        if result.decision != "ALLOW" or result.warnings:
            specific["additionalContext"] = reason
        return output if len(specific) > 1 else {}

    if result.decision == "HOLD":
        specific["permissionDecision"] = "deny"
        specific["permissionDecisionReason"] = reason
    elif result.degraded:
        specific["permissionDecision"] = "deny"
        specific["permissionDecisionReason"] = reason
    elif result.decision == "REVIEW":
        # Claude Code supports an explicit ask decision for PreToolUse.
        specific["permissionDecision"] = "ask"
        specific["permissionDecisionReason"] = reason
    return output


def evaluate_claude_code_hook(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    demo: bool = False,
) -> tuple[EvaluationResult, dict[str, Any]]:
    context = context_from_hook_payload(payload, config=config)
    evaluator = DemoEvaluator(config) if demo else DefaultEvaluator(config)
    result = evaluator.evaluate(context)
    return result, claude_code_hook_response(result, config)


def claude_code_settings_json(command: str = "jev-reflex claude-code-hook") -> dict[str, Any]:
    """Return a copyable native Claude Code settings declaration."""

    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash|Edit|Write|mcp__.*",
                    "hooks": [{"type": "command", "command": command, "timeout": 30}],
                }
            ]
        }
    }
