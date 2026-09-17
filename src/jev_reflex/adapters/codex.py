"""Native Codex PreToolUse adapter."""

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


def codex_hook_response(result: EvaluationResult, config: ReflexConfig) -> dict[str, Any]:
    """Map policy output to the currently supported Codex hook response shape."""

    reason = hook_context(result)
    should_block = result.decision == "HOLD" or (result.degraded and config.mode != "advisory")
    # Codex currently documents deny/allow for PreToolUse; ask is parsed but not supported.
    if config.mode == "review" and result.decision == "REVIEW":
        should_block = True
    if config.mode == "advisory":
        should_block = False

    if should_block:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    if result.decision != "ALLOW" or result.warnings:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": reason,
            }
        }
    return {}


def evaluate_codex_hook(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    demo: bool = False,
) -> tuple[EvaluationResult, dict[str, Any]]:
    context = context_from_hook_payload(payload, config=config)
    evaluator = DemoEvaluator(config) if demo else DefaultEvaluator(config)
    result = evaluator.evaluate(context)
    return result, codex_hook_response(result, config)


def codex_hooks_json(command: str = "jev-reflex codex-hook") -> dict[str, Any]:
    """Return a copyable native Codex hook declaration."""

    return {
        "description": "JEV Reflex deterministic execution control",
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash|apply_patch|mcp__.*",
                    "hooks": [{"type": "command", "command": command, "timeout": 30}],
                }
            ]
        },
    }
