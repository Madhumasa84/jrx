"""DeepSeek Harness hook adapter.

DeepSeek Harness currently bridges Codex and Claude Code command-hook
protocols. This adapter exposes an explicit command name while retaining the
Codex-shaped response that the DeepSeek hook bridge understands.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..config import ReflexConfig
from ..models import EvaluationResult
from .harness import evaluate_harness_hook, hook_error_reason


def deepseek_hook_response(
    result: EvaluationResult,
    config: ReflexConfig,
    *,
    reason: str | None = None,
) -> dict[str, Any]:
    """Map policy output to the Codex-compatible DeepSeek bridge contract."""

    message = reason or result.reason_summary()
    should_block = result.decision == "HOLD" or (result.degraded and config.mode != "advisory")
    if config.mode == "review" and result.decision == "REVIEW":
        should_block = True
    if config.mode == "advisory":
        should_block = False

    if should_block:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        }
    if result.decision != "ALLOW" or result.warnings:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": message,
            }
        }
    return {}


def evaluate_deepseek_hook(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    demo: bool = False,
) -> tuple[EvaluationResult, dict[str, Any]]:
    """Evaluate a DeepSeek Harness Codex-bridge payload."""

    result, reason = evaluate_harness_hook(payload, config=config, demo=demo)
    return result, deepseek_hook_response(result, config, reason=reason)


def deepseek_hook_error() -> dict[str, Any]:
    """Return a fail-safe DeepSeek bridge response."""

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": hook_error_reason(),
        }
    }


def deepseek_hooks_json(command: str = "jev-reflex deepseek-hook") -> dict[str, Any]:
    """Return a Codex-dialect config usable by DeepSeek's hook bridge."""

    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": command, "timeout": 30}],
                }
            ]
        }
    }
