"""Native Codex PreToolUse adapter."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..config import ReflexConfig
from ..formatters import hook_context
from ..models import EvaluationResult
from .harness import (
    evaluate_harness_hook,
    hook_error_reason,
    host_verdict,
    pretooluse_context,
    pretooluse_denial,
)


def _hook_error() -> dict[str, Any]:
    return pretooluse_denial(hook_error_reason())


def codex_hook_response(result: EvaluationResult, config: ReflexConfig) -> dict[str, Any]:
    """Map policy output to the currently supported Codex hook response shape."""

    return codex_shaped_response(result, config, hook_context(result))


def codex_shaped_response(
    result: EvaluationResult, config: ReflexConfig, reason: str
) -> dict[str, Any]:
    """The Codex PreToolUse contract, which parses but does not support "ask".

    A REVIEW in an enforcing mode is therefore denied, and additionalContext is only
    informational: it does not stop the call. DeepSeek's bridge speaks the same contract.
    """

    if host_verdict(result, config, can_ask=False) == "deny":
        return pretooluse_denial(reason)
    return pretooluse_context(result, reason)


def evaluate_codex_hook(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    demo: bool = False,
) -> tuple[EvaluationResult, dict[str, Any]]:
    result, reason = evaluate_harness_hook(payload, config=config, demo=demo, provider_key="codex")
    return result, codex_shaped_response(result, config, reason)


def codex_hooks_json(command: str = "jev-reflex codex-hook") -> dict[str, Any]:
    """Return a copyable native Codex hook declaration."""

    return {
        "description": "JEV Reflex deterministic execution control",
        "hooks": {
            "PreToolUse": [
                {
                    # Kept equal to workspace.hooks._MATCHERS["codex"] (tested).
                    "matcher": "Bash|exec_command|shell_command|apply_patch|mcp__.*",
                    "hooks": [{"type": "command", "command": command, "timeout": 30}],
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "Bash|Read|exec_command|shell_command|mcp__.*",
                    "hooks": [{"type": "command", "command": command, "timeout": 30}],
                }
            ],
        },
    }
