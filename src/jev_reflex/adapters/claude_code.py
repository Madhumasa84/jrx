"""Native Claude Code PreToolUse adapter."""

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


def claude_code_hook_response(result: EvaluationResult, config: ReflexConfig) -> dict[str, Any]:
    reason = hook_context(result)
    verdict = host_verdict(result, config, can_ask=True)
    if config.mode == "advisory" and verdict == "proceed":
        return pretooluse_context(result, reason)
    output: dict[str, Any] = {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
    if verdict != "proceed":
        # Claude Code supports an explicit ask decision for PreToolUse. JRX never
        # sends "allow", which would skip Claude Code's own permission prompt.
        output["hookSpecificOutput"]["permissionDecision"] = verdict
        output["hookSpecificOutput"]["permissionDecisionReason"] = reason
    return output


def evaluate_claude_code_hook(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    demo: bool = False,
) -> tuple[EvaluationResult, dict[str, Any]]:
    result, _reason = evaluate_harness_hook(
        payload, config=config, demo=demo, provider_key="claude"
    )
    return result, claude_code_hook_response(result, config)


def claude_code_settings_json(command: str = "jev-reflex claude-code-hook") -> dict[str, Any]:
    """Return a copyable native Claude Code settings declaration."""

    return {
        "hooks": {
            "PreToolUse": [
                {
                    # Kept equal to workspace.hooks._MATCHERS["claude"] (tested).
                    "matcher": "Bash|Edit|MultiEdit|Write|NotebookEdit|mcp__.*",
                    # Block the call if the hook cannot answer (crash, timeout).
                    "hooks": [
                        {
                            "type": "command",
                            "command": command,
                            "timeout": 30,
                            "onFailure": "block",
                        }
                    ],
                }
            ],
            "PostToolUse": [
                {
                    # Every tool whose output can surface a secret records taint.
                    "matcher": "Bash|Read|Grep|WebFetch|mcp__.*",
                    "hooks": [{"type": "command", "command": command, "timeout": 30}],
                }
            ],
        }
    }
