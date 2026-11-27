"""Native Google Antigravity ``PreToolUse`` adapter."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..config import ReflexConfig
from ..models import EvaluationResult
from .harness import (
    evaluate_harness_hook,
    hook_error_reason,
    host_verdict,
)


def antigravity_hook_response(
    result: EvaluationResult,
    config: ReflexConfig,
    *,
    reason: str | None = None,
) -> dict[str, Any]:
    """Map JEV Reflex policy to Antigravity's allow/ask/deny contract."""

    # "allow" delegates to the next hook or Antigravity's default policy; it is not
    # auto-approval. A review must remain an explicit user decision even when
    # Antigravity has a cached "Always Allow" permission, hence "force_ask".
    decision = {"proceed": "allow", "ask": "force_ask", "deny": "deny"}[
        host_verdict(result, config, can_ask=True)
    ]
    output: dict[str, Any] = {"decision": decision}
    if reason and (decision != "allow" or result.decision != "ALLOW" or result.warnings):
        output["reason"] = reason
    return output


def evaluate_antigravity_hook(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    demo: bool = False,
) -> tuple[EvaluationResult, dict[str, Any]]:
    """Evaluate an Antigravity hook event."""

    result, reason = evaluate_harness_hook(
        payload, config=config, demo=demo, provider_key="antigravity"
    )
    return result, antigravity_hook_response(result, config, reason=reason)


def antigravity_hook_error() -> dict[str, Any]:
    """Return a fail-safe response for malformed input or configuration."""

    return {"decision": "deny", "reason": hook_error_reason()}


def antigravity_hooks_json(command: str = "jev-reflex antigravity-hook") -> dict[str, Any]:
    """Return a copyable Antigravity ``hooks.json`` declaration."""

    return {
        "jev-reflex": {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [{"type": "command", "command": command, "timeout": 30}],
                }
            ]
        }
    }
