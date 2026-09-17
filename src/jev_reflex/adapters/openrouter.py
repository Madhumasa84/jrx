"""OpenRouter Agent SDK lifecycle-hook adapter."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..config import ReflexConfig
from ..models import EvaluationResult
from .harness import (
    evaluate_harness_hook,
    hook_error_reason,
    permission_decision,
    should_block,
)


def _event_name(payload: Mapping[str, Any]) -> str:
    for name in ("hook_name", "hookName", "event", "event_name", "eventName"):
        value = payload.get(name)
        if isinstance(value, str):
            return value
    return "PreToolUse"


def _is_permission_request(event: str) -> bool:
    normalized = event.replace("_", "").replace("-", "").lower()
    return normalized == "permissionrequest"


def openrouter_hook_response(
    result: EvaluationResult,
    config: ReflexConfig,
    *,
    event: str = "PreToolUse",
    reason: str | None = None,
) -> dict[str, Any]:
    """Map policy output to OpenRouter's pre-tool and approval hook results."""

    message = reason or result.reason_summary()
    if config.mode == "advisory":
        return {}
    if _is_permission_request(event):
        decision = permission_decision(result, config)
        output: dict[str, Any] = {"decision": "ask_user" if decision == "ask" else decision}
        if output["decision"] != "allow":
            output["reason"] = message
        return output if output["decision"] != "allow" or result.decision != "ALLOW" else {}

    if should_block(result, config, review_supported=False):
        return {"block": message}
    return {}


def evaluate_openrouter_hook(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    demo: bool = False,
    event: str | None = None,
) -> tuple[EvaluationResult, dict[str, Any]]:
    """Evaluate an OpenRouter Agent SDK lifecycle payload."""

    result, reason = evaluate_harness_hook(payload, config=config, demo=demo)
    return result, openrouter_hook_response(
        result,
        config,
        event=event or _event_name(payload),
        reason=reason,
    )


def openrouter_hook_error(*, event: str = "PreToolUse") -> dict[str, Any]:
    """Return a fail-safe OpenRouter hook result."""

    reason = hook_error_reason()
    if _is_permission_request(event):
        return {"decision": "deny", "reason": reason}
    return {"block": reason}
