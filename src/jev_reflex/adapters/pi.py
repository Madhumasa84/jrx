"""Pi coding-agent extension-hook adapter."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..config import ReflexConfig
from ..models import EvaluationResult
from .harness import evaluate_harness_hook, hook_error_reason, should_block


def pi_hook_response(
    result: EvaluationResult,
    config: ReflexConfig,
    *,
    reason: str | None = None,
) -> dict[str, Any]:
    """Map policy output to Pi's ``tool_call`` extension result."""

    if not should_block(result, config, review_supported=False):
        return {}
    return {"block": True, "reason": reason or result.reason_summary()}


def evaluate_pi_hook(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    demo: bool = False,
) -> tuple[EvaluationResult, dict[str, Any]]:
    """Evaluate a Pi ``tool_call`` event payload."""

    result, reason = evaluate_harness_hook(payload, config=config, demo=demo)
    return result, pi_hook_response(result, config, reason=reason)


def pi_hook_error() -> dict[str, Any]:
    """Return a fail-safe Pi extension result."""

    return {"block": True, "reason": hook_error_reason()}
