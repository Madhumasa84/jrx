"""Shared evaluation and decision helpers for native harness integrations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..config import ReflexConfig
from ..evaluator import DefaultEvaluator, DemoEvaluator
from ..formatters import hook_context
from ..models import EvaluationResult
from .generic import context_from_hook_payload


def evaluate_harness_hook(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    demo: bool = False,
) -> tuple[EvaluationResult, str]:
    """Evaluate one native tool event and return its safe hook explanation."""

    context = context_from_hook_payload(payload, config=config)
    evaluator = DemoEvaluator(config) if demo else DefaultEvaluator(config)
    result = evaluator.evaluate(context)
    return result, hook_context(result)


def should_block(result: EvaluationResult, config: ReflexConfig, *, review_supported: bool) -> bool:
    """Apply the configured execution mode to a harness that can block calls."""

    if config.mode == "advisory":
        return False
    if result.degraded or result.decision == "HOLD":
        return True
    return result.decision == "REVIEW" and not review_supported


def permission_decision(result: EvaluationResult, config: ReflexConfig) -> str:
    """Map the public policy result to a host with allow/ask/deny controls."""

    if config.mode == "advisory":
        return "allow"
    if result.degraded or result.decision == "HOLD":
        return "deny"
    if result.decision == "REVIEW":
        return "ask"
    return "allow"


def hook_error_reason() -> str:
    """Return a stable, non-sensitive reason for malformed hook input."""

    return "JEV Reflex could not parse the hook input; action denied safely."
