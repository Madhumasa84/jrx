"""Shared evaluation and decision helpers for native harness integrations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from ..config import ReflexConfig
from ..evaluator import DefaultEvaluator, DemoEvaluator
from ..formatters import hook_context
from ..models import EvaluationResult
from ..policy import execution_allowed, host_guard_denied
from .generic import context_from_hook_payload


def evaluate_harness_hook(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    demo: bool = False,
    provider_key: str | None = None,
) -> tuple[EvaluationResult, str]:
    """Evaluate one native tool event and return its safe hook explanation."""

    context = context_from_hook_payload(payload, config=config, provider_key=provider_key)
    evaluator = DemoEvaluator(config) if demo else DefaultEvaluator(config)
    result = evaluator.evaluate(context)
    return result, hook_context(result)


Verdict = Literal["proceed", "ask", "deny"]


def host_verdict(result: EvaluationResult, config: ReflexConfig, *, can_ask: bool) -> Verdict:
    """What the host must do with a policy result. Every hook adapter uses this mapping.

    ``proceed``: JRX does not stop the call; the host's own permission flow still decides,
    and no adapter turns this into an explicit grant. ``ask``: the host must put the call
    to the user. ``deny``: the host must refuse it. A REVIEW the host cannot ask about is
    denied; host-guard findings deny in every mode.
    """

    if host_guard_denied(result):
        return "deny"
    if execution_allowed(result.decision, mode=config.mode, degraded=result.degraded):
        return "proceed"
    if (
        result.decision == "REVIEW"
        and not result.degraded
        and can_ask
        and not config.strict_review_required
    ):
        return "ask"
    return "deny"


def pretooluse_denial(reason: str) -> dict[str, Any]:
    """The PreToolUse deny response shared by Claude Code, Codex and DeepSeek."""

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def pretooluse_context(result: EvaluationResult, reason: str) -> dict[str, Any]:
    """Informational PreToolUse output for a call JRX does not stop."""

    if result.decision != "ALLOW" or result.warnings:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": reason}}
    return {}


def hook_error_reason() -> str:
    """Return a stable, non-sensitive reason for malformed hook input."""

    return "JEV Reflex could not parse the hook input; action denied safely."
