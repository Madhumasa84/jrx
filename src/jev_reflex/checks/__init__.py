"""Deterministic, model-free checks used before semantic evaluation."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from functools import partial
from typing import Protocol

from ..config import ReflexConfig
from ..models import DeterministicFinding, EvaluationContext
from . import (
    destructive,
    execution,
    filesystem,
    git_risk,
    repo_boundary,
    safe_commands,
    secrets,
    supply_chain,
    tamper,
)


class DeterministicCheck(Protocol):
    """A pure check that returns reproducible findings without network/model calls."""

    def evaluate(self, context: EvaluationContext) -> list[DeterministicFinding]: ...


class FunctionCheck:
    """Adapt a module-level check function to the public check protocol."""

    def __init__(self, function: Callable[[EvaluationContext], list[DeterministicFinding]]) -> None:
        self._function = function

    def evaluate(self, context: EvaluationContext) -> list[DeterministicFinding]:
        return self._function(context)


DEFAULT_CHECKS: tuple[DeterministicCheck, ...] = tuple(
    FunctionCheck(function)
    for function in (
        secrets.evaluate,
        destructive.evaluate,
        repo_boundary.evaluate,
        git_risk.evaluate,
        filesystem.evaluate,
        safe_commands.evaluate,
        execution.evaluate,
        supply_chain.evaluate,
        tamper.evaluate,
    )
)


def run_deterministic_checks(
    context: EvaluationContext,
    checks: Sequence[DeterministicCheck] = DEFAULT_CHECKS,
    *,
    config: ReflexConfig | None = None,
) -> list[DeterministicFinding]:
    """Run checks in a fixed order and return only structured, non-secret findings."""

    findings: list[DeterministicFinding] = []
    if checks is DEFAULT_CHECKS and config is not None:
        checks = (
            *DEFAULT_CHECKS[:-2],
            FunctionCheck(partial(supply_chain.evaluate, config=config)),
            FunctionCheck(partial(tamper.evaluate, config=config)),
        )
    for check in checks:
        findings.extend(check.evaluate(context))
    return findings


def has_blocking_finding(findings: Iterable[DeterministicFinding]) -> bool:
    return any(finding.triggered and finding.blocking for finding in findings)


class DeterministicChecks:
    """Composable collection of deterministic checks."""

    def __init__(self, checks: Sequence[DeterministicCheck] = DEFAULT_CHECKS) -> None:
        self.checks = tuple(checks)

    def evaluate(self, context: EvaluationContext) -> list[DeterministicFinding]:
        return run_deterministic_checks(context, self.checks)


__all__ = [
    "DEFAULT_CHECKS",
    "DeterministicCheck",
    "DeterministicChecks",
    "FunctionCheck",
    "has_blocking_finding",
    "run_deterministic_checks",
]
