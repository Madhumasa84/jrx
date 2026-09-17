"""Repeated-evaluation runner for observed decision stability."""

from __future__ import annotations

from collections.abc import Callable

from ..config import ReflexConfig
from ..models import EvaluationContext, EvaluationResult
from .metrics import StabilityReport, build_report


class StabilityRunner:
    """Run the same evaluator repeatedly and measure final-control stability."""

    def __init__(
        self,
        evaluator: Callable[[EvaluationContext], EvaluationResult],
        config: ReflexConfig,
    ) -> None:
        self.evaluator = evaluator
        self.config = config

    def run(self, context: EvaluationContext, repetitions: int) -> StabilityReport:
        if repetitions < 1:
            raise ValueError("repetitions must be at least 1")
        results = [self.evaluator(context) for _ in range(repetitions)]
        return build_report(results, self.config)


__all__ = ["StabilityReport", "StabilityRunner", "build_report"]
