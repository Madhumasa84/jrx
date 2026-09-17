"""Observed decision and signal stability metrics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from statistics import fmean, pstdev
from typing import Any

from ..config import ReflexConfig
from ..evaluator import JUDGMENT_NAMES
from ..models import Decision, EvaluationResult


@dataclass(frozen=True)
class SignalStatistics:
    mean: float
    std: float
    min: float
    max: float
    threshold: float
    threshold_crossings: int
    threshold_crossing_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StabilityReport:
    runs: int
    decisions: dict[str, int]
    dominant_decision: Decision
    decision_consistency: float
    decision_flip_rate: float
    signals: dict[str, SignalStatistics]
    high_confidence_disagreement_rate: float
    degraded_runs: int

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["signals"] = {name: stats.to_dict() for name, stats in self.signals.items()}
        return value


def _crossings(values: list[float], threshold: float) -> int:
    sides = [value >= threshold for value in values]
    above = sum(sides)
    below = len(sides) - above
    if above == 0 or below == 0:
        return 0
    majority_side = above >= below
    return sum(side != majority_side for side in sides)


def _signal_threshold(name: str, config: ReflexConfig) -> float:
    if name in config.hold_on or name in {"destructive", "secret_exposure", "irreversible"}:
        return config.thresholds.strong
    return config.thresholds.review


def build_report(results: list[EvaluationResult], config: ReflexConfig) -> StabilityReport:
    """Compute metrics from results in input order, with deterministic tie handling."""

    if not results:
        raise ValueError("at least one result is required")
    decisions: dict[str, int] = {decision: 0 for decision in ("ALLOW", "REVIEW", "HOLD")}
    for result in results:
        decisions[result.decision] += 1
    order = {"HOLD": 0, "REVIEW": 1, "ALLOW": 2}
    dominant = min(
        decisions,
        key=lambda decision: (-decisions[decision], order[decision]),
    )
    consistency = max(decisions.values()) / len(results)
    names = tuple(
        dict.fromkeys(
            name for result in results for name in (tuple(JUDGMENT_NAMES) + tuple(result.signals))
        )
    )
    signal_stats: dict[str, SignalStatistics] = {}
    for name in names:
        values = [float(result.signals.get(name, 0.0)) for result in results]
        threshold = _signal_threshold(name, config)
        threshold_crossings = _crossings(values, threshold)
        signal_stats[name] = SignalStatistics(
            mean=fmean(values),
            std=pstdev(values) if len(values) > 1 else 0.0,
            min=min(values),
            max=max(values),
            threshold=threshold,
            threshold_crossings=threshold_crossings,
            threshold_crossing_rate=threshold_crossings / len(values),
        )

    high_confidence = [
        result
        for result in results
        if any(value >= config.thresholds.strong for value in result.signals.values())
    ]
    disagreements = sum(result.decision != dominant for result in high_confidence)
    return StabilityReport(
        runs=len(results),
        decisions=decisions,
        dominant_decision=dominant,  # type: ignore[arg-type]
        decision_consistency=consistency,
        decision_flip_rate=1.0 - consistency,
        signals=signal_stats,
        high_confidence_disagreement_rate=(disagreements / len(high_confidence))
        if high_confidence
        else 0.0,
        degraded_runs=sum(result.degraded for result in results),
    )
