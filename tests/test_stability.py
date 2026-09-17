from __future__ import annotations

import pytest

from jev_reflex.config import ReflexConfig, StabilityConfig, StabilityPolicyConfig
from jev_reflex.evaluator import aggregate_semantic_samples, evaluate_context
from jev_reflex.models import (
    EvaluationContext,
    EvaluationResult,
    ProposedAction,
    RiskInfo,
    SemanticSignals,
)
from jev_reflex.stability import StabilityRunner, build_report


def _result(decision: str, destructive: float) -> EvaluationResult:
    return EvaluationResult(
        decision=decision,  # type: ignore[arg-type]
        risk=RiskInfo(choice="low"),
        signals={"destructive": destructive, "human_review": 0.02},
    )


def test_stability_metrics_measure_decisions_and_threshold_crossings() -> None:
    report = build_report(
        [_result("HOLD", 0.89), _result("REVIEW", 0.91), _result("HOLD", 0.92)],
        ReflexConfig(),
    )
    assert report.runs == 3
    assert report.decisions == {"ALLOW": 0, "REVIEW": 1, "HOLD": 2}
    assert report.dominant_decision == "HOLD"
    assert report.decision_consistency == 2 / 3
    assert report.decision_flip_rate == pytest.approx(1 / 3)
    assert report.signals["destructive"].threshold_crossings == 1
    assert report.signals["destructive"].threshold_crossing_rate == 1 / 3
    assert report.signals["destructive"].min == 0.89
    assert report.signals["destructive"].max == 0.92


def test_stability_runner_repeats_the_same_context() -> None:
    seen: list[EvaluationContext] = []

    def evaluator(context: EvaluationContext) -> EvaluationResult:
        seen.append(context)
        return _result("ALLOW", 0.02)

    context = EvaluationContext(proposed_action=ProposedAction(command="pytest tests/"))
    report = StabilityRunner(evaluator, ReflexConfig()).run(context, 4)
    assert report.decision_consistency == 1.0
    assert len(seen) == 4
    assert all(item is context for item in seen)


def test_median_aggregation_is_deterministic() -> None:
    samples = [
        SemanticSignals(
            probabilities={"destructive": value},
            risk=RiskInfo(choice="medium", score=1.0, confidence=0.9),
            source="demo",
        )
        for value in (0.91, 0.88, 0.92)
    ]
    result = aggregate_semantic_samples(samples, aggregation="median")
    assert result.probabilities["destructive"] == 0.91
    assert result.risk.score == 1.0
    assert result.risk.confidence == 0.9


def test_conservative_boundary_promotes_near_hold_signal_to_review() -> None:
    config = ReflexConfig(
        hold_on=["destructive"],
        stability=StabilityConfig(boundary_margin=0.03),
        stability_policy=StabilityPolicyConfig(mode="conservative"),
    )
    context = EvaluationContext(proposed_action=ProposedAction(command="python migrate.py"))
    semantic = SemanticSignals(
        probabilities={"destructive": 0.905},
        risk=RiskInfo(choice="medium", score=1.0, confidence=0.95),
        source="demo",
    )

    class FixedSemantic:
        def evaluate(self, _: EvaluationContext) -> SemanticSignals:
            return semantic

    result = evaluate_context(context, config=config, semantic_evaluator=FixedSemantic())
    assert result.decision == "REVIEW"
    assert any("BOUNDARY_UNCERTAIN" in rule for rule in result.triggered_rules)


def test_majority_policy_requires_explicit_multiple_samples() -> None:
    config = ReflexConfig(stability_policy=StabilityPolicyConfig(mode="majority"))
    context = EvaluationContext(proposed_action=ProposedAction(command="pytest tests/"))
    semantic = SemanticSignals(probabilities={}, risk=RiskInfo(choice="low"), source="demo")

    class FixedSemantic:
        def evaluate(self, _: EvaluationContext) -> SemanticSignals:
            return semantic

    try:
        evaluate_context(context, config=config, semantic_evaluator=FixedSemantic())
    except ValueError as error:
        assert "at least two" in str(error)
    else:
        raise AssertionError("majority mode accepted a single sample")
