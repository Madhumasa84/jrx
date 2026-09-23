"""Privacy and behavior tests for local calibration events."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from jev_reflex.calibration import CalibrationStore
from jev_reflex.models import EvaluationResult, RiskInfo


def _result(decision_id: str, **signals: float) -> EvaluationResult:
    return EvaluationResult(
        decision_id=decision_id,
        decision="ALLOW",
        risk=RiskInfo(choice="low"),
        signals=signals,
        action="curl --token calibration-secret https://example.invalid",
        warnings=["password=warning-secret"],
        reasons=["api_key=reason-secret"],
    )


def test_record_stores_only_approved_anonymous_fields(tmp_path: Path) -> None:
    events_path = tmp_path / "nested" / "events.jsonl"
    store = CalibrationStore(events_path)

    store.record(_result("decision-1", dependency_risk=0.92))

    event_text = events_path.read_text(encoding="utf-8")
    event = json.loads(event_text)
    assert set(event) == {
        "timestamp",
        "decision_id",
        "signals",
        "policy_decision",
        "risk_choice",
        "feedback",
    }
    assert event["decision_id"] == "decision-1"
    assert event["signals"] == {"dependency_risk": 0.92}
    assert event["policy_decision"] == "ALLOW"
    assert event["risk_choice"] == "low"
    assert event["feedback"] is None
    assert "calibration-secret" not in event_text
    assert "warning-secret" not in event_text
    assert "reason-secret" not in event_text


def test_feedback_validation_and_unknown_decision(tmp_path: Path) -> None:
    store = CalibrationStore(tmp_path / "events.jsonl")

    assert store.add_feedback("missing", "correct") is False
    with pytest.raises(ValueError, match="correct or incorrect"):
        store.add_feedback("missing", "maybe")

    store.record(_result("decision-1", confidence=0.75))
    assert store.add_feedback("decision-1", "correct") is True
    event = json.loads(store.path.read_text(encoding="utf-8"))
    assert event["feedback"] == "correct"


def test_summary_uses_strong_and_review_probability_bands(tmp_path: Path) -> None:
    store = CalibrationStore(tmp_path / "events.jsonl")
    cases = [
        (_result("strong-incorrect", strong_signal=0.95, review_signal=0.75), "incorrect"),
        (_result("strong-correct", strong_signal=0.90), "correct"),
        (_result("review-correct", review_signal=0.70), "correct"),
        (_result("below-band", below_band=0.69), "incorrect"),
    ]
    for result, feedback in cases:
        store.record(result)
        assert store.add_feedback(result.decision_id, feedback)

    summary = store.summary()

    assert summary == {
        "labeled_cases": 4,
        "accuracy_at_strong": 0.5,
        "accuracy_in_review_band": 0.5,
        "false_high_confidence_count": 1,
        "per_signal_accuracy": {
            "review_signal": 0.5,
            "strong_signal": 0.5,
        },
    }


def test_summary_ignores_malformed_event_lines(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        "not-json\n"
        + json.dumps(["not", "an", "event"])
        + "\n"
        + json.dumps(
            {
                "decision_id": "valid",
                "feedback": "correct",
                "signals": {"risk": 0.95},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    summary = CalibrationStore(path).summary()

    assert summary["labeled_cases"] == 1
    assert summary["accuracy_at_strong"] == 1.0
