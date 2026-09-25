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


def test_feedback_does_not_lose_concurrent_append(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    path = tmp_path / "events.jsonl"
    feedback_store = CalibrationStore(path)
    recorder = CalibrationStore(path)
    recorder.record(_result("first"))
    snapshot_ready = Event()
    release_feedback = Event()
    writer_started = Event()
    writer_finished = Event()
    read = feedback_store._read

    def paused_read():
        rows = read()
        snapshot_ready.set()
        assert release_feedback.wait(5)
        return rows

    def record():
        writer_started.set()
        recorder.record(_result("second"))
        writer_finished.set()

    monkeypatch.setattr(feedback_store, "_read", paused_read)
    with ThreadPoolExecutor(max_workers=2) as pool:
        feedback = pool.submit(feedback_store.add_feedback, "first", "correct")
        try:
            assert snapshot_ready.wait(5)
            append = pool.submit(record)
            assert writer_started.wait(5)
            # A competing writer must wait until the read-modify-replace completes.
            assert not writer_finished.wait(0.2)
        finally:
            release_feedback.set()
        assert feedback.result(timeout=5)
        append.result(timeout=5)
    rows = recorder._read()
    assert [row["decision_id"] for row in rows] == ["first", "second"]
    assert rows[0]["feedback"] == "correct"


def test_failed_feedback_replace_preserves_data_and_releases_lock(tmp_path, monkeypatch):
    import os

    store = CalibrationStore(tmp_path / "events.jsonl")
    store.record(_result("first"))
    original = store.path.read_bytes()
    replace = os.replace

    def fail_replace(*args):
        raise OSError("injected write failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected"):
        store.add_feedback("first", "correct")
    assert store.path.read_bytes() == original
    assert not list(tmp_path.glob("events-*.jsonl"))
    monkeypatch.setattr(os, "replace", replace)
    assert store.add_feedback("first", "correct")
    store.record(_result("second"))
    assert len(store._read()) == 2
