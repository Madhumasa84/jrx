from __future__ import annotations

from typing import Any

from jev_reflex.config import JEVConfig, ReflexConfig
from jev_reflex.evaluator import (
    JUDGMENT_NAMES,
    DefaultEvaluator,
    parse_system_one_response,
)
from jev_reflex.models import EvaluationContext, ProposedAction


def _response(*, destructive: float = 0.02, risk: str = "low") -> dict[str, Any]:
    answers: dict[str, Any] = {
        name: {"type": "noul", "noul": destructive if name == "destructive" else 0.02}
        for name in JUDGMENT_NAMES
    }
    answers["risk_level"] = {
        "type": "choice",
        "choice": risk,
        "confidence": 0.91,
        "probabilities": {"low": 0.91, "medium": 0.06, "high": 0.03},
    }
    answers["risk_score"] = {
        "type": "score",
        "score": 0.0 if risk == "low" else 1.0 if risk == "medium" else 2.0,
        "confidence": 0.91,
        "probabilities": {"0": 0.91, "1": 0.06, "2": 0.03},
    }
    return {"answers": answers}


class FakeGateway:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.state: dict[str, Any] | None = None
        self.questions: dict[str, Any] | None = None

    def system_one(self, state: dict[str, Any], questions: dict[str, Any]) -> Any:
        self.state = state
        self.questions = questions
        return self.response


def test_judgments_are_sent_as_structured_independent_questions() -> None:
    gateway = FakeGateway(_response())
    context = EvaluationContext(proposed_action=ProposedAction(command="pytest tests/"))
    result = DefaultEvaluator(gateway=gateway).evaluate(context)
    assert result.decision == "ALLOW"
    assert gateway.state is not None
    assert gateway.questions is not None
    assert set(JUDGMENT_NAMES).issubset(gateway.questions)
    assert type(gateway.questions["destructive"]).__name__ == "Noul"
    assert type(gateway.questions["risk_level"]).__name__ == "Choice"
    assert type(gateway.questions["risk_score"]).__name__ == "Score"


def test_redaction_happens_before_gateway_call() -> None:
    gateway = FakeGateway(_response())
    secret = "dont-send-this-value"
    context = EvaluationContext(
        user_task=f'Use password="{secret}" only for the test',
        proposed_action=ProposedAction(argv=["curl", "--password", secret]),
        external_content=f"Authorization: Bearer {secret}",
    )
    result = DefaultEvaluator(gateway=gateway).evaluate(context)
    assert result.decision == "HOLD"
    assert any(finding.check == "secret_pattern" for finding in result.deterministic_findings)
    assert gateway.state is not None
    serialized = str(gateway.state)
    assert secret not in serialized
    assert "<REDACTED_SECRET>" in serialized


def test_malformed_response_fails_safely() -> None:
    context = EvaluationContext(proposed_action=ProposedAction(command="pytest tests/"))
    advisory = DefaultEvaluator(gateway=FakeGateway({"answers": {}})).evaluate(context)
    enforce = DefaultEvaluator(
        config=ReflexConfig(mode="enforce"), gateway=FakeGateway({"answers": {}})
    ).evaluate(context)
    assert advisory.degraded is True
    assert advisory.decision == "REVIEW"
    assert enforce.degraded is True
    assert enforce.decision == "REVIEW"


def test_gateway_exception_text_never_reaches_result() -> None:
    class BrokenGateway:
        def system_one(self, state: dict[str, Any], questions: dict[str, Any]) -> Any:
            raise RuntimeError("api key=do-not-print")

    result = DefaultEvaluator(gateway=BrokenGateway()).evaluate(
        EvaluationContext(proposed_action=ProposedAction(command="pytest tests/"))
    )
    assert result.degraded is True
    assert "do-not-print" not in str(result)


def test_parser_rejects_invalid_probability() -> None:
    response = _response()
    response["answers"]["destructive"]["noul"] = 2.0
    try:
        parse_system_one_response(response)
    except ValueError as error:
        assert "range" in str(error)
    else:
        raise AssertionError("invalid response was accepted")


def test_parser_uses_the_lower_risk_primitive_confidence() -> None:
    response = _response()
    response["answers"]["risk_score"]["confidence"] = 0.42
    _, risk = parse_system_one_response(response)
    assert risk.confidence == 0.42


def test_multiple_jev_samples_are_aggregated_before_policy() -> None:
    gateway = FakeGateway(_response(destructive=0.91, risk="high"))
    result = DefaultEvaluator(
        config=ReflexConfig(jev=JEVConfig(samples=3, aggregation="median")),
        gateway=gateway,
    ).evaluate(EvaluationContext(proposed_action=ProposedAction(command="python migrate.py")))
    assert result.samples == 3
    assert result.aggregation == "median"
    assert result.signals["destructive"] == 0.91
