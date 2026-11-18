import json

import pytest

from jev_reflex.config import ReflexConfig
from jev_reflex.evaluator import JEVSemanticEvaluator, compact_state, evaluate_context
from jev_reflex.models import EvaluationContext, ProposedAction
from jev_reflex.policy import decide, execution_allowed
from jev_reflex.policy_source import PolicyMerger


@pytest.mark.parametrize(
    "action",
    [
        ProposedAction(command="deploy production", input={"padding": "x" * 60_000}),
        ProposedAction(argv=["deploy", "production"], input={"padding": "x" * 60_000}),
    ],
)
def test_large_input_preserves_executable_action(action: ProposedAction) -> None:
    state = compact_state(EvaluationContext(proposed_action=action), 50_000)
    assert state["proposed_action"]["command"] == action.command
    assert state["proposed_action"]["argv"] == action.argv
    assert len(json.dumps(state, ensure_ascii=False, separators=(",", ":"))) <= 50_000


def test_redaction_failure_blocks_execution_with_semantics_disabled(monkeypatch) -> None:
    context = EvaluationContext(proposed_action=ProposedAction(command="echo hello"))
    monkeypatch.setattr(
        "jev_reflex.evaluator._redacted_context_with_gitleaks", lambda _: (context, True)
    )
    result = evaluate_context(context, config=ReflexConfig(mode="enforce"), use_jev=False)
    assert result.degraded
    assert not execution_allowed(result.decision, mode="enforce", degraded=result.degraded)


def test_semantic_redaction_failure_has_no_api_request(monkeypatch) -> None:
    context = EvaluationContext(proposed_action=ProposedAction(command="echo hello"))
    monkeypatch.setattr(
        "jev_reflex.evaluator._redacted_context_with_gitleaks", lambda _: (context, True)
    )

    class Gateway:
        last_api_requests = 1

    evaluator = JEVSemanticEvaluator(gateway=Gateway())
    assert evaluator.evaluate(context).degraded
    assert evaluator.last_api_requests == 0


def test_local_enforce_cannot_allow_central_review_action() -> None:
    central = ReflexConfig(mode="review")
    merged = PolicyMerger.merge_policies(central, ReflexConfig(mode="enforce"))
    decision = decide([], {"security_sensitive": 0.8}, merged)
    assert not execution_allowed(decision.decision, mode=merged.mode)


def test_local_review_cannot_enable_override_of_central_enforce_hold() -> None:
    central = ReflexConfig(mode="enforce", policy={"allow_hold_override": False})
    merged = PolicyMerger.merge_policies(central, ReflexConfig(mode="review"))
    # CLI review mode offers confirmation for HOLD; enforce refuses an override
    # when allow_hold_override is false. Retain that central enforcement mode.
    assert merged.mode == "enforce"
    assert merged.policy.allow_hold_override is False
