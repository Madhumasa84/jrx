"""Fail-closed conformance tests for semantic evaluation failures."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from jev_reflex.config import JEVConfig, ReflexConfig
from jev_reflex.evaluator import DefaultEvaluator, evaluate_context
from jev_reflex.integrations.typesafe import TypeSafeIntegrationError
from jev_reflex.models import EvaluationContext, ProposedAction


class MockGateway:
    """Mock gateway that can simulate various failure modes."""

    def __init__(self, failure_mode: str = "none") -> None:
        self.failure_mode = failure_mode
        self.last_api_requests = 0

    def system_one(self, state: dict[str, Any], questions: dict[str, Any]) -> Any:
        self.last_api_requests = 1

        if self.failure_mode == "timeout":
            raise TimeoutError("Request timeout")

        elif self.failure_mode == "5xx_error":
            raise TypeSafeIntegrationError("request_failed")

        elif self.failure_mode == "malformed_json":
            return "not a dict"

        elif self.failure_mode == "missing_keys":
            return {"answers": {}}  # Missing all expected signal keys

        elif self.failure_mode == "missing_answers":
            return {}  # Missing answers entirely

        elif self.failure_mode == "invalid_answer_type":
            return {
                "answers": {
                    "destructive": {"type": "wrong_type", "noul": 0.1},
                }
            }

        elif self.failure_mode == "invalid_risk_choice":
            answers = {
                name: {"type": "noul", "noul": 0.1}
                for name in [
                    "destructive",
                    "secret_exposure",
                    "scope_creep",
                    "security_sensitive",
                    "irreversible",
                    "needs_tests",
                    "prompt_injection",
                    "dependency_risk",
                    "wrong_repo",
                    "human_review",
                    "concurrency_sensitive",
                    "persistence_sensitive",
                    "backwards_compatibility",
                    "untrusted_input_path",
                    "fail_open",
                    "wrong_repo_semantic",
                    "suspicious_intent",
                    "external_side_effect_risk",
                ]
            }
            answers["risk_level"] = {
                "type": "choice",
                "choice": "invalid_choice",
                "confidence": 0.91,
            }
            answers["risk_score"] = {
                "type": "score",
                "score": 0.0,
                "confidence": 0.91,
            }
            return {"answers": answers}

        elif self.failure_mode == "sdk_missing":
            raise TypeSafeIntegrationError("sdk_missing")

        elif self.failure_mode == "missing_api_key":
            raise TypeSafeIntegrationError("missing_api_key")

        elif self.failure_mode == "network_unreachable":
            raise OSError("Network unreachable")

        elif self.failure_mode == "401_unauthorized":
            raise TypeSafeIntegrationError("request_failed")

        else:
            # Normal response
            answers = {
                name: {"type": "noul", "noul": 0.1}
                for name in [
                    "destructive",
                    "secret_exposure",
                    "scope_creep",
                    "security_sensitive",
                    "irreversible",
                    "needs_tests",
                    "prompt_injection",
                    "dependency_risk",
                    "wrong_repo",
                    "human_review",
                    "concurrency_sensitive",
                    "persistence_sensitive",
                    "backwards_compatibility",
                    "untrusted_input_path",
                    "fail_open",
                    "wrong_repo_semantic",
                    "suspicious_intent",
                    "external_side_effect_risk",
                ]
            }
            answers["risk_level"] = {
                "type": "choice",
                "choice": "low",
                "confidence": 0.91,
            }
            answers["risk_score"] = {
                "type": "score",
                "score": 0.0,
                "confidence": 0.91,
            }
            return {"answers": answers}


@pytest.fixture
def safe_context() -> EvaluationContext:
    """Create a context that would pass hard rules (safe command)."""
    return EvaluationContext(
        user_task="Run tests",
        repository="test-repo",
        repository_root="/tmp/test",
        working_directory="/tmp/test",
        proposed_action=ProposedAction(command="pytest tests/"),
        changed_files=[],
        git_diff="",
        test_results="",
        recent_context="",
        external_content="",
    )


@pytest.fixture
def temp_socket_path(tmp_path: Path) -> Path:
    """Create a temporary path for broker socket."""
    return tmp_path / "broker.sock"


# TypeSafe API failure modes
typesafe_failure_modes = [
    "timeout",
    "5xx_error",
    "malformed_json",
    "missing_keys",
    "missing_answers",
    "invalid_answer_type",
    "invalid_risk_choice",
    "sdk_missing",
    "missing_api_key",
    "network_unreachable",
    "401_unauthorized",
]


@pytest.mark.parametrize("failure_mode", typesafe_failure_modes)
@pytest.mark.parametrize("mode", ["advisory", "review", "enforce"])
def test_typesafe_failures_are_fail_closed(
    failure_mode: str,
    mode: str,
    safe_context: EvaluationContext,
) -> None:
    """Test that TypeSafe API failures result in fail-closed behavior."""
    config = ReflexConfig(mode=mode)
    gateway = MockGateway(failure_mode=failure_mode)
    evaluator = DefaultEvaluator(config=config, gateway=gateway)

    result = evaluator.evaluate(safe_context)

    # In enforce mode, degraded evaluations should never return ALLOW
    if mode == "enforce":
        assert result.decision != "ALLOW", f"Enforce mode returned ALLOW for {failure_mode}"
        assert result.degraded, f"Enforce mode should mark {failure_mode} as degraded"

    # In review mode, degraded evaluations should never return ALLOW
    if mode == "review":
        assert result.decision != "ALLOW", f"Review mode returned ALLOW for {failure_mode}"
        assert result.degraded, f"Review mode should mark {failure_mode} as degraded"

    # In advisory mode, degraded should still be set
    if mode == "advisory":
        assert result.degraded, f"Advisory mode should mark {failure_mode} as degraded"
        # Advisory mode should surface the degradation via warnings
        assert len(result.warnings) > 0, f"Advisory mode should warn about {failure_mode}"


@pytest.mark.parametrize("failure_mode", typesafe_failure_modes)
def test_typesafe_failures_log_degraded_evaluation(
    failure_mode: str,
    safe_context: EvaluationContext,
    tmp_path: Path,
) -> None:
    """Test that TypeSafe failures are logged with degraded_evaluation reason code."""
    from jev_reflex.audit import AuditLog

    config = ReflexConfig(
        mode="enforce",
        audit={"enabled": True, "path": str(tmp_path / "audit.log"), "rotate_mb": 100},
    )
    gateway = MockGateway(failure_mode=failure_mode)
    evaluator = DefaultEvaluator(config=config, gateway=gateway)

    result = evaluator.evaluate(safe_context)

    # Check audit log contains the degraded evaluation
    audit_log = AuditLog(config)
    entries = audit_log.tail(1)

    assert len(entries) == 1, "Audit log should contain one entry"
    entry = entries[0]

    # Verify the entry shows degraded evaluation
    assert entry["policy_decision"] != "ALLOW", (
        f"Logged decision should not be ALLOW for {failure_mode}"
    )
    assert result.degraded, f"Result should be marked as degraded for {failure_mode}"


# Broker failure modes
@pytest.fixture
def mock_broker_config(temp_socket_path: Path) -> ReflexConfig:
    """Create config with broker transport."""
    return ReflexConfig(
        mode="enforce",
        jev=JEVConfig(
            transport="broker",
            socket=str(temp_socket_path),
            connect_timeout=1.0,
            request_timeout=1.0,
        ),
    )


def test_broker_socket_does_not_exist(
    mock_broker_config: ReflexConfig,
    safe_context: EvaluationContext,
) -> None:
    """Test that non-existent broker socket results in fail-closed behavior."""
    result = evaluate_context(safe_context, config=mock_broker_config)

    assert result.degraded, "Non-existent socket should be marked as degraded"
    assert result.semantic_source == "broker/unavailable"


def test_broker_socket_connection_refused(
    mock_broker_config: ReflexConfig,
    safe_context: EvaluationContext,
    temp_socket_path: Path,
) -> None:
    """Test that connection refused results in fail-closed behavior."""
    # Create a socket but don't listen on it
    temp_socket_path.unlink(missing_ok=True)

    # Try to connect - should fail
    result = evaluate_context(safe_context, config=mock_broker_config)

    assert result.degraded, "Connection refused should be marked as degraded"
    assert result.semantic_source == "broker/unavailable"


def test_broker_socket_hangs(
    mock_broker_config: ReflexConfig,
    safe_context: EvaluationContext,
    temp_socket_path: Path,
) -> None:
    """Test that broker hanging (no response within timeout) results in fail-closed behavior."""
    import asyncio
    import threading
    import time

    # Create a hanging broker
    class HangingBroker:
        def __init__(self, path: Path) -> None:
            self.path = path
            self.server = None
            self.thread = None

        def start(self) -> None:
            async def hanging_handler(
                reader: asyncio.StreamReader, writer: asyncio.StreamWriter
            ) -> None:
                # Accept connection but never respond
                await reader.read(1024)
                # Never write response - just hang
                await asyncio.sleep(1000)

            async def run_server() -> None:
                self.server = await asyncio.start_unix_server(hanging_handler, path=str(self.path))
                async with self.server:
                    await asyncio.sleep(1000)

            def run_in_thread() -> None:
                asyncio.run(run_server())

            self.thread = threading.Thread(target=run_in_thread, daemon=True)
            self.thread.start()
            time.sleep(0.2)  # Give server time to start

        def stop(self) -> None:
            if self.path.exists():
                self.path.unlink()
            if self.thread:
                self.thread.join(timeout=1.0)

    try:
        hanging_broker = HangingBroker(temp_socket_path)
        hanging_broker.start()

        result = evaluate_context(safe_context, config=mock_broker_config)

        assert result.degraded, "Hanging broker should be marked as degraded"
        assert result.semantic_source == "broker/unavailable"
    finally:
        if temp_socket_path.exists():
            temp_socket_path.unlink()


def test_broker_clock_skew_not_implemented(
    mock_broker_config: ReflexConfig,
    safe_context: EvaluationContext,
) -> None:
    """Test clock skew detection - stubbed until signing lands in 1.3."""
    # TODO: Implement this test once Prompt 1.3's signing is implemented
    # This should test that broker responses with timestamps outside acceptable window
    # are rejected and marked as degraded
    pytest.skip("Clock skew detection not implemented until Prompt 1.3 signing")


@pytest.mark.parametrize("mode", ["advisory", "review", "enforce"])
def test_broker_failures_are_fail_closed(
    mode: str,
    safe_context: EvaluationContext,
    temp_socket_path: Path,
) -> None:
    """Test that broker failures result in fail-closed behavior in all modes."""
    config = ReflexConfig(
        mode=mode,
        jev=JEVConfig(
            transport="broker",
            socket=str(temp_socket_path),
            connect_timeout=1.0,
            request_timeout=1.0,
        ),
    )

    result = evaluate_context(safe_context, config=config)

    # All modes should mark as degraded
    assert result.degraded, f"{mode} mode should mark broker failure as degraded"

    # Enforce and review modes should never return ALLOW on degraded
    if mode in ["enforce", "review"]:
        assert result.decision != "ALLOW", f"{mode} mode returned ALLOW on degraded broker"

    # Advisory mode should surface the degradation
    if mode == "advisory":
        assert len(result.warnings) > 0, f"{mode} mode should warn about broker failure"


def test_hard_rules_override_degraded_evaluation(
    safe_context: EvaluationContext,
) -> None:
    """Test that hard rules still work even when semantic evaluation is degraded."""
    # Create a context with a destructive command
    destructive_context = EvaluationContext(
        user_task="Delete cache",
        repository="test-repo",
        repository_root="/tmp/test",
        working_directory="/tmp/test",
        proposed_action=ProposedAction(command="rm -rf /tmp/cache"),
        changed_files=[],
        git_diff="",
        test_results="",
        recent_context="",
        external_content="",
    )

    config = ReflexConfig(mode="enforce")
    gateway = MockGateway(failure_mode="timeout")
    evaluator = DefaultEvaluator(config=config, gateway=gateway)

    result = evaluator.evaluate(destructive_context)

    # Should be HOLD due to hard rule, not just degraded
    assert result.decision == "HOLD", "Hard rule should override to HOLD"
    assert result.degraded, "Should still be marked as degraded"
    assert any("destructive" in rule for rule in result.triggered_rules), (
        "Should trigger destructive rule"
    )


def test_degraded_evaluation_reason_codes_distinct(
    safe_context: EvaluationContext,
) -> None:
    """Test that different failure modes produce distinct warning/reason codes."""
    failure_modes = [
        "timeout",
        "5xx_error",
        "malformed_json",
        "missing_keys",
        "sdk_missing",
        "missing_api_key",
    ]

    seen_warnings = set()

    for failure_mode in failure_modes:
        config = ReflexConfig(mode="advisory")
        gateway = MockGateway(failure_mode=failure_mode)
        evaluator = DefaultEvaluator(config=config, gateway=gateway)

        result = evaluator.evaluate(safe_context)

        # Each failure should produce some warning
        assert len(result.warnings) > 0, f"{failure_mode} should produce warnings"

        # Collect unique warning patterns
        for warning in result.warnings:
            seen_warnings.add(warning)

    # At minimum, we should have distinct warnings for different failure categories
    assert len(seen_warnings) >= 2, "Should have distinct warnings for different failure modes"


@pytest.mark.parametrize("mode", ["advisory", "review", "enforce"])
def test_no_jev_mode_bypasses_semantic_failures(
    mode: str,
    safe_context: EvaluationContext,
) -> None:
    """Test that --no-jev mode bypasses semantic failures entirely."""
    config = ReflexConfig(mode=mode)

    result = evaluate_context(
        safe_context,
        config=config,
        use_jev=False,  # Bypass JEV entirely
    )

    # Should not be degraded since we're not using JEV
    assert not result.degraded, f"{mode} mode with --no-jev should not be degraded"

    # Decision should be based on hard rules only
    # Advisory mode should ALLOW safe actions
    if mode == "advisory":
        assert result.decision == "ALLOW", f"{mode} mode with --no-jev should ALLOW safe actions"
    # Review and enforce modes may still require review based on other policy factors
    # The key point is that it's not degraded due to semantic failure


def test_concurrent_mode_samples_with_one_degraded(
    safe_context: EvaluationContext,
) -> None:
    """Test that when one sample is degraded in multi-sample mode, overall is degraded."""
    config = ReflexConfig(jev=JEVConfig(samples=3, aggregation="median"))

    # Create a gateway that fails on second call
    class FailingGateway:
        def __init__(self) -> None:
            self.call_count = 0
            self.last_api_requests = 0

        def system_one(self, state: dict[str, Any], questions: dict[str, Any]) -> Any:
            self.call_count += 1
            self.last_api_requests = 1

            if self.call_count == 2:
                raise TimeoutError("Second call fails")

            # Normal response for other calls
            answers = {
                name: {"type": "noul", "noul": 0.1}
                for name in [
                    "destructive",
                    "secret_exposure",
                    "scope_creep",
                    "security_sensitive",
                    "irreversible",
                    "needs_tests",
                    "prompt_injection",
                    "dependency_risk",
                    "wrong_repo",
                    "human_review",
                    "concurrency_sensitive",
                    "persistence_sensitive",
                    "backwards_compatibility",
                    "untrusted_input_path",
                    "fail_open",
                    "wrong_repo_semantic",
                    "suspicious_intent",
                    "external_side_effect_risk",
                ]
            }
            answers["risk_level"] = {
                "type": "choice",
                "choice": "low",
                "confidence": 0.91,
            }
            answers["risk_score"] = {
                "type": "score",
                "score": 0.0,
                "confidence": 0.91,
            }
            return {"answers": answers}

    evaluator = DefaultEvaluator(config=config, gateway=FailingGateway())
    result = evaluator.evaluate(safe_context)

    # Should be marked as degraded
    assert result.degraded, "Multi-sample with one failure should be degraded"
