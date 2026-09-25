"""Tests for gitleaks-enhanced secret redaction."""

from __future__ import annotations

import json
import random
import shutil
import string
import warnings
from unittest.mock import MagicMock, patch

import pytest

from jev_reflex.evaluator import _redacted_context_with_gitleaks
from jev_reflex.models import EvaluationContext, ProposedAction
from jev_reflex.redaction import (
    REDACTED_SECRET,
    GitleaksRedactor,
    _check_gitleaks_available,
    _get_gitleaks_redactor,
    redact_text,
    redact_text_with_gitleaks,
)


@pytest.fixture(autouse=True)
def reset_gitleaks_state():
    """Reset global gitleaks state before and after each test to avoid polluting other test modules."""
    import jev_reflex.redaction as redaction_module

    redaction_module._GITLEAKS_AVAILABLE = None
    redaction_module._GITLEAKS_WARNING_SHOWN = False
    redaction_module._gitleaks_redactor = None
    yield
    redaction_module._GITLEAKS_AVAILABLE = None
    redaction_module._GITLEAKS_WARNING_SHOWN = False
    redaction_module._gitleaks_redactor = None


@pytest.fixture
def sample_context() -> EvaluationContext:
    """Create a sample evaluation context for testing."""
    return EvaluationContext(
        user_task="Deploy the application with API key AKIAIOSFODNN7EXAMPLE",
        repository="test-repo",
        repository_root="/tmp/test",
        working_directory="/tmp/test",
        proposed_action=ProposedAction(
            command="curl -H 'Authorization: Bearer ghp_testtoken123' https://api.example.com"
        ),
        changed_files=[],
        git_diff="",
        test_results="",
        recent_context="",
        external_content="",
    )


def test_redact_text_regex_fallback() -> None:
    """Test that regex redaction works as a fallback."""
    text = "password: secret123"
    redacted = redact_text(text)
    assert "secret123" not in redacted
    assert "<REDACTED_SECRET>" in redacted


def test_redact_text_with_gitleaks_no_gitleaks() -> None:
    """Test that redaction falls back to regex when gitleaks is not available."""
    with patch("jev_reflex.redaction.shutil.which", return_value=None):
        # Reset the cached availability check
        import jev_reflex.redaction as redaction_module

        redaction_module._GITLEAKS_AVAILABLE = None
        redaction_module._GITLEAKS_WARNING_SHOWN = False

        text = "password: secret123"
        redacted, failed = redact_text_with_gitleaks(text)
        assert "secret123" not in redacted
        assert "<REDACTED_SECRET>" in redacted
        assert failed is False


def test_gitleaks_redactor_not_available() -> None:
    """Test that GitleaksRedactor falls back to regex when gitleaks is not available."""
    with patch("jev_reflex.redaction.shutil.which", return_value=None):
        import jev_reflex.redaction as redaction_module

        redaction_module._GITLEAKS_AVAILABLE = None
        redaction_module._GITLEAKS_WARNING_SHOWN = False

        redactor = GitleaksRedactor()
        assert redactor._available is False

        text = "password: secret123"
        redacted, failed = redactor.redact(text)
        assert "secret123" not in redacted
        assert failed is False


def test_gitleaks_redactor_timeout() -> None:
    """Test that gitleaks timeout triggers fail-toward-more-redaction."""
    with patch("jev_reflex.redaction.shutil.which", return_value="/usr/bin/gitleaks"):
        with patch("jev_reflex.redaction.subprocess.run") as mock_run:
            import jev_reflex.redaction as redaction_module

            redaction_module._GITLEAKS_AVAILABLE = None
            redaction_module._GITLEAKS_WARNING_SHOWN = False

            # Simulate timeout
            from subprocess import TimeoutExpired

            mock_run.side_effect = TimeoutExpired("gitleaks", 10)

            redactor = GitleaksRedactor(timeout=5.0)
            text = "some text"
            redacted, failed = redactor.redact(text)

            assert redacted == "<REDACTED_SECRET>"
            assert failed is True


def test_gitleaks_redactor_subprocess_error() -> None:
    """Test that gitleaks subprocess error triggers fail-toward-more-redaction."""
    with patch("jev_reflex.redaction.shutil.which", return_value="/usr/bin/gitleaks"):
        with patch("jev_reflex.redaction.subprocess.run") as mock_run:
            import jev_reflex.redaction as redaction_module

            redaction_module._GITLEAKS_AVAILABLE = None
            redaction_module._GITLEAKS_WARNING_SHOWN = False

            # Simulate subprocess error
            mock_run.side_effect = OSError("Command failed")

            redactor = GitleaksRedactor()
            text = "some text"
            redacted, failed = redactor.redact(text)

            assert redacted == "<REDACTED_SECRET>"
            assert failed is True


def test_gitleaks_redactor_invalid_json() -> None:
    """Test that invalid gitleaks JSON output triggers fail-toward-more-redaction."""
    with patch("jev_reflex.redaction.shutil.which", return_value="/usr/bin/gitleaks"):
        with patch("jev_reflex.redaction.subprocess.run") as mock_run:
            import jev_reflex.redaction as redaction_module

            redaction_module._GITLEAKS_AVAILABLE = None
            redaction_module._GITLEAKS_WARNING_SHOWN = False

            # Simulate invalid JSON
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "not valid json"
            mock_run.return_value = mock_result

            redactor = GitleaksRedactor()
            text = "some text"
            redacted, failed = redactor.redact(text)

            assert redacted == "<REDACTED_SECRET>"
            assert failed is True


def test_gitleaks_redactor_nonzero_exit() -> None:
    """Test that gitleaks non-zero exit code triggers fail-toward-more-redaction."""
    with patch("jev_reflex.redaction.shutil.which", return_value="/usr/bin/gitleaks"):
        with patch("jev_reflex.redaction.subprocess.run") as mock_run:
            import jev_reflex.redaction as redaction_module

            redaction_module._GITLEAKS_AVAILABLE = None
            redaction_module._GITLEAKS_WARNING_SHOWN = False

            # Simulate non-zero exit code
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stdout = "error message"
            mock_run.return_value = mock_result

            redactor = GitleaksRedactor()
            text = "some text"
            redacted, failed = redactor.redact(text)

            assert redacted == "<REDACTED_SECRET>"
            assert failed is True


def test_redacted_context_with_gitleaks(sample_context: EvaluationContext) -> None:
    """Test that context redaction works with gitleaks."""
    with patch("jev_reflex.redaction.shutil.which", return_value=None):
        import jev_reflex.redaction as redaction_module

        redaction_module._GITLEAKS_AVAILABLE = None
        redaction_module._GITLEAKS_WARNING_SHOWN = False

        redacted, failed = _redacted_context_with_gitleaks(sample_context)
        assert failed is False
        # Regex should have caught the patterns
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted.user_task
        assert "ghp_testtoken123" not in redacted.proposed_action.command


def test_redacted_context_gitleaks_failure_forces_review(sample_context: EvaluationContext) -> None:
    """Test that gitleaks failure triggers REVIEW in policy."""
    with patch("jev_reflex.redaction.shutil.which", return_value="/usr/bin/gitleaks"):
        with patch("jev_reflex.redaction.subprocess.run") as mock_run:
            import jev_reflex.redaction as redaction_module

            redaction_module._GITLEAKS_AVAILABLE = None
            redaction_module._GITLEAKS_WARNING_SHOWN = False
            redaction_module._gitleaks_redactor = None

            # Simulate timeout
            from subprocess import TimeoutExpired

            mock_run.side_effect = TimeoutExpired("gitleaks", 10)

            redacted, failed = _redacted_context_with_gitleaks(sample_context)
            assert failed is True


def test_check_gitleaks_available_warning() -> None:
    """Test that gitleaks availability check shows warning when not available."""
    with patch("jev_reflex.redaction.shutil.which", return_value=None):
        import jev_reflex.redaction as redaction_module

        redaction_module._GITLEAKS_AVAILABLE = None
        redaction_module._GITLEAKS_WARNING_SHOWN = False

        with pytest.warns(UserWarning, match="gitleaks not found"):
            available = _check_gitleaks_available()

        assert available is False
        assert redaction_module._GITLEAKS_WARNING_SHOWN is True


def test_check_gitleaks_available_no_warning_second_call() -> None:
    """Test that warning is only shown once."""
    with patch("jev_reflex.redaction.shutil.which", return_value=None):
        import jev_reflex.redaction as redaction_module

        redaction_module._GITLEAKS_AVAILABLE = None
        redaction_module._GITLEAKS_WARNING_SHOWN = False

        # First call - should warn
        with pytest.warns(UserWarning, match="gitleaks not found"):
            _check_gitleaks_available()

        # Second call - should not warn
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            _check_gitleaks_available()


def test_get_gitleaks_redactor_singleton() -> None:
    """Test that gitleaks redactor is a singleton."""
    with patch("jev_reflex.redaction.shutil.which", return_value=None):
        import jev_reflex.redaction as redaction_module

        redaction_module._GITLEAKS_AVAILABLE = None
        redaction_module._GITLEAKS_WARNING_SHOWN = False
        redaction_module._gitleaks_redactor = None

        redactor1 = _get_gitleaks_redactor()
        redactor2 = _get_gitleaks_redactor()

        assert redactor1 is redactor2


def test_regex_patterns_still_work_with_gitleaks() -> None:
    """Test that regex patterns are applied even when gitleaks is available."""
    with patch("jev_reflex.redaction.shutil.which", return_value="/usr/bin/gitleaks"):
        with patch("jev_reflex.redaction.subprocess.run") as mock_run:
            import jev_reflex.redaction as redaction_module

            redaction_module._GITLEAKS_AVAILABLE = None
            redaction_module._GITLEAKS_WARNING_SHOWN = False
            redaction_module._gitleaks_redactor = None

            # Simulate gitleaks finding nothing
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "[]"
            mock_run.return_value = mock_result

            # Text with regex pattern
            text = "password: secret123"
            redacted, failed = redact_text_with_gitleaks(text)

            # Regex should still have caught it
            assert "secret123" not in redacted
            assert "<REDACTED_SECRET>" in redacted
            assert failed is False


def test_gitleaks_finds_secrets_regex_misses() -> None:
    """Test that gitleaks can catch secrets regex misses."""
    with patch("jev_reflex.redaction.shutil.which", return_value="/usr/bin/gitleaks"):
        with patch("jev_reflex.redaction.subprocess.run") as mock_run:
            import jev_reflex.redaction as redaction_module

            redaction_module._GITLEAKS_AVAILABLE = None
            redaction_module._GITLEAKS_WARNING_SHOWN = False
            redaction_module._gitleaks_redactor = None

            # Simulate gitleaks finding a secret
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = json.dumps(
                [
                    {
                        "startLine": 0,
                        "startColumn": 10,
                        "endLine": 0,
                        "endColumn": 30,
                        "secret": "custom_secret_key",
                    }
                ]
            )
            mock_run.return_value = mock_result

            # Text without obvious regex pattern
            text = "some custom_secret_key in code"
            redacted, failed = redact_text_with_gitleaks(text)

            # Gitleaks should have caught it
            assert "custom_secret_key" not in redacted
            assert "<REDACTED_SECRET>" in redacted
            assert failed is False


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="real gitleaks binary unavailable")
def test_real_gitleaks_redacts_reported_secret_without_leaving_input_file(tmp_path, monkeypatch):
    token = "ghp_" + "".join(random.Random(42).choices(string.ascii_letters + string.digits, k=36))
    monkeypatch.setattr("jev_reflex.redaction.tempfile.tempdir", str(tmp_path))
    redacted, failed = GitleaksRedactor().redact("🙂\ngithub_token = " + token + "\n")
    assert not failed
    assert token not in redacted
    assert REDACTED_SECRET in redacted
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="real gitleaks binary unavailable")
def test_real_gitleaks_handles_repeated_secret_without_false_failure():
    token = "ghp_" + "".join(random.Random(42).choices(string.ascii_letters + string.digits, k=36))
    redacted, failed = GitleaksRedactor().redact(f"first {token}\nsecond {token}\n")
    assert not failed
    assert token not in redacted
    assert redacted.count(REDACTED_SECRET) == 2


def test_gitleaks_redacted_context_is_sent_to_gateway(monkeypatch):
    import jev_reflex.evaluator as ev
    from jev_reflex.config import ReflexConfig
    from jev_reflex.evaluator import JEVSemanticEvaluator, evaluate_context
    from jev_reflex.models import EvaluationContext, ProposedAction

    class CapturingGateway:
        def __init__(self):
            self.captured_state = None

        def system_one(self, state, questions):
            self.captured_state = state
            return {
                "answers": {
                    "risk": {"choice": "low", "confidence": 0.95},
                    "destructive": 0.01,
                    "secret_exposure": 0.01,
                    "prompt_injection": 0.01,
                    "wrong_repo": 0.01,
                    "wrong_repo_semantic": 0.01,
                    "fail_open": 0.01,
                    "irreversible": 0.01,
                    "security_sensitive": 0.01,
                    "concurrency_sensitive": 0.01,
                    "persistence_sensitive": 0.01,
                    "backwards_compatibility": 0.01,
                    "human_review": 0.01,
                    "tests_needed": 0.01,
                    "untrusted_input_path": 0.01,
                    "dependency_risk": 0.01,
                    "external_side_effect_risk": 0.01,
                    "scope_creep": 0.01,
                    "suspicious_intent": 0.01,
                }
            }

    secret_token = "gitleaks_custom_pat_value_9999"
    monkeypatch.setattr(
        ev,
        "redact_text_with_gitleaks",
        lambda text: (text.replace(secret_token, "<REDACTED_SECRET>"), False),
    )

    gateway = CapturingGateway()
    config = ReflexConfig(mode="enforce")
    ctx = EvaluationContext(
        user_task=f"Task with {secret_token}",
        proposed_action=ProposedAction(command=f"echo {secret_token}"),
    )
    evaluator = JEVSemanticEvaluator(config=config, gateway=gateway)
    res = evaluate_context(ctx, config=config, semantic_evaluator=evaluator)

    assert gateway.captured_state is not None
    assert secret_token not in str(gateway.captured_state)
    assert "<REDACTED_SECRET>" in gateway.captured_state.get("user_task", "")
    assert res.decision in {"ALLOW", "REVIEW"}


def test_gitleaks_failure_skips_external_evaluation_and_aligns_telemetry(monkeypatch):
    import jev_reflex.evaluator as ev
    from jev_reflex.config import ReflexConfig
    from jev_reflex.evaluator import JEVSemanticEvaluator, evaluate_context
    from jev_reflex.metrics import decisions_total
    from jev_reflex.models import EvaluationContext, ProposedAction

    class SpyGateway:
        def __init__(self):
            self.called = False

        def system_one(self, state, questions):
            self.called = True
            return {"answers": {"risk": {"choice": "low", "confidence": 0.9}}}

    monkeypatch.setattr(
        ev,
        "redact_text_with_gitleaks",
        lambda text: (text, True),
    )

    logged_events = []
    monkeypatch.setattr(
        ev,
        "log_structured",
        lambda level, event, fields: logged_events.append((event, fields)),
    )

    gateway = SpyGateway()
    config = ReflexConfig(mode="enforce")
    ctx = EvaluationContext(
        user_task="Safe task",
        proposed_action=ProposedAction(command="echo safe"),
    )

    before_review = decisions_total._label_values.get(("REVIEW",), 0.0)
    before_allow = decisions_total._label_values.get(("ALLOW",), 0.0)

    evaluator = JEVSemanticEvaluator(config=config, gateway=gateway)
    res = evaluate_context(ctx, config=config, semantic_evaluator=evaluator)

    after_review = decisions_total._label_values.get(("REVIEW",), 0.0)
    after_allow = decisions_total._label_values.get(("ALLOW",), 0.0)

    # 1. External evaluation must be skipped on redaction failure
    assert not gateway.called

    # 2. Decision must be forced to REVIEW and marked degraded
    assert res.decision == "REVIEW"
    assert res.degraded is True

    # 3. Decision metric must increment REVIEW, NOT ALLOW
    assert after_review - before_review == 1.0
    assert after_allow - before_allow == 0.0

    # 4. Structured log event must report REVIEW and degraded: True
    decision_events = [fields for event, fields in logged_events if event == "policy_decision"]
    assert len(decision_events) == 1
    assert decision_events[0]["decision"] == "REVIEW"
    assert decision_events[0]["degraded"] is True
