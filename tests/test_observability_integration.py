"""Integration tests for observability features."""

import json

from jev_reflex.logging_config import WebhookSink
from jev_reflex.metrics import get_registry


class TestMetricsEndpoint:
    """Test /metrics HTTP endpoint."""

    def test_metrics_endpoint_returns_valid_format(self) -> None:
        """Test that metrics registry renders valid Prometheus exposition format."""
        from jev_reflex.metrics import decisions_total, get_registry

        # Increment some metrics to ensure they're rendered
        decisions_total.inc(decision="allow")

        output = get_registry().render()
        assert "# HELP" in output
        assert "# TYPE" in output
        assert "jrx_decisions_total" in output

    def test_metrics_endpoint_content_type(self) -> None:
        """Test that metrics output contains expected content type indicators."""
        from jev_reflex.metrics import get_registry

        output = get_registry().render()
        # Prometheus exposition format doesn't include content-type in the body
        # but should have proper HELP and TYPE comments
        assert "# HELP" in output
        assert "# TYPE" in output


class TestWebhookSink:
    """Test webhook log sink with retry/backoff."""

    def test_webhook_sink_emits_to_queue(self) -> None:
        """Test that webhook sink emits log entries to queue without blocking."""
        sink = WebhookSink("http://localhost:9999/webhook", max_queue_size=10)

        entry = {"timestamp": "2024-01-01T00:00:00Z", "level": "INFO", "event": "test"}
        sink.emit(entry)

        # Should not block
        assert sink._queue.qsize() == 1

        sink.stop()

    def test_webhook_sink_drops_when_queue_full(self) -> None:
        """Test that webhook sink drops entries when queue is full."""
        sink = WebhookSink("http://localhost:9999/webhook", max_queue_size=2)

        # Fill the queue
        for _ in range(10):
            entry = {"timestamp": "2024-01-01T00:00:00Z", "level": "INFO", "event": "test"}
            sink.emit(entry)

        # Queue should be at max size
        assert sink._queue.qsize() == 2

        sink.stop()


class TestMetricsIntegration:
    """Test metrics integration with evaluation flow."""

    def test_metrics_increment_on_decisions(self) -> None:
        """Test that decision metrics increment correctly."""
        from jev_reflex.metrics import decisions_total

        # Reset the counter
        decisions_total._value = 0.0
        decisions_total._label_values.clear()

        decisions_total.inc(decision="allow")
        decisions_total.inc(decision="allow")
        decisions_total.inc(decision="hold")

        output = get_registry().render()
        assert 'jrx_decisions_total{decision="allow"} 2' in output
        assert 'jrx_decisions_total{decision="hold"} 1' in output

    def test_metrics_increment_on_hard_rules(self) -> None:
        """Test that hard rule metrics increment correctly."""
        from jev_reflex.metrics import hard_rule_triggers_total

        # Reset the counter
        hard_rule_triggers_total._value = 0.0
        hard_rule_triggers_total._label_values.clear()

        hard_rule_triggers_total.inc(rule_name="destructive")
        hard_rule_triggers_total.inc(rule_name="secret_exposure")
        hard_rule_triggers_total.inc(rule_name="destructive")

        output = get_registry().render()
        assert 'jrx_hard_rule_triggers_total{rule_name="destructive"} 2' in output
        assert 'jrx_hard_rule_triggers_total{rule_name="secret_exposure"} 1' in output

    def test_metrics_jev_latency_histogram(self) -> None:
        """Test that JEV latency histogram records correctly."""
        from jev_reflex.metrics import jev_signal_latency_seconds

        # Reset the histogram
        jev_signal_latency_seconds._sum = 0.0
        jev_signal_latency_seconds._count = 0
        jev_signal_latency_seconds._bucket_counts = [0] * len(jev_signal_latency_seconds.buckets)

        # Record some latencies
        jev_signal_latency_seconds.observe(0.05)
        jev_signal_latency_seconds.observe(0.15)
        jev_signal_latency_seconds.observe(0.5)

        output = get_registry().render()
        assert "jrx_jev_signal_latency_seconds_sum" in output
        assert "jrx_jev_signal_latency_seconds_count 3" in output

    def test_metrics_degraded_evaluations(self) -> None:
        """Test that degraded evaluation metrics increment correctly."""
        from jev_reflex.metrics import degraded_evaluations_total

        # Reset the counter
        degraded_evaluations_total._value = 0.0
        degraded_evaluations_total._label_values.clear()

        degraded_evaluations_total.inc(reason="jev_unavailable")
        degraded_evaluations_total.inc(reason="gitleaks_failed")

        output = get_registry().render()
        assert 'jrx_degraded_evaluations_total{reason="jev_unavailable"} 1' in output
        assert 'jrx_degraded_evaluations_total{reason="gitleaks_failed"} 1' in output


class TestLoggingRedaction:
    """Test that logging properly redacts secrets."""

    def test_logging_redacts_secrets_in_fields(self) -> None:
        """Test that secrets in log fields are redacted."""
        from jev_reflex.logging_config import log_structured

        # This should not crash and should redact the secret
        log_structured(
            level="INFO",
            event="test_event",
            fields={
                "secret": "my-secret-key",
                "token": "Bearer abc123",
                "password": "hunter2",
                "normal": "value",
            },
        )

    def test_logging_redacts_secrets_in_json_formatter(self) -> None:
        """Test that JSON formatter redacts secrets."""
        import logging

        from jev_reflex.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord("test", logging.INFO, "test.py", 1, "Test message", (), None)
        record.fields = {
            "secret": "my-secret-key",
            "token": "Bearer abc123",
            "password": "hunter2",
        }  # type: ignore[attr-defined]

        output = formatter.format(record)
        data = json.loads(output)

        # Check that secrets are redacted
        assert "<REDACTED_SECRET>" in str(data["fields"])
        assert "my-secret-key" not in str(data["fields"])
        assert "abc123" not in str(data["fields"])
        assert "hunter2" not in str(data["fields"])
