"""Tests for Prometheus metrics and structured logging."""

import json
import logging
import time

import pytest

from jev_reflex.logging_config import JSONFormatter, log_structured, setup_logging
from jev_reflex.metrics import (
    BrokerMetrics,
    Counter,
    Gauge,
    Histogram,
    MetricsRegistry,
    broker_uptime_seconds,
    decisions_total,
    degraded_evaluations_total,
    get_registry,
    hard_rule_triggers_total,
    jev_signal_latency_seconds,
    policy_reload_total,
)


class TestCounter:
    """Test Counter metric."""

    def test_counter_increment(self) -> None:
        counter = Counter("test_counter", "Test counter metric")
        counter.inc()
        assert counter._value == 1.0

    def test_counter_increment_by_value(self) -> None:
        counter = Counter("test_counter", "Test counter metric")
        counter.inc(5.0)
        assert counter._value == 5.0

    def test_counter_with_labels(self) -> None:
        counter = Counter("test_counter", "Test counter metric", labels=["decision"])
        counter.inc(decision="allow")
        counter.inc(decision="hold")
        assert counter._label_values[("allow",)] == 1.0
        assert counter._label_values[("hold",)] == 1.0

    def test_counter_cannot_decrease(self) -> None:
        counter = Counter("test_counter", "Test counter metric")
        with pytest.raises(ValueError, match="counter cannot decrease"):
            counter.inc(-1.0)

    def test_counter_render(self) -> None:
        counter = Counter("test_counter", "Test counter metric")
        counter.inc()
        output = counter._render()
        assert "# HELP test_counter Test counter metric" in output
        assert "# TYPE test_counter counter" in output
        assert "test_counter 1.0" in output


class TestHistogram:
    """Test Histogram metric."""

    def test_histogram_observe(self) -> None:
        histogram = Histogram("test_histogram", "Test histogram metric")
        histogram.observe(0.5)
        histogram.observe(1.5)
        assert histogram._count == 2
        assert histogram._sum == 2.0

    def test_histogram_buckets(self) -> None:
        histogram = Histogram("test_histogram", "Test histogram metric", buckets=(0.5, 1.0, 2.0))
        histogram.observe(0.3)
        histogram.observe(0.7)
        histogram.observe(1.5)
        # Prometheus histograms are cumulative: each observation increments all buckets it falls into
        # 0.3 <= 0.5: increments first bucket [1, 0, 0]
        # 0.7 > 0.5 but <= 1.0: increments first and second buckets [1, 1, 0]
        # 1.5 > 1.0 but <= 2.0: increments first, second, and third buckets [1, 2, 3]
        assert histogram._bucket_counts == [1, 2, 3]

    def test_histogram_with_labels(self) -> None:
        histogram = Histogram("test_histogram", "Test histogram metric", labels=["label"])
        histogram.observe(0.5, label="test")
        assert histogram._label_data[("test",)]["count"] == 1  # type: ignore[index]

    def test_histogram_cannot_observe_negative(self) -> None:
        histogram = Histogram("test_histogram", "Test histogram metric")
        with pytest.raises(ValueError, match="histogram cannot observe negative values"):
            histogram.observe(-1.0)

    def test_histogram_render(self) -> None:
        histogram = Histogram("test_histogram", "Test histogram metric")
        histogram.observe(0.5)
        output = histogram._render()
        assert "# HELP test_histogram Test histogram metric" in output
        assert "# TYPE test_histogram histogram" in output
        assert "test_histogram_sum 0.5" in output
        assert "test_histogram_count 1" in output


class TestGauge:
    """Test Gauge metric."""

    def test_gauge_set(self) -> None:
        gauge = Gauge("test_gauge", "Test gauge metric")
        gauge.set(42.0)
        assert gauge._value == 42.0

    def test_gauge_inc(self) -> None:
        gauge = Gauge("test_gauge", "Test gauge metric")
        gauge.inc(5.0)
        assert gauge._value == 5.0

    def test_gauge_dec(self) -> None:
        gauge = Gauge("test_gauge", "Test gauge metric")
        gauge.set(10.0)
        gauge.dec(3.0)
        assert gauge._value == 7.0

    def test_gauge_with_labels(self) -> None:
        gauge = Gauge("test_gauge", "Test gauge metric", labels=["label"])
        gauge.set(42.0, label="test")
        assert gauge._label_values[("test",)] == 42.0

    def test_gauge_render(self) -> None:
        gauge = Gauge("test_gauge", "Test gauge metric")
        gauge.set(42.0)
        output = gauge._render()
        assert "# HELP test_gauge Test gauge metric" in output
        assert "# TYPE test_gauge gauge" in output
        assert "test_gauge 42.0" in output


class TestMetricsRegistry:
    """Test MetricsRegistry."""

    def test_register_counter(self) -> None:
        registry = MetricsRegistry()
        counter = Counter("test_counter", "Test counter")
        registry.register(counter)
        assert "test_counter" in registry._metrics

    def test_duplicate_metric_raises(self) -> None:
        registry = MetricsRegistry()
        counter = Counter("test_counter", "Test counter")
        registry.register(counter)
        with pytest.raises(ValueError, match="metric test_counter already registered"):
            registry.register(counter)

    def test_get_counter_creates_if_not_exists(self) -> None:
        registry = MetricsRegistry()
        counter = registry.get_counter("test_counter", "Test counter")
        assert isinstance(counter, Counter)
        assert counter.name == "test_counter"

    def test_get_counter_returns_existing(self) -> None:
        registry = MetricsRegistry()
        counter1 = registry.get_counter("test_counter", "Test counter")
        counter2 = registry.get_counter("test_counter", "Test counter")
        assert counter1 is counter2

    def test_get_histogram_creates_if_not_exists(self) -> None:
        registry = MetricsRegistry()
        histogram = registry.get_histogram("test_histogram", "Test histogram")
        assert isinstance(histogram, Histogram)
        assert histogram.name == "test_histogram"

    def test_get_gauge_creates_if_not_exists(self) -> None:
        registry = MetricsRegistry()
        gauge = registry.get_gauge("test_gauge", "Test gauge")
        assert isinstance(gauge, Gauge)
        assert gauge.name == "test_gauge"

    def test_render_all_metrics(self) -> None:
        registry = MetricsRegistry()
        counter = registry.get_counter("test_counter", "Test counter")
        counter.inc()
        histogram = registry.get_histogram("test_histogram", "Test histogram")
        histogram.observe(0.5)
        gauge = registry.get_gauge("test_gauge", "Test gauge")
        gauge.set(42.0)

        output = registry.render()
        assert "test_counter" in output
        assert "test_histogram" in output
        assert "test_gauge" in output


class TestPredefinedMetrics:
    """Test predefined JEV Reflex metrics."""

    def test_decisions_total_metric(self) -> None:
        decisions_total.inc(decision="allow")
        decisions_total.inc(decision="hold")
        decisions_total.inc(decision="review")

        output = get_registry().render()
        assert 'jrx_decisions_total{decision="allow"}' in output
        assert 'jrx_decisions_total{decision="hold"}' in output
        assert 'jrx_decisions_total{decision="review"}' in output

    def test_hard_rule_triggers_total_metric(self) -> None:
        hard_rule_triggers_total.inc(rule_name="destructive")
        hard_rule_triggers_total.inc(rule_name="secret_exposure")

        output = get_registry().render()
        assert 'jrx_hard_rule_triggers_total{rule_name="destructive"}' in output
        assert 'jrx_hard_rule_triggers_total{rule_name="secret_exposure"}' in output

    def test_jev_signal_latency_seconds_metric(self) -> None:
        jev_signal_latency_seconds.observe(0.1)
        jev_signal_latency_seconds.observe(0.5)
        jev_signal_latency_seconds.observe(1.5)

        output = get_registry().render()
        assert "jrx_jev_signal_latency_seconds" in output
        assert "jrx_jev_signal_latency_seconds_sum" in output
        assert "jrx_jev_signal_latency_seconds_count" in output

    def test_degraded_evaluations_total_metric(self) -> None:
        degraded_evaluations_total.inc(reason="jev_unavailable")
        degraded_evaluations_total.inc(reason="gitleaks_failed")

        output = get_registry().render()
        assert 'jrx_degraded_evaluations_total{reason="jev_unavailable"}' in output
        assert 'jrx_degraded_evaluations_total{reason="gitleaks_failed"}' in output

    def test_policy_reload_total_metric(self) -> None:
        policy_reload_total.inc(result="success")
        policy_reload_total.inc(result="failure")

        output = get_registry().render()
        assert 'jrx_policy_reload_total{result="success"}' in output
        assert 'jrx_policy_reload_total{result="failure"}' in output

    def test_broker_uptime_seconds_metric(self) -> None:
        broker_uptime_seconds.set(100.0)

        output = get_registry().render()
        assert "jrx_broker_uptime_seconds 100.0" in output


class TestBrokerMetrics:
    """Test BrokerMetrics uptime tracking."""

    def test_broker_metrics_initialization(self) -> None:
        metrics = BrokerMetrics()
        assert metrics._start_time > 0

    def test_broker_metrics_uptime_tracking(self) -> None:
        metrics = BrokerMetrics()
        time.sleep(0.1)
        # Uptime should be at least 0.1 seconds
        uptime = time.monotonic() - metrics._start_time
        assert uptime >= 0.1


class TestJSONFormatter:
    """Test JSON formatter."""

    def test_json_formatter_basic(self) -> None:
        formatter = JSONFormatter()
        record = logging.LogRecord("test", logging.INFO, "test.py", 1, "Test message", (), None)
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["event"] == "Test message"
        assert "timestamp" in data
        assert "fields" in data

    def test_json_formatter_with_fields(self) -> None:
        formatter = JSONFormatter()
        record = logging.LogRecord("test", logging.INFO, "test.py", 1, "Test message", (), None)
        record.fields = {"key": "value"}  # type: ignore[attr-defined]
        output = formatter.format(record)
        data = json.loads(output)
        # The fields should be present and redacted
        assert "fields" in data
        assert "key" in data["fields"]

    def test_json_formatter_redaction(self) -> None:
        formatter = JSONFormatter()
        record = logging.LogRecord("test", logging.INFO, "test.py", 1, "Test message", (), None)
        record.fields = {"secret": "my-secret-key"}  # type: ignore[attr-defined]
        output = formatter.format(record)
        data = json.loads(output)
        # Secret should be redacted
        assert data["fields"]["secret"] != "my-secret-key"


class TestStructuredLogging:
    """Test structured logging."""

    def test_log_structured_basic(self) -> None:
        # This test ensures the function doesn't crash
        log_structured(level="INFO", event="test_event", fields={"key": "value"})

    def test_log_structured_with_redaction(self) -> None:
        # This test ensures secrets are redacted
        log_structured(
            level="INFO",
            event="test_event",
            fields={"secret": "my-secret-key", "normal": "value"},
        )

    def test_setup_logging_stdout(self) -> None:
        logger = setup_logging(sink="stdout", level="INFO")
        assert logger.level == logging.INFO
        assert len(logger.handlers) > 0

    def test_setup_logging_invalid_sink(self) -> None:
        with pytest.raises(ValueError, match="invalid sink type"):
            setup_logging(sink="invalid")

    def test_setup_logging_webhook_without_url(self) -> None:
        with pytest.raises(ValueError, match="webhook_url is required"):
            setup_logging(sink="webhook-url")


def test_labeled_histogram_uses_valid_sample_names_and_one_label_set():
    metric = Histogram("duration", "Duration", labels=["route"], buckets=(1.0, float("inf")))
    metric.observe(0.5, route='a"b\\c\nd')
    output = metric._render().splitlines()
    assert 'duration_bucket{route="a\\"b\\\\c\\nd",le="1.0"} 1' in output
    assert 'duration_sum{route="a\\"b\\\\c\\nd"} 0.5' in output
    assert 'duration_count{route="a\\"b\\\\c\\nd"} 1' in output


@pytest.mark.parametrize("kind", [Counter, Gauge])
def test_metric_label_values_are_escaped(kind):
    metric = kind("metric", "Help", labels=["label"])
    metric.inc(label='a"b\\c\nd')
    assert 'metric{label="a\\"b\\\\c\\nd"} 1.0' in metric._render().splitlines()


def test_json_formatter_redacts_messages_and_exception_tracebacks():
    import sys

    try:
        raise RuntimeError("password=synthetic-exception-credential")
    except RuntimeError:
        record = logging.LogRecord(
            "test",
            logging.ERROR,
            "test.py",
            1,
            "request failed: token=synthetic-message-credential",
            (),
            sys.exc_info(),
        )
    output = JSONFormatter().format(record)
    assert "synthetic-exception-credential" not in output
    assert "synthetic-message-credential" not in output
    assert json.loads(output)["fields"]["exception"]


@pytest.mark.parametrize(
    "sink_type,sink_class", [("syslog", "SyslogSink"), ("webhook-url", "WebhookSink")]
)
def test_non_stdout_handlers_format_and_redact_records(monkeypatch, sink_type, sink_class):
    entries = []

    class Sink:
        def __init__(self, *args, **kwargs):
            pass

        def emit(self, entry):
            assert isinstance(entry, dict)
            entries.append(entry)

        def close(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(f"jev_reflex.logging_config.{sink_class}", Sink)
    root = logging.getLogger()
    old_handlers, old_level = root.handlers[:], root.level
    try:
        setup_logging(sink=sink_type, webhook_url="https://logs.example.invalid")
        log_structured("ERROR", "token=synthetic-log-value", {"password": "synthetic-field-value"})
        assert len(entries) == 1
        assert "synthetic-log-value" not in json.dumps(entries)
        assert "synthetic-field-value" not in json.dumps(entries)
    finally:
        for handler in root.handlers:
            handler.close()
        root.handlers[:] = old_handlers
        root.setLevel(old_level)
