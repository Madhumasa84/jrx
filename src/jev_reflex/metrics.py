"""Prometheus metrics with hand-rolled exposition format writer.

We use a minimal hand-rolled implementation instead of prometheus_client to:
1. Avoid adding an external dependency for simple counter/histogram metrics
2. Keep the broker lightweight and avoid dependency bloat
3. The Prometheus exposition format is simple text-based and well-documented
4. We only need a small subset of metric types (counter, histogram, gauge)

Reference: https://prometheus.io/docs/instrumenting/exposition_formats/
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from threading import Lock
from typing import Any


class Counter:
    """A Prometheus counter metric that only increases."""

    def __init__(self, name: str, help_text: str, labels: list[str] | None = None) -> None:
        self.name = name
        self.help_text = help_text
        self.labels = labels or []
        self._value: float = 0.0
        self._label_values: dict[tuple[str, ...], float] = defaultdict(float)
        self._lock = Lock()

    def inc(self, value: float = 1.0, **labels: str) -> None:
        """Increment the counter by value (default 1.0)."""
        if value < 0:
            raise ValueError("counter cannot decrease")
        with self._lock:
            if labels:
                label_tuple = tuple(labels.get(k, "") for k in self.labels)
                self._label_values[label_tuple] += value
            else:
                self._value += value

    def _render(self) -> str:
        """Render the counter in Prometheus exposition format."""
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} counter"]
        if self._value > 0:
            lines.append(f"{self.name} {self._value}")
        for label_tuple, value in self._label_values.items():
            if value > 0:
                label_str = ",".join(
                    f'{k}="{v}"' for k, v in zip(self.labels, label_tuple, strict=True)
                )
                lines.append(f"{self.name}{{{label_str}}} {value}")
        return "\n".join(lines)


class Histogram:
    """A Prometheus histogram metric that counts observations in buckets."""

    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf"))

    def __init__(
        self,
        name: str,
        help_text: str,
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
        labels: list[str] | None = None,
    ) -> None:
        self.name = name
        self.help_text = help_text
        self.buckets = buckets
        self.labels = labels or []
        self._sum: float = 0.0
        self._count: int = 0
        self._bucket_counts: list[int] = [0] * len(buckets)
        self._label_data: dict[tuple[str, ...], dict[str, float | int]] = defaultdict(
            lambda: {"sum": 0.0, "count": 0, "buckets": [0] * len(buckets)}
        )
        self._lock = Lock()

    def observe(self, value: float, **labels: str) -> None:
        """Observe a value."""
        if value < 0:
            raise ValueError("histogram cannot observe negative values")
        with self._lock:
            if labels:
                label_tuple = tuple(labels.get(k, "") for k in self.labels)
                data = self._label_data[label_tuple]
                data["sum"] += value  # type: ignore[assignment]
                data["count"] += 1  # type: ignore[assignment]
                for i, bucket in enumerate(self.buckets):
                    if value <= bucket:
                        data["buckets"][i] += 1  # type: ignore[index]
            else:
                self._sum += value
                self._count += 1
                for i, bucket in enumerate(self.buckets):
                    if value <= bucket:
                        self._bucket_counts[i] += 1

    def _render(self) -> str:
        """Render the histogram in Prometheus exposition format."""
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} histogram"]

        def render_label_data(
            label_str: str, sum_val: float, count: int, bucket_counts: list[int]
        ) -> list[str]:
            label_prefix = f"{self.name}{label_str}"
            result = []
            for i, bucket in enumerate(self.buckets):
                le = "+Inf" if bucket == float("inf") else str(bucket)
                result.append(f'{label_prefix}_bucket{{le="{le}"}} {bucket_counts[i]}')
            result.append(f"{label_prefix}_sum {sum_val}")
            result.append(f"{label_prefix}_count {count}")
            return result

        if self._count > 0:
            lines.extend(render_label_data("", self._sum, self._count, self._bucket_counts))

        for label_tuple, data in self._label_data.items():
            if data["count"] > 0:  # type: ignore[comparison-overlap]
                label_str = ",".join(
                    f'{k}="{v}"' for k, v in zip(self.labels, label_tuple, strict=True)
                )
                lines.extend(
                    render_label_data(
                        f"{{{label_str}}}",
                        data["sum"],  # type: ignore[arg-type]
                        data["count"],  # type: ignore[arg-type]
                        data["buckets"],  # type: ignore[arg-type]
                    )
                )

        return "\n".join(lines)


class Gauge:
    """A Prometheus gauge metric that can increase or decrease."""

    def __init__(self, name: str, help_text: str, labels: list[str] | None = None) -> None:
        self.name = name
        self.help_text = help_text
        self.labels = labels or []
        self._value: float = 0.0
        self._label_values: dict[tuple[str, ...], float] = {}
        self._lock = Lock()

    def set(self, value: float, **labels: str) -> None:
        """Set the gauge to value."""
        with self._lock:
            if labels:
                label_tuple = tuple(labels.get(k, "") for k in self.labels)
                self._label_values[label_tuple] = value
            else:
                self._value = value

    def inc(self, value: float = 1.0, **labels: str) -> None:
        """Increment the gauge by value."""
        with self._lock:
            if labels:
                label_tuple = tuple(labels.get(k, "") for k in self.labels)
                self._label_values[label_tuple] = self._label_values.get(label_tuple, 0.0) + value
            else:
                self._value += value

    def dec(self, value: float = 1.0, **labels: str) -> None:
        """Decrement the gauge by value."""
        with self._lock:
            if labels:
                label_tuple = tuple(labels.get(k, "") for k in self.labels)
                self._label_values[label_tuple] = self._label_values.get(label_tuple, 0.0) - value
            else:
                self._value -= value

    def _render(self) -> str:
        """Render the gauge in Prometheus exposition format."""
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} gauge"]
        lines.append(f"{self.name} {self._value}")
        for label_tuple, value in self._label_values.items():
            label_str = ",".join(
                f'{k}="{v}"' for k, v in zip(self.labels, label_tuple, strict=True)
            )
            lines.append(f"{self.name}{{{label_str}}} {value}")
        return "\n".join(lines)


class MetricsRegistry:
    """Registry for all Prometheus metrics."""

    def __init__(self) -> None:
        self._metrics: dict[str, Counter | Histogram | Gauge] = {}
        self._lock = Lock()

    def register(self, metric: Counter | Histogram | Gauge) -> None:
        """Register a metric in the registry."""
        with self._lock:
            if metric.name in self._metrics:
                raise ValueError(f"metric {metric.name} already registered")
            self._metrics[metric.name] = metric

    def get_counter(self, name: str, help_text: str, labels: list[str] | None = None) -> Counter:
        """Get or create a counter metric."""
        with self._lock:
            if name not in self._metrics:
                counter = Counter(name, help_text, labels)
                self._metrics[name] = counter
                return counter
            metric = self._metrics[name]
            if not isinstance(metric, Counter):
                raise ValueError(f"metric {name} is not a counter")
            return metric

    def get_histogram(
        self,
        name: str,
        help_text: str,
        buckets: tuple[float, ...] = Histogram.DEFAULT_BUCKETS,
        labels: list[str] | None = None,
    ) -> Histogram:
        """Get or create a histogram metric."""
        with self._lock:
            if name not in self._metrics:
                histogram = Histogram(name, help_text, buckets, labels)
                self._metrics[name] = histogram
                return histogram
            metric = self._metrics[name]
            if not isinstance(metric, Histogram):
                raise ValueError(f"metric {name} is not a histogram")
            return metric

    def get_gauge(self, name: str, help_text: str, labels: list[str] | None = None) -> Gauge:
        """Get or create a gauge metric."""
        with self._lock:
            if name not in self._metrics:
                gauge = Gauge(name, help_text, labels)
                self._metrics[name] = gauge
                return gauge
            metric = self._metrics[name]
            if not isinstance(metric, Gauge):
                raise ValueError(f"metric {name} is not a gauge")
            return metric

    def render(self) -> str:
        """Render all metrics in Prometheus exposition format."""
        with self._lock:
            return "\n\n".join(metric._render() for metric in self._metrics.values())


# Global registry
_global_registry = MetricsRegistry()


def get_registry() -> MetricsRegistry:
    """Get the global metrics registry."""
    return _global_registry


# Predefined metrics for JEV Reflex
decisions_total = get_registry().get_counter(
    "jrx_decisions_total",
    "Total number of policy decisions made",
    labels=["decision"],
)

hard_rule_triggers_total = get_registry().get_counter(
    "jrx_hard_rule_triggers_total",
    "Total number of hard rule triggers",
    labels=["rule_name"],
)

jev_signal_latency_seconds = get_registry().get_histogram(
    "jrx_jev_signal_latency_seconds",
    "Latency of JEV semantic signal requests in seconds",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf")),
)

degraded_evaluations_total = get_registry().get_counter(
    "jrx_degraded_evaluations_total",
    "Total number of degraded evaluations",
    labels=["reason"],
)

policy_reload_total = get_registry().get_counter(
    "jrx_policy_reload_total",
    "Total number of policy reload attempts",
    labels=["result"],
)

broker_uptime_seconds = get_registry().get_gauge(
    "jrx_broker_uptime_seconds",
    "Broker uptime in seconds",
)


class BrokerMetrics:
    """Metrics tracker for the broker with uptime tracking."""

    def __init__(self) -> None:
        self._start_time = time.monotonic()
        self._update_task: Callable[[], None] | None = None

    def start_uptime_tracking(self, loop: Any) -> None:
        """Start tracking broker uptime in the background."""

        def update_uptime() -> None:
            broker_uptime_seconds.set(time.monotonic() - self._start_time)
            loop.call_later(1.0, update_uptime)

        self._update_task = update_uptime
        update_uptime()

    def stop_uptime_tracking(self) -> None:
        """Stop tracking broker uptime."""
        self._update_task = None
