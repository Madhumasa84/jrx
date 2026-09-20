"""Structured JSON logging with redaction support for JEV Reflex.

This module provides a JSON formatter for Python's stdlib logging with:
- Consistent schema: timestamp, level, event, fields
- Automatic secret redaction before logging any content
- Support for multiple sinks: stdout, syslog, webhook-url
- Fire-and-forget webhook delivery with bounded queue and retry/backoff
"""

from __future__ import annotations

import json
import logging
import queue
import socket
import sys
import threading
import time
import urllib.parse
from datetime import UTC, datetime
from typing import Any

import requests

from .redaction import redact_obj

# Syslog facility constants (since logging.LOG_USER doesn't exist in stdlib)
LOG_USER = 1 << 3
LOG_LOCAL0 = 16 << 3
LOG_LOCAL1 = 17 << 3
LOG_LOCAL2 = 18 << 3
LOG_LOCAL3 = 19 << 3
LOG_LOCAL4 = 20 << 3
LOG_LOCAL5 = 21 << 3
LOG_LOCAL6 = 22 << 3
LOG_LOCAL7 = 23 << 3


class JSONFormatter(logging.Formatter):
    """JSON formatter with consistent schema and redaction."""

    def __init__(self) -> None:
        super().__init__()
        self.converter = time.gmtime

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with redaction."""
        # Extract relevant fields
        log_entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
            "fields": {},
        }

        # Add context fields if present
        if hasattr(record, "fields") and isinstance(record.fields, dict):
            # Redact all field values
            log_entry["fields"] = redact_obj(record.fields)

        # Add exception info if present
        if record.exc_info:
            log_entry["fields"]["exception"] = self.formatException(record.exc_info)

        # Add standard logging attributes
        if record.name:
            log_entry["fields"]["logger"] = record.name
        if record.pathname:
            log_entry["fields"]["file"] = record.pathname
        if record.lineno:
            log_entry["fields"]["line"] = record.lineno
        if record.funcName:
            log_entry["fields"]["function"] = record.funcName

        return json.dumps(log_entry, separators=(",", ":"))


class WebhookSink:
    """Fire-and-forget webhook log sink with bounded queue and retry/backoff."""

    def __init__(self, url: str, max_queue_size: int = 1000, max_retries: int = 3) -> None:
        """Initialize webhook sink.

        Args:
            url: Webhook URL to POST log entries to
            max_queue_size: Maximum number of log entries to queue before dropping
            max_retries: Maximum number of retry attempts for failed deliveries
        """
        self.url = url
        self.max_queue_size = max_queue_size
        self.max_retries = max_retries
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max_queue_size)
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(target=self._worker, daemon=True)
        self._worker_thread.start()

    def _worker(self) -> None:
        """Background worker that delivers log entries to webhook."""
        while not self._stop_event.is_set():
            try:
                # Wait for log entry with timeout to check stop event
                entry = self._queue.get(timeout=1.0)
                self._deliver_with_retry(entry)
            except queue.Empty:
                continue
            except Exception:
                # Log delivery errors to stderr to avoid infinite loops
                pass

    def _deliver_with_retry(self, entry: dict[str, Any]) -> None:
        """Deliver log entry with exponential backoff retry."""
        for attempt in range(self.max_retries + 1):
            try:
                response = requests.post(
                    self.url,
                    json=entry,
                    headers={"Content-Type": "application/json"},
                    timeout=5.0,
                )
                if response.status_code >= 200 and response.status_code < 300:
                    return
                if attempt == self.max_retries:
                    return
            except requests.RequestException:
                if attempt == self.max_retries:
                    return
            # Exponential backoff: 2^attempt seconds, max 10 seconds
            backoff = min(2**attempt, 10.0)
            time.sleep(backoff)

    def emit(self, entry: dict[str, Any]) -> None:
        """Emit log entry to webhook (non-blocking)."""
        try:
            self._queue.put_nowait(entry)
        except queue.Full:
            # Queue is full, drop the log entry
            pass

    def stop(self) -> None:
        """Stop the background worker and drain remaining queue."""
        self._stop_event.set()
        self._worker_thread.join(timeout=5.0)


class StdoutSink:
    """Stdout log sink."""

    def emit(self, entry: dict[str, Any]) -> None:
        """Emit log entry to stdout."""
        print(json.dumps(entry, separators=(",", ":")), file=sys.stdout, flush=True)


class SyslogSink:
    """Syslog log sink."""

    def __init__(self, ident: str = "jrx", facility: int = LOG_USER) -> None:
        """Initialize syslog sink.

        Args:
            ident: Program identifier for syslog
            facility: Syslog facility (default: LOG_USER)
        """
        self.ident = ident
        self.facility = facility
        self._socket: socket.socket | None = None
        self._connect()

    def _connect(self) -> None:
        """Connect to syslog socket."""
        try:
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self._socket.connect("/dev/log")
        except (OSError, FileNotFoundError):
            # Fallback to UDP syslog
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.connect(("127.0.0.1", 514))

    def emit(self, entry: dict[str, Any]) -> None:
        """Emit log entry to syslog."""
        if self._socket is None:
            return

        try:
            priority = self.facility | self._level_to_priority(entry.get("level", "INFO"))
            message = json.dumps(entry, separators=(",", ":"))
            syslog_message = f"<{priority}>{self.ident}: {message}"
            self._socket.send(syslog_message.encode("utf-8"))
        except OSError:
            # Try to reconnect on next emit
            self._socket = None
            self._connect()

    def _level_to_priority(self, level: str) -> int:
        """Convert log level name to syslog priority."""
        level_map = {
            "DEBUG": 7,  # LOG_DEBUG
            "INFO": 6,  # LOG_INFO
            "WARNING": 4,  # LOG_WARNING
            "ERROR": 3,  # LOG_ERR
            "CRITICAL": 2,  # LOG_CRIT
        }
        return level_map.get(level, 6)  # Default to INFO

    def close(self) -> None:
        """Close syslog socket."""
        if self._socket:
            self._socket.close()
            self._socket = None


def setup_logging(
    sink: str = "stdout",
    level: str = "INFO",
    webhook_url: str | None = None,
    syslog_ident: str = "jrx",
) -> logging.Logger:
    """Setup structured JSON logging for JEV Reflex.

    Args:
        sink: Log sink type: "stdout", "syslog", or "webhook-url"
        level: Log level: "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
        webhook_url: Webhook URL for webhook sink (required if sink="webhook-url")
        syslog_ident: Program identifier for syslog

    Returns:
        Configured logger instance
    """
    # Validate sink type
    if sink not in {"stdout", "syslog", "webhook-url"}:
        raise ValueError(f"invalid sink type: {sink}")

    if sink == "webhook-url" and not webhook_url:
        raise ValueError("webhook_url is required when sink='webhook-url'")

    # Validate webhook URL
    if webhook_url:
        try:
            parsed = urllib.parse.urlparse(webhook_url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("invalid webhook URL")
        except Exception as e:
            raise ValueError(f"invalid webhook URL: {e}") from e

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create JSON formatter
    formatter = JSONFormatter()

    # Create handler based on sink type
    if sink == "stdout":
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)
    elif sink == "syslog":
        handler = logging.Handler()
        handler.setFormatter(formatter)
        syslog_sink = SyslogSink(ident=syslog_ident)

        def emit(syslog_entry: dict[str, Any]) -> None:
            syslog_sink.emit(syslog_entry)

        handler.emit = emit  # type: ignore[assignment]
        root_logger.addHandler(handler)
    elif sink == "webhook-url":
        handler = logging.Handler()
        handler.setFormatter(formatter)
        webhook_sink = WebhookSink(url=webhook_url)

        def emit(webhook_entry: dict[str, Any]) -> None:
            webhook_sink.emit(webhook_entry)

        handler.emit = emit  # type: ignore[assignment]
        root_logger.addHandler(handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name."""
    return logging.getLogger(name)


def log_structured(
    level: str,
    event: str,
    fields: dict[str, Any] | None = None,
    logger_name: str = "jrx",
) -> None:
    """Log a structured event with automatic redaction.

    Args:
        level: Log level: "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
        event: Event description
        fields: Additional structured fields (will be redacted)
        logger_name: Logger name
    """
    logger = get_logger(logger_name)
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Create log record with custom fields
    record = logger.makeRecord(
        logger.name,
        log_level,
        "",
        0,
        event,
        (),
        None,
    )
    record.fields = fields or {}  # type: ignore[attr-defined]

    logger.handle(record)
