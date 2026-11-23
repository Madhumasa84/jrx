"""User-only, bounded Unix IPC. This service evaluates data; it never executes actions."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import socket
import ssl
import stat
import struct
import sys
import threading
import time
import uuid
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import ReflexConfig, parse_local_base_url
from .logging_config import debug as debug
from .logging_config import log_structured, setup_logging
from .metrics import BrokerMetrics, get_registry, jev_signal_latency_seconds
from .models import EvaluationContext, RiskInfo, SemanticSignals
from .redaction import redact_text

PROTOCOL_VERSION = 1
MAX_BYTES = 262_144
MAX_CLOCK_SKEW_SECONDS = 300
MAX_METRICS_HEADER_BYTES = 8192
METRICS_HEADER_TIMEOUT = 5
ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_PEER_CREDENTIALS = struct.Struct("iII")


def socket_path(config: ReflexConfig) -> Path:
    return Path(config.jev.socket).expanduser().absolute()


def secure_directory(path: Path, *, create: bool = False) -> None:
    if path.resolve() != path:
        raise ValueError("broker directory must not use symbolic links")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if create and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid():
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if info.st_uid == os.getuid():
                os.fchmod(descriptor, 0o700)
                info = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("broker directory must be owned by the current user with mode 0700")
    if path.resolve() != path:
        raise ValueError("broker directory must not use symbolic links")


def verify_socket(path: Path) -> None:
    secure_directory(path.parent)
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("unsafe broker socket")


def _verify_unix_peer(connection: socket.socket) -> None:
    """Check the live Unix peer where Linux exposes kernel credentials."""
    if sys.platform == "linux" and hasattr(socket, "SO_PEERCRED"):
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER_CREDENTIALS.size
        )
        if len(credentials) != _PEER_CREDENTIALS.size:
            raise PermissionError("broker peer credentials are unavailable")
        _, uid, _ = _PEER_CREDENTIALS.unpack(credentials)
        if uid != os.getuid():
            raise PermissionError("unsafe broker peer")


def _local_endpoint_digest(config: ReflexConfig) -> str | None:
    settings = config.evaluator
    if settings.local_base_url is None:
        return None
    url = parse_local_base_url(
        settings.local_base_url, allow_non_loopback_http=settings.allow_non_loopback_http
    )
    return hashlib.sha256(url.geturl().rstrip("/").encode()).hexdigest()


def encode(value: dict[str, Any]) -> bytes:
    data = json.dumps(value, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    if len(data) > MAX_BYTES:
        raise ValueError("message exceeds size limit")
    return data


def _validate_response(result: Any, request_id: str) -> dict[str, Any]:
    if (
        not isinstance(result, dict)
        or result.get("protocol_version") != PROTOCOL_VERSION
        or result.get("request_id") != request_id
    ):
        raise ValueError("invalid broker response")
    server_time = result.get("server_time")
    if not isinstance(server_time, (int, float)) or isinstance(server_time, bool):
        raise ValueError("broker clock skew exceeds limit")
    if not math.isfinite(server_time) or abs(time.time() - server_time) > MAX_CLOCK_SKEW_SECONDS:
        raise ValueError("broker clock skew exceeds limit")
    return result


class BrokerClient:
    """SemanticEvaluator implementation. Never loads credentials or falls back to direct."""

    def __init__(self, config: ReflexConfig | None = None) -> None:
        self.config = config or ReflexConfig()
        self.last_api_requests: int | None = 0
        self.last_jev_latency_ms: float | None = None
        self.last_usage: dict[str, int] | None = None

    def request(self, operation: str, **fields: Any) -> dict[str, Any]:
        if self.config.jev.transport == "broker-tls":
            return self._request_tls(operation, **fields)
        return self._request_unix(operation, **fields)

    def _request_unix(self, operation: str, **fields: Any) -> dict[str, Any]:
        path = socket_path(self.config)
        verify_socket(path)
        request_id = uuid.uuid4().hex
        message = encode(
            dict(protocol_version=1, request_id=request_id, operation=operation, **fields)
        )
        started = time.monotonic()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.config.jev.connect_timeout)
            connection.connect(str(path))
            _verify_unix_peer(connection)
            deadline = time.monotonic() + self.config.jev.request_timeout
            connection.settimeout(self.config.jev.request_timeout)
            connection.sendall(message)
            if operation == "evaluate":
                # If the response is lost, an API call may still have been started.
                self.last_api_requests = None
            data = bytearray()
            while b"\n" not in data:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("broker deadline exceeded")
                connection.settimeout(remaining)
                chunk = connection.recv(min(4096, MAX_BYTES + 1 - len(data)))
                if not chunk:
                    raise ValueError("incomplete broker response")
                data.extend(chunk)
                if len(data) > MAX_BYTES:
                    raise ValueError("oversized broker response")
        result = json.loads(data)
        result = _validate_response(result, request_id)
        debug(
            request_id=request_id, broker_latency_ms=round((time.monotonic() - started) * 1000, 2)
        )
        return result

    def _request_tls(self, operation: str, **fields: Any) -> dict[str, Any]:
        """Request over TLS with mutual authentication."""
        tls_config = self.config.jev.broker_tls
        if not tls_config:
            raise ValueError("broker_tls configuration is required for TLS client")

        # Parse server address
        host, port_str = tls_config.listen_addr.rsplit(":", 1)
        port = int(port_str)

        # Expand paths
        cert_path = Path(tls_config.cert_path).expanduser()
        key_path = Path(tls_config.key_path).expanduser()
        client_ca_path = Path(tls_config.client_ca_path).expanduser()

        # Verify files exist
        if not cert_path.exists():
            raise ValueError(f"TLS client cert file not found: {cert_path}")
        if not key_path.exists():
            raise ValueError(f"TLS client key file not found: {key_path}")
        if not client_ca_path.exists():
            raise ValueError(f"TLS client CA file not found: {client_ca_path}")

        # Create an authenticated client context using the standard library API.
        ssl_context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            cafile=str(client_ca_path),
        )
        ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        request_id = uuid.uuid4().hex
        message = encode(
            dict(protocol_version=1, request_id=request_id, operation=operation, **fields)
        )
        started = time.monotonic()

        # Create TCP socket and wrap with SSL
        with socket.create_connection(
            (host, port), timeout=self.config.jev.connect_timeout
        ) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=host) as ssl_sock:
                deadline = time.monotonic() + self.config.jev.request_timeout
                ssl_sock.settimeout(self.config.jev.request_timeout)
                ssl_sock.sendall(message)
                if operation == "evaluate":
                    # If the response is lost, an API call may still have been started.
                    self.last_api_requests = None
                data = bytearray()
                while b"\n" not in data:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("broker deadline exceeded")
                    ssl_sock.settimeout(remaining)
                    chunk = ssl_sock.recv(min(4096, MAX_BYTES + 1 - len(data)))
                    if not chunk:
                        raise ValueError("incomplete broker response")
                    data.extend(chunk)
                    if len(data) > MAX_BYTES:
                        raise ValueError("oversized broker response")

        result = json.loads(data)
        result = _validate_response(result, request_id)
        debug(
            request_id=request_id, broker_latency_ms=round((time.monotonic() - started) * 1000, 2)
        )
        return result

    def health(self) -> dict[str, Any]:
        try:
            response = self.request("health")
            if response.get("status") != "ok":
                raise ValueError("unhealthy broker")
            transport_info = str(socket_path(self.config))
            if self.config.jev.transport == "broker-tls" and self.config.jev.broker_tls:
                transport_info = self.config.jev.broker_tls.listen_addr
            health = {
                "running": True,
                "socket": transport_info,
                "jev_configured": response.get("jev_configured") is True,
                "protocol_version": 1,
                "pid": response.get("pid") if type(response.get("pid")) is int else None,
            }
            if isinstance(response.get("local_evaluator"), dict):
                health["local_evaluator"] = response["local_evaluator"]
            return health
        except (OSError, ValueError):
            transport_info = str(socket_path(self.config))
            if self.config.jev.transport == "broker-tls" and self.config.jev.broker_tls:
                transport_info = self.config.jev.broker_tls.listen_addr
            return {
                "running": False,
                "socket": transport_info,
                "jev_configured": False,
                "protocol_version": 1,
            }

    def evaluate(self, context: EvaluationContext) -> SemanticSignals:
        from .evaluator import JUDGMENT_NAMES, _redacted_context, compact_state

        self.last_api_requests = 0
        self.last_jev_latency_ms = None
        self.last_usage = None
        try:
            state = compact_state(context, self.config.context.max_context_chars)
            fields: dict[str, Any] = {}
            provider = self.config.evaluator.provider
            if provider != "jev":
                fields = {
                    "provider": provider,
                    "model_id": self.config.evaluator.local_model,
                    "state_truncated": (
                        context.semantic_state_truncated
                        or state != _redacted_context(context).to_jev_state()
                    ),
                }
                if endpoint := _local_endpoint_digest(self.config):
                    fields["local_endpoint_digest"] = endpoint
            action = state.pop("proposed_action")
            response = self.request("evaluate", action=action, context=state, **fields)
            count = response.get("api_requests", 0)
            if count is not None and (type(count) is not int or count not in {0, 1}):
                raise ValueError("invalid request count")
            self.last_api_requests = count
            latency = response.get("jev_latency_ms")
            if latency is not None:
                if type(latency) not in {float, int} or not math.isfinite(latency) or latency < 0:
                    raise ValueError("invalid timing")
                self.last_jev_latency_ms = latency
            usage = response.get("usage")
            if isinstance(usage, dict):
                self.last_usage = {
                    name: usage[name]
                    for name in ("input_tokens", "output_tokens", "billing_units")
                    if type(usage.get(name)) is int and usage[name] >= 0
                } or None
            if response.get("status") == "ok" and response.get("source") == "local":
                if provider == "jev":
                    raise ValueError("unexpected local evaluator")
                return self._local_signals(response, context)
            if (
                response.get("status") != "ok"
                or response.get("degraded") is not False
                or response.get("source") != "live_jev"
                or provider == "local"
            ):
                raise ValueError("semantic evaluation unavailable")
            signals = response["signals"]
            if (
                not isinstance(signals, dict)
                or not set(JUDGMENT_NAMES).issubset(signals)
                or set(signals) - set(JUDGMENT_NAMES) - {"tests_needed"}
            ):
                raise ValueError("incomplete or unknown semantic signals")
            return SemanticSignals(
                probabilities={**signals, "tests_needed": signals["needs_tests"]},
                risk=RiskInfo.model_validate(response["risk"]),
                source="broker/live",
            )
        except (OSError, ValueError, KeyError, TypeError):
            return SemanticSignals(
                probabilities={},
                risk=RiskInfo(choice="medium"),
                source="broker/unavailable",
                degraded=True,
                warnings=["Broker semantic evaluation unavailable; fail-safe policy applied."],
            )

    def _local_signals(
        self, response: dict[str, Any], context: EvaluationContext
    ) -> SemanticSignals:
        from .local_evaluator import (
            LOCAL_WARNINGS,
            RISK_QUESTIONS,
            _questions,
            active_local_signals,
        )

        signals = response["signals"]
        warnings = response["warnings"]
        degraded = response["degraded"]
        digest = response.get("model_digest")
        if (
            not isinstance(signals, dict)
            or signals.keys() - RISK_QUESTIONS.keys() - {"tests_needed"}
            or type(degraded) is not bool
            or type(response["truncated"]) is not bool
            or not isinstance(warnings, list)
            or any(not isinstance(item, str) or item not in LOCAL_WARNINGS for item in warnings)
            or (not degraded and not self.config.evaluator.local_base_url and digest is None)
        ):
            raise ValueError("invalid local evaluator response")
        expected = set(_questions(context, self.config))
        if not degraded and expected - signals.keys():
            raise ValueError("broker is missing a requested local signal")
        probabilities = {name: value for name, value in signals.items() if name in expected}
        if "tests_needed" in active_local_signals(self.config) and "needs_tests" in probabilities:
            probabilities["tests_needed"] = probabilities["needs_tests"]
        return SemanticSignals(
            probabilities=probabilities,
            risk=RiskInfo.model_validate(response["risk"]),
            source="local",
            model_digest=digest,
            truncated=response["truncated"],
            degraded=degraded,
            warnings=warnings,
        )


@dataclass(frozen=True)
class _EvaluationResult:
    signals: SemanticSignals | None
    api_requests: int | None
    usage: dict[str, int] | None


class BrokerServer:
    """Single bounded API worker, with concurrent health checks and bounded IPC clients."""

    def __init__(
        self,
        config: ReflexConfig,
        evaluator: Any = None,
        *,
        configured: bool | None = None,
        metrics_host: str = "127.0.0.1",
        metrics_port: int = 9090,
    ) -> None:
        from .evaluator import direct_semantic_backend

        self.config = config
        self.evaluator = evaluator or direct_semantic_backend(config)
        self.local_evaluator = None
        if config.evaluator.provider != "jev":
            from .local_evaluator import LocalSemanticEvaluator

            if isinstance(self.evaluator, LocalSemanticEvaluator):
                self.local_evaluator = self.evaluator
                self.local_evaluator.warm()
                health = self.local_evaluator.health()
                metric = get_registry().get_gauge(
                    "jrx_local_model_warm",
                    "Whether the local ONNX model is warm",
                    labels=["model_id", "model_digest"],
                )
                metric.set(
                    float(health["warm"]),
                    model_id=health["model_id"],
                    model_digest=health["model_digest"] or "",
                )
        # Only the host service reads credential presence. The value is never returned.
        self.configured = (
            configured
            if configured is not None
            else (config.evaluator.provider != "local" and bool(os.environ.get("TYPESAFE_API_KEY")))
        )
        self.stop_event = asyncio.Event()
        self.worker_lock = threading.Lock()
        self.clients = 0
        self.metrics = BrokerMetrics()
        self.metrics_host = metrics_host
        self.metrics_port = metrics_port

        # Setup structured logging
        if config.logging.enabled:
            setup_logging(
                sink=config.logging.sink,
                level=config.logging.level,
                webhook_url=config.logging.webhook_url,
                syslog_ident=config.logging.syslog_ident,
            )

        log_structured(
            level="INFO",
            event="broker_started",
            fields={
                "pid": os.getpid(),
                "jev_configured": self.configured,
                "socket": str(socket_path(config)),
                "metrics_endpoint": f"http://{metrics_host}:{metrics_port}/metrics",
            },
        )

    async def evaluate(self, context: EvaluationContext) -> _EvaluationResult:
        if not self.worker_lock.acquire(blocking=False):
            raise BlockingIOError("busy")
        loop = asyncio.get_running_loop()
        future: asyncio.Future[_EvaluationResult] = loop.create_future()

        def deliver(value: _EvaluationResult) -> None:
            if not future.done():
                future.set_result(value)

        def worker() -> None:
            value = _EvaluationResult(None, None, None)
            try:
                try:
                    signals = self.evaluator.evaluate(context)
                except Exception:
                    signals = None
                api_requests = getattr(self.evaluator, "last_api_requests", 1)
                usage = getattr(self.evaluator, "last_usage", None)
                value = _EvaluationResult(signals, api_requests, dict(usage) if usage else None)
            except Exception:
                pass
            finally:
                self.worker_lock.release()
                try:
                    loop.call_soon_threadsafe(deliver, value)
                except RuntimeError:
                    pass

        try:
            threading.Thread(target=worker, daemon=True).start()
        except RuntimeError:
            self.worker_lock.release()
            raise
        return await asyncio.wait_for(future, self.config.jev.api_timeout)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.clients += 1
        request_id = ""
        response: dict[str, Any] = {}
        evaluating = False
        api_requests: int | None = 0
        started = time.monotonic()
        try:
            if self.clients > 16:
                raise BlockingIOError("busy")
            connection = writer.get_extra_info("socket")
            if connection is not None and connection.family == socket.AF_UNIX:
                _verify_unix_peer(connection)
            raw = await asyncio.wait_for(reader.readuntil(b"\n"), self.config.jev.request_timeout)
            if len(raw) > MAX_BYTES:
                raise OverflowError
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise ValueError
            candidate = request.get("request_id")
            if (
                not isinstance(candidate, str)
                or not ID_PATTERN.fullmatch(candidate)
                or redact_text(candidate) != candidate
            ):
                raise ValueError
            request_id = candidate
            if type(request.get("protocol_version")) is not int or request["protocol_version"] != 1:
                response = {"error_code": "UNSUPPORTED_PROTOCOL"}
            elif request.get("operation", "evaluate") == "health":
                response = {"status": "ok", "jev_configured": self.configured, "pid": os.getpid()}
                if self.local_evaluator is not None:
                    local = self.local_evaluator.health()
                    if warning := local.get("warning"):
                        local["warning"] = f"{warning} Restart the broker after completing the fix."
                    response["local_evaluator"] = local
            elif request.get("operation") == "stop":
                if writer.get_extra_info("ssl_object") is not None:
                    response = {"error_code": "FORBIDDEN"}
                else:
                    response = {"status": "ok"}
                    self.stop_event.set()
            elif request.get("operation", "evaluate") == "evaluate":
                from .evaluator import JUDGMENT_NAMES, _redacted_context

                provider = self.config.evaluator.provider
                supplied_provider = request.get("provider", "jev")
                if provider != supplied_provider:
                    raise ValueError("semantic provider mismatch")
                if provider != "jev":
                    if request.get("model_id") != self.config.evaluator.local_model:
                        raise ValueError("semantic model mismatch")
                    if request.get("local_endpoint_digest") != _local_endpoint_digest(self.config):
                        raise ValueError("semantic endpoint mismatch")
                state_truncated = (
                    request.get("state_truncated", False) if provider != "jev" else False
                )
                if type(state_truncated) is not bool:
                    raise ValueError("invalid state truncation flag")
                context = EvaluationContext.model_validate(
                    {**request["context"], "proposed_action": request["action"]}
                )
                context = _redacted_context(context)
                context.semantic_state_truncated = state_truncated
                api_started = time.monotonic()
                evaluating = True
                api_requests = None
                outcome = await self.evaluate(context)
                api_requests = outcome.api_requests
                semantic = outcome.signals
                if semantic is None:
                    raise ValueError("unavailable")
                if semantic.source == "local" and provider != "jev":
                    from .local_evaluator import LOCAL_WARNINGS, RISK_QUESTIONS

                    signals = {
                        name: value
                        for name, value in semantic.probabilities.items()
                        if name in RISK_QUESTIONS or name == "tests_needed"
                    }
                    response = {
                        "source": "local",
                        "degraded": semantic.degraded,
                        "model_digest": semantic.model_digest,
                        "truncated": semantic.truncated,
                        "warnings": [item for item in semantic.warnings if item in LOCAL_WARNINGS],
                    }
                elif semantic.source == "jev" and provider != "local" and not semantic.degraded:
                    # Never forward SDK prose, warnings, errors or unknown signals.
                    signals = {name: semantic.probabilities[name] for name in JUDGMENT_NAMES}
                    response = {"source": "live_jev", "degraded": False}
                else:
                    raise ValueError("unavailable")
                latency_ms = (time.monotonic() - api_started) * 1000
                response.update(
                    status="ok",
                    signals=signals,
                    risk=semantic.risk.model_dump(),
                    usage=outcome.usage,
                )

                if semantic.source == "jev":
                    response["jev_latency_ms"] = latency_ms
                    jev_signal_latency_seconds.observe(latency_ms / 1000.0)

                debug(
                    request_id=request_id,
                    context_chars=len(raw),
                    jev_latency_ms=response.get("jev_latency_ms"),
                    signals=signals,
                )
            else:
                raise ValueError
        except TimeoutError:
            response = {"error_code": "TIMEOUT"}
            log_structured(
                level="WARNING",
                event="broker_request_timeout",
                fields={"request_id": request_id},
            )
        except BlockingIOError:
            response = {"error_code": "BUSY"}
            api_requests = 0
            log_structured(
                level="WARNING",
                event="broker_busy",
                fields={"request_id": request_id, "clients": self.clients},
            )
        except (OverflowError, asyncio.LimitOverrunError):
            response = {"error_code": "REQUEST_TOO_LARGE"}
            log_structured(
                level="WARNING",
                event="broker_request_too_large",
                fields={"request_id": request_id},
            )
        except Exception:
            response = {"error_code": "JEV_UNAVAILABLE" if evaluating else "INVALID_REQUEST"}
            log_structured(
                level="ERROR",
                event="broker_evaluation_error",
                fields={"request_id": request_id, "evaluating": evaluating},
            )
        finally:
            response["api_requests"] = api_requests
            if "error_code" in response:
                response.update(status="error", degraded=True)
            response.update(protocol_version=1, request_id=request_id, server_time=time.time())
            try:
                writer.write(encode(response))
                await asyncio.wait_for(writer.drain(), 1)
            except (TimeoutError, OSError, ValueError):
                pass
            writer.close()
            self.clients -= 1
            debug(request_id=request_id, broker_latency_ms=(time.monotonic() - started) * 1000)

    async def handle_metrics(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle HTTP requests to /metrics endpoint."""
        try:
            body = b""
            try:
                headers = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), METRICS_HEADER_TIMEOUT
                )
            except TimeoutError:
                status = "408 Request Timeout"
            except asyncio.LimitOverrunError:
                status = "431 Request Header Fields Too Large"
            except asyncio.IncompleteReadError:
                return
            else:
                parts = headers.partition(b"\r\n")[0].split()
                if len(headers) > MAX_METRICS_HEADER_BYTES:
                    status = "431 Request Header Fields Too Large"
                elif len(parts) != 3 or parts[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
                    status = "400 Bad Request"
                elif parts[0] != b"GET":
                    status = "405 Method Not Allowed"
                elif parts[1] != b"/metrics":
                    status = "404 Not Found"
                else:
                    status = "200 OK"
                    body = get_registry().render().encode()
            allow = "Allow: GET\r\n" if status == "405 Method Not Allowed" else ""
            response = (
                f"HTTP/1.1 {status}\r\n"
                "Content-Type: text/plain; version=0.0.4\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"{allow}"
                "Connection: close\r\n\r\n"
            )
            writer.write(response.encode() + body)
            await asyncio.wait_for(writer.drain(), 1)
        except (OSError, TimeoutError):
            pass
        finally:
            writer.close()

    async def run(self) -> None:
        import fcntl
        import signal

        path = socket_path(self.config)
        secure_directory(path.parent, create=True)
        lock_fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        bound = False
        try:
            lock_info = os.fstat(lock_fd)
            if (
                lock_info.st_uid != os.getuid()
                or not stat.S_ISREG(lock_info.st_mode)
                or lock_info.st_mode & 0o077
            ):
                raise ValueError("unsafe lock file")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if path.exists() or path.is_symlink():
                verify_socket(path)
                # A lock protects our lifecycle; never remove an active foreign listener.
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.2)
                    try:
                        probe.connect(str(path))
                    except ConnectionRefusedError:
                        path.unlink()
                    else:
                        raise ValueError("socket already active")
            loop = asyncio.get_running_loop()
            async with AsyncExitStack() as stack:
                for signum in (signal.SIGTERM, signal.SIGINT):
                    loop.add_signal_handler(signum, self.stop_event.set)
                    stack.callback(loop.remove_signal_handler, signum)
                old_mask = os.umask(0o077)
                try:
                    server = await asyncio.start_unix_server(
                        self.handle, path=str(path), limit=MAX_BYTES, start_serving=False
                    )
                    bound = True
                finally:
                    os.umask(old_mask)
                await stack.enter_async_context(server)
                os.chmod(path, 0o600)
                verify_socket(path)
                metrics_server = await asyncio.start_server(
                    self.handle_metrics,
                    host=self.metrics_host,
                    port=self.metrics_port,
                    limit=MAX_METRICS_HEADER_BYTES,
                )
                await stack.enter_async_context(metrics_server)
                if self.config.jev.transport == "broker-tls":
                    await stack.enter_async_context(await self._start_tls_server())

                self.metrics.start_uptime_tracking(loop)
                stack.callback(self.metrics.stop_uptime_tracking)
                # Local probes succeed only after the other listeners are available.
                await server.start_serving()
                log_structured(
                    level="INFO",
                    event="metrics_server_started",
                    fields={"host": self.metrics_host, "port": self.metrics_port},
                )
                print(
                    "Status: running\nJEV: "
                    + ("configured" if self.configured else "not configured")
                    + f"\nPID: {os.getpid()}",
                    flush=True,
                )
                await self.stop_event.wait()
        finally:
            try:
                if bound:
                    path.unlink(missing_ok=True)
            finally:
                os.close(lock_fd)

    async def _start_tls_server(self) -> asyncio.Server:
        """Start TLS server with mutual authentication."""
        tls_config = self.config.jev.broker_tls
        if not tls_config:
            raise ValueError("broker_tls configuration is required for TLS server")

        # Parse listen address
        host, port_str = tls_config.listen_addr.rsplit(":", 1)
        port = int(port_str)

        # Expand paths
        cert_path = Path(tls_config.cert_path).expanduser()
        key_path = Path(tls_config.key_path).expanduser()
        client_ca_path = Path(tls_config.client_ca_path).expanduser()

        # Verify files exist
        if not cert_path.exists():
            raise ValueError(f"TLS cert file not found: {cert_path}")
        if not key_path.exists():
            raise ValueError(f"TLS key file not found: {key_path}")
        if not client_ca_path.exists():
            raise ValueError(f"TLS client CA file not found: {client_ca_path}")

        # Create SSL context for mutual TLS
        ssl_context = ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH,
            cafile=str(client_ca_path),
        )
        ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        # Create server with SSL context
        tls_server = await asyncio.start_server(
            self.handle,
            host=host,
            port=port,
            ssl=ssl_context,
            limit=MAX_BYTES,
        )

        log_structured(
            level="INFO",
            event="tls_server_started",
            fields={
                "listen_addr": tls_config.listen_addr,
                "cert_path": str(cert_path),
                "client_ca_path": str(client_ca_path),
            },
        )

        print(f"TLS: listening on {tls_config.listen_addr}", flush=True)

        return tls_server
