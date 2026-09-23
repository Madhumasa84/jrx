"""User-only, bounded Unix IPC. This service evaluates data; it never executes actions."""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import socket
import ssl
import stat
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .config import ReflexConfig
from .logging_config import log_structured, setup_logging
from .metrics import BrokerMetrics, get_registry, jev_signal_latency_seconds
from .models import EvaluationContext, RiskInfo, SemanticSignals
from .redaction import redact_text

PROTOCOL_VERSION = 1
MAX_BYTES = 262_144
ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


def socket_path(config: ReflexConfig) -> Path:
    return Path(config.jev.socket).expanduser().absolute()


def secure_directory(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            if path.stat().st_uid == os.getuid():
                path.chmod(0o700)
        except OSError:
            pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("broker directory must be owned by the current user with mode 0700")
    if path.resolve() != path:
        raise ValueError("broker directory must not use symbolic links")


def verify_socket(path: Path) -> None:
    secure_directory(path.parent)
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("unsafe broker socket")


def encode(value: dict[str, Any]) -> bytes:
    data = json.dumps(value, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    if len(data) > MAX_BYTES:
        raise ValueError("message exceeds size limit")
    return data


def debug(**fields: Any) -> None:
    # Callers supply only fixed labels, numeric metrics and validated IDs.
    if os.environ.get("JRX_DEBUG") == "1":
        print(json.dumps(fields, separators=(",", ":")), file=sys.stderr, flush=True)


class BrokerClient:
    """SemanticEvaluator implementation. Never loads credentials or falls back to direct."""

    def __init__(self, config: ReflexConfig | None = None) -> None:
        self.config = config or ReflexConfig()
        self.last_api_requests = 0
        self.last_jev_latency_ms = None
        self.last_usage = None

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
        if (
            not isinstance(result, dict)
            or result.get("protocol_version") != 1
            or result.get("request_id") != request_id
        ):
            raise ValueError("invalid broker response")
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
        ssl_context.check_hostname = False  # Don't verify hostname for simplicity

        request_id = uuid.uuid4().hex
        message = encode(
            dict(protocol_version=1, request_id=request_id, operation=operation, **fields)
        )
        started = time.monotonic()

        # Create TCP socket and wrap with SSL
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.jev.connect_timeout)
        try:
            sock.connect((host, port))
            ssl_sock = ssl_context.wrap_socket(sock, server_hostname=host)

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
        finally:
            try:
                ssl_sock.close()
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass

        result = json.loads(data)
        if (
            not isinstance(result, dict)
            or result.get("protocol_version") != 1
            or result.get("request_id") != request_id
        ):
            raise ValueError("invalid broker response")
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
            return {
                "running": True,
                "socket": transport_info,
                "jev_configured": response.get("jev_configured") is True,
                "protocol_version": 1,
                "pid": response.get("pid") if type(response.get("pid")) is int else None,
            }
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
        from .evaluator import JUDGMENT_NAMES, compact_state

        self.last_api_requests = 0
        self.last_jev_latency_ms = None
        self.last_usage = None
        try:
            state = compact_state(context, self.config.context.max_context_chars)
            action = state.pop("proposed_action")
            response = self.request("evaluate", action=action, context=state)
            count = response.get("api_requests", 0)
            if type(count) is not int or count not in {0, 1}:
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
            if (
                response.get("status") != "ok"
                or response.get("degraded") is not False
                or response.get("source") != "live_jev"
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
        from .evaluator import JEVSemanticEvaluator

        self.config = config
        self.evaluator = evaluator or JEVSemanticEvaluator(config)
        # Only the host service reads credential presence. The value is never returned.
        self.configured = (
            bool(os.environ.get("TYPESAFE_API_KEY")) if configured is None else configured
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

    async def evaluate(self, context: EvaluationContext) -> SemanticSignals:
        if not self.worker_lock.acquire(blocking=False):
            raise BlockingIOError("busy")
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        def deliver(value: SemanticSignals | None) -> None:
            if not future.done():
                future.set_result(value)

        def worker() -> None:
            value = None
            try:
                value = self.evaluator.evaluate(context)
            except Exception:
                pass
            finally:
                self.worker_lock.release()
                try:
                    loop.call_soon_threadsafe(deliver, value)
                except RuntimeError:
                    pass

        threading.Thread(target=worker, daemon=True).start()
        result = await asyncio.wait_for(future, self.config.jev.api_timeout)
        if result is None or result.degraded or result.source != "jev":
            raise ValueError("unavailable")
        return result

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.clients += 1
        request_id = ""
        response: dict[str, Any] = {}
        evaluating = False
        started = time.monotonic()
        try:
            if self.clients > 16:
                raise BlockingIOError("busy")
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
            elif request.get("operation") == "stop":
                response = {"status": "ok"}
                self.stop_event.set()
            elif request.get("operation", "evaluate") == "evaluate":
                from .evaluator import JUDGMENT_NAMES, _redacted_context

                context = EvaluationContext.model_validate(
                    {**request["context"], "proposed_action": request["action"]}
                )
                context = _redacted_context(context)
                api_started = time.monotonic()
                evaluating = True
                semantic = await self.evaluate(context)
                # Whitelist primitive outputs; never forward SDK prose, warnings or errors.
                signals = {name: semantic.probabilities[name] for name in JUDGMENT_NAMES}
                latency_ms = (time.monotonic() - api_started) * 1000
                response = {
                    "status": "ok",
                    "signals": signals,
                    "risk": semantic.risk.model_dump(),
                    "degraded": False,
                    "source": "live_jev",
                    "jev_latency_ms": latency_ms,
                    "usage": getattr(self.evaluator, "last_usage", None),
                }

                # Track JEV latency
                jev_signal_latency_seconds.observe(latency_ms / 1000.0)

                debug(
                    request_id=request_id,
                    context_chars=len(raw),
                    jev_latency_ms=response["jev_latency_ms"],
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
            response["api_requests"] = (
                getattr(getattr(self.evaluator, "gateway", self.evaluator), "last_api_requests", 1)
                if evaluating and response.get("error_code") != "BUSY"
                else 0
            )
            if "error_code" in response:
                response.update(status="error", degraded=True)
            response.update(protocol_version=1, request_id=request_id)
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
            request_line = await reader.readline()
            if not request_line:
                return

            request = request_line.decode().strip()
            if not request.startswith("GET "):
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                await writer.drain()
                writer.close()
                return

            # Parse the request path
            parts = request.split()
            if len(parts) < 2:
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                writer.close()
                return

            path = parts[1]

            # Only serve /metrics endpoint
            if path != "/metrics":
                writer.write(b"HTTP/1.1 404 Not Found\r\n\r\n")
                await writer.drain()
                writer.close()
                return

            # Read and discard headers
            while True:
                header_line = await reader.readline()
                if not header_line or header_line == b"\r\n":
                    break

            # Render metrics
            metrics_data = get_registry().render()

            # Send HTTP response
            response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: text/plain; version=0.0.4\r\n"
                f"Content-Length: {len(metrics_data)}\r\n"
                f"\r\n"
                f"{metrics_data}"
            ).encode()

            writer.write(response)
            await writer.drain()
            writer.close()

        except Exception:
            writer.write(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
            await writer.drain()
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
            old_mask = os.umask(0o077)
            try:
                server = await asyncio.start_unix_server(
                    self.handle, path=str(path), limit=MAX_BYTES
                )
                bound = True
            finally:
                os.umask(old_mask)
            os.chmod(path, 0o600)
            verify_socket(path)
            print(
                "Status: running\nJEV: "
                + ("configured" if self.configured else "not configured")
                + f"\nPID: {os.getpid()}",
                flush=True,
            )
            loop = asyncio.get_running_loop()

            # Start uptime tracking
            self.metrics.start_uptime_tracking(loop)

            # Start HTTP metrics server
            metrics_server = await asyncio.start_server(
                self.handle_metrics,
                host=self.metrics_host,
                port=self.metrics_port,
            )

            log_structured(
                level="INFO",
                event="metrics_server_started",
                fields={
                    "host": self.metrics_host,
                    "port": self.metrics_port,
                },
            )

            # Start TLS server if configured
            tls_server = None
            if self.config.jev.transport == "broker-tls" and self.config.jev.broker_tls:
                tls_server = await self._start_tls_server()

            for signum in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(signum, self.stop_event.set)

            # Run servers
            async with server, metrics_server:
                if tls_server:
                    # Start TLS server as a task
                    tls_task = asyncio.create_task(tls_server.serve_forever())
                    try:
                        await self.stop_event.wait()
                    finally:
                        tls_task.cancel()
                        try:
                            await tls_task
                        except asyncio.CancelledError:
                            pass
                else:
                    await self.stop_event.wait()
        finally:
            if bound:
                path.unlink(missing_ok=True)
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
        ssl_context.check_hostname = False  # Don't verify hostname for simplicity

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
