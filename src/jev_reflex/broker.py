"""User-only, bounded Unix IPC. This service evaluates data; it never executes actions."""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import socket
import stat
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .config import ReflexConfig
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

    def health(self) -> dict[str, Any]:
        try:
            response = self.request("health")
            if response.get("status") != "ok":
                raise ValueError("unhealthy broker")
            return {
                "running": True,
                "socket": str(socket_path(self.config)),
                "jev_configured": response.get("jev_configured") is True,
                "protocol_version": 1,
                "pid": response.get("pid") if type(response.get("pid")) is int else None,
            }
        except (OSError, ValueError):
            return {
                "running": False,
                "socket": str(socket_path(self.config)),
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
        self, config: ReflexConfig, evaluator: Any = None, *, configured: bool | None = None
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
                response = {
                    "status": "ok",
                    "signals": signals,
                    "risk": semantic.risk.model_dump(),
                    "degraded": False,
                    "source": "live_jev",
                    "jev_latency_ms": (time.monotonic() - api_started) * 1000,
                    "usage": getattr(self.evaluator, "last_usage", None),
                }
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
        except BlockingIOError:
            response = {"error_code": "BUSY"}
        except (OverflowError, asyncio.LimitOverrunError):
            response = {"error_code": "REQUEST_TOO_LARGE"}
        except Exception:
            response = {"error_code": "JEV_UNAVAILABLE" if evaluating else "INVALID_REQUEST"}
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
            for signum in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(signum, self.stop_event.set)
            async with server:
                await self.stop_event.wait()
        finally:
            if bound:
                path.unlink(missing_ok=True)
            os.close(lock_fd)
