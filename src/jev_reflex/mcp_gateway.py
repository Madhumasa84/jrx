"""Policy enforcing stdio proxy for MCP JSON-RPC tool calls."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO

from .config import ReflexConfig
from .context import RepositoryContextProvider
from .enterprise import authorize, verified_identity
from .evaluator import evaluate_context
from .models import ProposedAction
from .session_limits import SessionStore


def _tool_error(request_id: object, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": message}], "isError": True},
    }


def _rpc_error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class MCPGateway:
    """Forward stdio MCP traffic while deciding every tools/call locally."""

    def __init__(
        self,
        config: ReflexConfig,
        server_name: str,
        command: list[str],
        *,
        session_id: str | None = None,
        source: BinaryIO | None = None,
        sink: BinaryIO | None = None,
    ) -> None:
        if not server_name or not command:
            raise ValueError("server name and upstream command are required")
        self.config = config
        self.server_name = server_name
        self.command = command
        self.source = source or sys.stdin.buffer
        self.sink = sink or sys.stdout.buffer
        self.session_id = session_id or os.environ.get("JRX_SESSION_ID", "")
        if config.session.enabled:
            SessionStore._id(self.session_id)
        self._output_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending: dict[str, tuple[object, threading.Timer]] = {}
        self._expired_ids: set[str] = set()
        names = [(rule.server, rule.name) for rule in config.mcp.tools]
        if len(names) != len(set(names)):
            raise ValueError("MCP server and tool pairs must be unique")
        self._rules = {(rule.server, rule.name): rule for rule in config.mcp.tools}

    def _send(self, message: Mapping[str, Any]) -> None:
        data = json.dumps(message, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        with self._output_lock:
            self.sink.write(data)
            self.sink.flush()

    def _forward_upstream(self, process: subprocess.Popen[bytes], raw: bytes) -> None:
        if process.poll() is not None or process.stdin is None:
            raise ValueError("upstream MCP server is unavailable")
        process.stdin.write(raw)
        process.stdin.flush()

    def _expired(self, process: subprocess.Popen[bytes], key: str) -> None:
        with self._pending_lock:
            pending = self._pending.pop(key, None)
            if pending is not None:
                self._expired_ids.add(key)
        if pending is not None:
            self._send(_tool_error(pending[0], "MCP tool execution time limit reached"))
            process.terminate()

    def _read_upstream(self, process: subprocess.Popen[bytes]) -> None:
        assert process.stdout is not None
        try:
            while raw := process.stdout.readline(self.config.mcp.max_message_bytes + 1):
                if len(raw) > self.config.mcp.max_message_bytes or not raw.endswith(b"\n"):
                    process.terminate()
                    break
                try:
                    message = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    process.terminate()
                    break
                if isinstance(message, dict) and "id" in message and "method" not in message:
                    key = json.dumps(message["id"], sort_keys=True)
                    with self._pending_lock:
                        pending = self._pending.pop(key, None)
                        expired = key in self._expired_ids
                        self._expired_ids.discard(key)
                    if pending is not None:
                        pending[1].cancel()
                    elif expired:
                        # The request timed out and already received an error.
                        continue
                if isinstance(message, dict):
                    self._send(message)
        finally:
            with self._pending_lock:
                outstanding = list(self._pending.values())
                self._pending.clear()
            for request_id, timer in outstanding:
                timer.cancel()
                self._send(_tool_error(request_id, "upstream MCP server stopped"))

    def _authorize_tool(self, name: str, arguments: dict[str, Any]) -> tuple[bool, str]:
        rule = self._rules.get((self.server_name, name))
        if rule is None:
            return False, "MCP tool is not permitted by policy"
        if rule.effect == "destructive":
            return False, "MCP destructive tool is blocked by policy"
        if rule.effect == "write" and not self.config.mcp.use_jev:
            return False, "MCP write tool requires semantic evaluation"
        provider = RepositoryContextProvider(cwd=Path.cwd())
        context = provider.build(
            user_task=f"MCP {self.server_name}.{name}",
            proposed_action=ProposedAction(
                type=f"mcp:{self.server_name}.{name}",
                input=arguments,
                description=f"{rule.effect} MCP tool call",
            ),
        )
        if self.config.access is not None:
            identity = verified_identity(self.config.access)
            authorize(
                identity,
                self.config.access,
                "execute",
                context.repository_root,
                self.config.access.environment,
            )
        result = evaluate_context(
            context,
            config=self.config,
            use_jev=self.config.mcp.use_jev,
            samples=self.config.jev.samples,
            session_id=self.session_id,
            session_tool_calls=0,
        )
        if self.config.session.enabled:
            SessionStore(self.config.session).reserve(self.session_id, semantic=0, tool_calls=0)
        if result.degraded or result.decision != "ALLOW":
            return False, f"MCP tool blocked: {result.decision}"
        if rule.effect == "write" and result.semantic_source not in {"jev", "broker/live"}:
            return False, "MCP write tool requires a live semantic decision"
        return True, ""

    def _handle(self, process: subprocess.Popen[bytes], raw: bytes) -> None:
        if len(raw) > self.config.mcp.max_message_bytes:
            self._send(_rpc_error(None, -32600, "MCP message exceeds configured limit"))
            return
        try:
            message = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self._send(_rpc_error(None, -32700, "Invalid JSON"))
            return
        if not isinstance(message, dict):
            self._send(_rpc_error(None, -32600, "Invalid JSON-RPC message"))
            return
        if message.get("method") != "tools/call":
            self._forward_upstream(process, raw)
            return
        request_id = message.get("id")
        if request_id is None:
            self._send(_rpc_error(None, -32600, "Tool call requires a request ID"))
            return
        params = message.get("params")
        if (
            not isinstance(params, dict)
            or not isinstance(params.get("name"), str)
            or not isinstance(params.get("arguments", {}), dict)
        ):
            self._send(_rpc_error(request_id, -32602, "Invalid tool call parameters"))
            return
        try:
            if self.config.session.enabled:
                SessionStore(self.config.session).reserve(self.session_id, semantic=0, tool_calls=1)
            allowed, reason = self._authorize_tool(params["name"], params.get("arguments", {}))
            if (
                not allowed
                and self.config.session.enabled
                and not reason.startswith("MCP tool blocked:")
            ):
                SessionStore(self.config.session).record_risky(
                    self.session_id,
                    json.dumps(
                        {"name": params["name"], "arguments": params.get("arguments", {})},
                        sort_keys=True,
                    ),
                )
        except Exception:
            allowed, reason = False, "MCP policy or session check failed"
        if not allowed:
            self._send(_tool_error(request_id, reason))
            return
        key = json.dumps(request_id, sort_keys=True)
        timeout = self.config.mcp.timeout_seconds
        if self.config.session.enabled:
            timeout = min(timeout, self.config.session.max_execution_seconds)
        timer = threading.Timer(timeout, self._expired, args=(process, key))
        with self._pending_lock:
            if key in self._pending:
                self._send(_rpc_error(request_id, -32600, "Duplicate request ID"))
                return
            self._pending[key] = (request_id, timer)
        timer.start()
        try:
            self._forward_upstream(process, raw)
        except (OSError, ValueError):
            with self._pending_lock:
                pending = self._pending.pop(key, None)
            if pending is not None:
                pending[1].cancel()
            self._send(_tool_error(request_id, "upstream MCP server is unavailable"))

    def run(self) -> int:
        with subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            shell=False,
        ) as process:
            reader = threading.Thread(target=self._read_upstream, args=(process,), daemon=True)
            reader.start()
            if self.config.session.enabled:

                def watch_stop() -> None:
                    store = SessionStore(self.config.session)
                    while process.poll() is None:
                        try:
                            if store.status(self.session_id)["stopped"]:
                                process.terminate()
                                return
                        except ValueError:
                            pass
                        time.sleep(0.1)

                threading.Thread(target=watch_stop, daemon=True).start()
            while raw := self.source.readline(self.config.mcp.max_message_bytes + 1):
                if len(raw) > self.config.mcp.max_message_bytes or not raw.endswith(b"\n"):
                    self._send(_rpc_error(None, -32600, "MCP message exceeds configured limit"))
                    break
                self._handle(process, raw)
            if process.stdin:
                process.stdin.close()
            try:
                return process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    return process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    return process.wait()
