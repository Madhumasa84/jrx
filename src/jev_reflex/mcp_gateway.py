"""Policy enforcing stdio proxy for MCP JSON-RPC tool calls."""

from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry
from referencing.exceptions import NoSuchResource

from .config import MCPToolRule, ReflexConfig
from .context import RepositoryContextProvider
from .enterprise import authorize, verified_identity
from .evaluator import evaluate_context
from .models import ProposedAction
from .session_limits import SessionStore


def _finite_number(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _reject_constant(value: str) -> None:
    raise ValueError("invalid JSON constant")


def _no_remote_schema(uri: str) -> None:
    raise NoSuchResource(ref=uri)


def _load_message(raw: bytes) -> Any:
    return json.loads(raw, parse_float=_finite_number, parse_constant=_reject_constant)


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
        self._catalog_lock = threading.Lock()
        self._pending: dict[str, tuple[object, threading.Timer]] = {}
        self._expired_ids: set[str] = set()
        names = [(rule.server, rule.name) for rule in config.mcp.tools]
        if len(names) != len(set(names)):
            raise ValueError("MCP server and tool pairs must be unique")
        self._rules = {(rule.server, rule.name): rule for rule in config.mcp.tools}
        self._pinned_schemas = {
            rule.name: rule.expected_input_schema_sha256
            for rule in config.mcp.tools
            if rule.server == server_name and rule.expected_input_schema_sha256 is not None
        }
        self._validated_schemas: dict[str, str] = {}
        self._catalog_generation = 0
        self._catalog_cursors: dict[str, int] = {}
        self._catalog_requests: dict[str, int | None] = {}
        self._argument_validators = {
            (rule.server, rule.name): Draft202012Validator(
                rule.argument_schema,
                format_checker=FormatChecker(),
                registry=Registry(retrieve=_no_remote_schema),
            )
            for rule in config.mcp.tools
            if rule.argument_schema is not None
        }

    def _invalidate_catalog_locked(self) -> None:
        self._catalog_generation += 1
        self._validated_schemas.clear()
        self._catalog_cursors.clear()

    def _validate_tool_catalog(
        self, response: dict[str, Any], generation: int | None
    ) -> str | None:
        """Validate each catalog page atomically; rejection revokes the entire scan."""
        if not self._pinned_schemas:
            return None
        with self._catalog_lock:
            if generation is None or generation != self._catalog_generation:
                return "MCP tool catalog scan is stale or unverified"

            def reject(reason: str) -> str:
                self._invalidate_catalog_locked()
                return reason

            if "error" in response:
                self._invalidate_catalog_locked()
                return None
            result = response.get("result")
            if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                return reject("MCP tool catalog does not match policy")
            validated = dict(self._validated_schemas)
            for tool in result["tools"]:
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                    return reject("MCP tool catalog does not match policy")
                name = tool["name"]
                if name not in self._pinned_schemas:
                    continue
                if name in validated:
                    return reject("MCP tool catalog contains a duplicate pinned tool")
                schema = tool.get("inputSchema")
                if not isinstance(schema, dict):
                    return reject("MCP tool catalog does not match policy")
                try:
                    canonical = json.dumps(
                        schema,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                except (TypeError, ValueError, UnicodeError):
                    return reject("MCP tool catalog does not match policy")
                digest = hashlib.sha256(canonical).hexdigest()
                if digest != self._pinned_schemas[name]:
                    return reject("MCP tool schema changed from the pinned policy")
                validated[name] = digest
            next_cursor = result.get("nextCursor")
            if next_cursor is not None:
                if not isinstance(next_cursor, str) or not next_cursor:
                    return reject("MCP tool catalog does not match policy")
                self._catalog_cursors[next_cursor] = generation
            elif set(self._pinned_schemas) - set(validated):
                return reject("MCP tool catalog is missing a pinned tool")
            self._validated_schemas = validated
        return None

    def _schema_is_verified(self, name: str) -> bool:
        expected = self._pinned_schemas.get(name)
        if expected is None:
            return True
        with self._catalog_lock:
            return self._validated_schemas.get(name) == expected

    @staticmethod
    def _pointer_value(arguments: dict[str, Any], pointer: str) -> Any:
        value: Any = arguments
        for segment in pointer[1:].split("/"):
            key = segment.replace("~1", "/").replace("~0", "~")
            if isinstance(value, dict):
                value = value[key]
            elif (
                isinstance(value, list)
                and key.isdecimal()
                and (key == "0" or not key.startswith("0"))
            ):
                value = value[int(key)]
            else:
                raise KeyError(pointer)
        return value

    @staticmethod
    def _same_json_value(actual: object, allowed: object) -> bool:
        if isinstance(actual, bool) or isinstance(allowed, bool):
            return type(actual) is type(allowed) and actual == allowed
        if isinstance(actual, int | float) and isinstance(allowed, int | float):
            return actual == allowed
        return type(actual) is type(allowed) and actual == allowed

    def _arguments_match_policy(self, rule: MCPToolRule, arguments: dict[str, Any]) -> bool:
        validator = self._argument_validators.get((rule.server, rule.name))
        if validator is not None:
            try:
                validator.validate(arguments)
            except ValidationError:
                return False
        for pointer, allowed_values in rule.argument_constraints.items():
            try:
                actual = self._pointer_value(arguments, pointer)
            except (KeyError, IndexError, ValueError):
                return False
            if not any(self._same_json_value(actual, allowed) for allowed in allowed_values):
                return False
        return True

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
                    message = _load_message(raw)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    process.terminate()
                    break
                if (
                    isinstance(message, dict)
                    and message.get("method") == "notifications/tools/list_changed"
                ):
                    with self._catalog_lock:
                        self._invalidate_catalog_locked()
                if isinstance(message, dict) and "id" in message and "method" not in message:
                    key = json.dumps(message["id"], sort_keys=True)
                    with self._pending_lock:
                        pending = self._pending.pop(key, None)
                        is_catalog_request = key in self._catalog_requests
                        catalog_generation = self._catalog_requests.pop(key, None)
                        expired = key in self._expired_ids
                        self._expired_ids.discard(key)
                    if pending is not None:
                        pending[1].cancel()
                    elif expired:
                        # The request timed out and already received an error.
                        continue
                    if is_catalog_request:
                        mismatch = self._validate_tool_catalog(message, catalog_generation)
                        if mismatch:
                            self._send(_rpc_error(message["id"], -32002, mismatch))
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
        if not self._schema_is_verified(name):
            return False, "MCP tool schema has not been verified against policy"
        if not self._arguments_match_policy(rule, arguments):
            return False, "MCP tool arguments do not match policy"
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
            message = _load_message(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            self._send(_rpc_error(None, -32700, "Invalid JSON"))
            return
        if not isinstance(message, dict):
            self._send(_rpc_error(None, -32600, "Invalid JSON-RPC message"))
            return
        if message.get("method") != "tools/call":
            if message.get("method") == "tools/list" and message.get("id") is not None:
                params = message.get("params")
                key = json.dumps(message["id"], sort_keys=True)
                with self._pending_lock:
                    if key in self._catalog_requests or key in self._pending:
                        self._send(_rpc_error(message["id"], -32600, "Duplicate request ID"))
                        return
                    with self._catalog_lock:
                        cursor = params.get("cursor") if isinstance(params, dict) else None
                        if cursor is None:
                            self._invalidate_catalog_locked()
                            generation = self._catalog_generation
                        elif isinstance(cursor, str):
                            generation = self._catalog_cursors.get(cursor)
                        else:
                            generation = None
                    self._catalog_requests[key] = generation
            self._forward_upstream(process, raw)
            return
        request_id = message.get("id")
        if request_id is None:
            self._send(_rpc_error(None, -32600, "Tool call requires a request ID"))
            return
        key = json.dumps(request_id, sort_keys=True)
        with self._pending_lock:
            if key in self._pending or key in self._catalog_requests:
                self._send(_rpc_error(request_id, -32600, "Duplicate request ID"))
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
            # A catalog notification may arrive while semantic evaluation is running.
            with self._catalog_lock:
                expected = self._pinned_schemas.get(params["name"])
                revoked = (
                    expected is not None and self._validated_schemas.get(params["name"]) != expected
                )
                if not revoked:
                    self._forward_upstream(process, raw)
            if revoked:
                with self._pending_lock:
                    pending = self._pending.pop(key, None)
                if pending is not None:
                    pending[1].cancel()
                self._send(
                    _tool_error(request_id, "MCP tool schema has not been verified against policy")
                )
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
