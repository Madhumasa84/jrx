"""Policy enforcing stdio proxy for MCP JSON-RPC tool calls."""

from __future__ import annotations

import hashlib
import json
import math
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry
from referencing.exceptions import NoSuchResource

from .config import MCPToolRule, ReflexConfig
from .context import RepositoryContextProvider, sanitized_child_env
from .enterprise import (
    AccessDenied,
    ApprovalStore,
    Identity,
    authorize,
    mcp_action_binding,
    verified_identity,
)
from .evaluator import evaluate_context
from .models import ProposedAction
from .redaction import looks_secret_key, redact_text
from .session_limits import SessionStore


def _finite_number(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _reject_constant(value: str) -> None:
    raise ValueError("invalid JSON constant")


def _no_remote_schema(uri: str) -> None:
    raise NoSuchResource(uri)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


@dataclass(frozen=True)
class _JSONNumber:
    # Retain the number as sent. Float rounding can make different arguments look identical.
    literal: str


def _load_message(raw: bytes, *, exact_numbers: bool = False) -> Any:
    return json.loads(
        raw,
        parse_float=_JSONNumber if exact_numbers else _finite_number,
        parse_int=_JSONNumber if exact_numbers else int,
        parse_constant=_reject_constant,
        object_pairs_hook=_unique_object,
    )


def _review_json(value: Any) -> str:
    if isinstance(value, _JSONNumber):
        return value.literal
    if isinstance(value, dict):
        if any(looks_secret_key(key) for key in value):
            raise AccessDenied("MCP tool call cannot be reviewed safely")
        return (
            "{"
            + ",".join(f"{_review_json(key)}:{_review_json(value[key])}" for key in sorted(value))
            + "}"
        )
    if isinstance(value, list):
        return "[" + ",".join(map(_review_json, value)) + "]"
    if isinstance(value, str) and redact_text(value) != value:
        raise AccessDenied("MCP tool call cannot be reviewed safely")
    return json.dumps(value, ensure_ascii=True, allow_nan=False)


def _tool_error(request_id: object, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": message}], "isError": True},
    }


def _rpc_error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


@dataclass(frozen=True)
class _ToolReview:
    identity: Identity
    repository: str
    summary: str


@dataclass(frozen=True)
class _PendingTool:
    request_id: object
    timer: threading.Timer
    approved: bool = False

    def error(self, message: str) -> dict[str, Any]:
        if not self.approved:
            return _tool_error(self.request_id, message)
        response = _tool_error(
            self.request_id, f"{message}. MCP approved write outcome is unknown. Approval spent."
        )
        response["result"]["structuredContent"] = {"status": "outcome_unknown"}
        return response


class MCPGateway:
    """Forward stdio MCP traffic while deciding every tools/call locally."""

    def __init__(
        self,
        config: ReflexConfig,
        server_name: str,
        command: list[str],
        *,
        session_id: str | None = None,
        approval_id: str | None = None,
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
        self.approval_id = approval_id
        if config.session.enabled:
            SessionStore._id(self.session_id)
        self._upstream_group: int | None = None
        self._output_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._catalog_lock = threading.Lock()
        self._pending: dict[str, _PendingTool] = {}
        self._upstream_closed = False
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
                # The installed referencing runtime accepts retrieve; its
                # bundled typing omits this constructor keyword.
                registry=Registry(retrieve=_no_remote_schema),  # type: ignore[call-arg]
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

    def _stop_upstream(self, process: subprocess.Popen[bytes]) -> int:
        """Stop the isolated upstream group, including children ignoring SIGTERM."""
        group = self._upstream_group if self._upstream_group == process.pid else None
        if os.name == "posix" and group is None:
            try:
                if os.getpgid(process.pid) == process.pid:
                    group = process.pid
            except ProcessLookupError:
                pass
        try:
            if group is not None:
                os.killpg(group, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            pass
        try:
            return process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait()
        finally:
            # The parent can exit on TERM while its children ignore it.
            if group is not None:
                try:
                    os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def _expired(self, process: subprocess.Popen[bytes], key: str) -> None:
        with self._pending_lock:
            pending = self._pending.pop(key, None)
            if pending is not None:
                self._expired_ids.add(key)
        if pending is not None:
            self._send(pending.error("MCP tool execution time limit reached"))
            self._stop_upstream(process)

    def _read_upstream(self, process: subprocess.Popen[bytes]) -> None:
        assert process.stdout is not None
        try:
            while raw := process.stdout.readline(self.config.mcp.max_message_bytes + 1):
                if len(raw) > self.config.mcp.max_message_bytes or not raw.endswith(b"\n"):
                    self._stop_upstream(process)
                    break
                try:
                    message = _load_message(raw)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    self._stop_upstream(process)
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
                        pending.timer.cancel()
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
                self._upstream_closed = True
                outstanding = list(self._pending.values())
                self._pending.clear()
            for pending in outstanding:
                pending.timer.cancel()
                self._send(pending.error("upstream MCP server stopped"))

    def _authorize_tool(
        self, name: str, arguments: dict[str, Any], request_id: object, raw: bytes
    ) -> tuple[str | None, _ToolReview | None]:
        rule = self._rules.get((self.server_name, name))
        if rule is None:
            return "MCP tool is not permitted by policy", None
        if rule.effect == "destructive":
            return "MCP destructive tool is blocked by policy", None
        if rule.effect == "write" and not self.config.mcp.use_jev:
            return "MCP write tool requires semantic evaluation", None
        if not self._schema_is_verified(name):
            return "MCP tool schema has not been verified against policy", None
        if not self._arguments_match_policy(rule, arguments):
            return "MCP tool arguments do not match policy", None
        provider = RepositoryContextProvider(cwd=Path.cwd())
        context = provider.build(
            user_task=f"MCP {self.server_name}.{name}",
            proposed_action=ProposedAction(
                type=f"mcp:{self.server_name}.{name}",
                input=arguments,
                description=f"{rule.effect} MCP tool call",
            ),
        )
        access = self.config.access
        approval_scope = None
        if access is not None:
            identity = verified_identity(access)
            repository = context.repository_root
            if rule.require_approval:
                repository = str(provider.repository_root() or provider.working_directory)
            authorize(identity, access, "execute", repository, access.environment)
            if rule.require_approval:
                try:
                    summary = self._review_tool_call(request_id, raw)
                except AccessDenied as exc:
                    return str(exc), None
                approval_scope = _ToolReview(identity, repository, summary)
        elif rule.require_approval:
            return "MCP approval requires enterprise access", None
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
            return f"MCP tool blocked: {result.decision}", None
        if rule.effect == "write" and result.semantic_source not in {"jev", "broker/live"}:
            return "MCP write tool requires a live semantic decision", None
        return None, approval_scope

    def _review_tool_call(self, request_id: object, raw: bytes) -> str:
        message = _load_message(raw, exact_numbers=True)
        params = message["params"]
        if (
            message.get("jsonrpc") != "2.0"
            or type(request_id) not in (str, int)
            or set(message) - {"jsonrpc", "id", "method", "params"}
            or set(params) - {"name", "arguments"}
        ):
            raise AccessDenied("MCP approval only supports plain tools/call requests")
        review: dict[str, Any] = {"server": self.server_name, "tool": params["name"]}
        if "arguments" in params:
            review["arguments"] = params["arguments"]
        return _review_json(review)

    def _dispatch_tool(
        self,
        process: subprocess.Popen[bytes],
        request_id: object,
        key: str,
        raw: bytes,
        *,
        approved: bool,
    ) -> None:
        timeout = self.config.mcp.timeout_seconds
        if self.config.session.enabled:
            timeout = min(timeout, self.config.session.max_execution_seconds)
        timer = threading.Timer(timeout, self._expired, args=(process, key))
        with self._pending_lock:
            if self._upstream_closed:
                message = "upstream MCP server is unavailable"
                if approved:
                    message += ". Approval spent."
                self._send(_tool_error(request_id, message))
                return
            self._pending[key] = _PendingTool(request_id, timer, approved)
        timer.start()
        try:
            self._forward_upstream(process, raw)
        except (OSError, ValueError):
            with self._pending_lock:
                pending = self._pending.pop(key, None)
            if pending is not None:
                pending.timer.cancel()
                self._send(pending.error("upstream MCP server is unavailable"))

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
                with self._catalog_lock, self._pending_lock:
                    if key in self._catalog_requests or key in self._pending:
                        self._send(_rpc_error(message["id"], -32600, "Duplicate request ID"))
                        return
                    cursor = params.get("cursor") if isinstance(params, dict) else None
                    generation: int | None
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
            reason, approval_scope = self._authorize_tool(
                params["name"], params.get("arguments", {}), request_id, raw
            )
            if (
                reason is not None
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
            self._send(_tool_error(request_id, "MCP policy or session check failed"))
            return
        if reason is not None:
            self._send(_tool_error(request_id, reason))
            return
        schema_error = "MCP tool schema has not been verified against policy"
        if approval_scope is not None and not self._schema_is_verified(params["name"]):
            self._send(_tool_error(request_id, schema_error))
            return
        if not self._check_approval(request_id, approval_scope):
            return
        # A catalog notification may arrive while evaluation or approval checks are running.
        with self._catalog_lock:
            expected = self._pinned_schemas.get(params["name"])
            if expected is not None and self._validated_schemas.get(params["name"]) != expected:
                if approval_scope is not None:
                    schema_error += ". Approval spent."
                self._send(_tool_error(request_id, schema_error))
                return
            self._dispatch_tool(process, request_id, key, raw, approved=approval_scope is not None)

    def _check_approval(self, request_id: object, scope: _ToolReview | None) -> bool:
        if scope is None:
            if self.approval_id is None:
                return True
            self._send(_tool_error(request_id, "Approval does not match this tool's policy"))
            return False

        access = self.config.access
        assert access is not None
        try:
            environment = access.environment
            binding = mcp_action_binding(self.config, scope.repository, environment, scope.summary)
            store = ApprovalStore(access)
            if self.approval_id is not None:
                store.consume(self.approval_id, scope.identity, binding)
                if self.config.session.enabled:
                    SessionStore(self.config.session).reserve(
                        self.session_id, semantic=0, tool_calls=0
                    )
                return True
            approval_id = store.request(
                scope.identity,
                scope.repository,
                environment,
                binding,
                scope.summary,
                kind="MCP tool call",
            )
        except AccessDenied as exc:
            self._send(_tool_error(request_id, str(exc)))
        except (OSError, ValueError, sqlite3.Error, RecursionError):
            self._send(_tool_error(request_id, "MCP approval or session check failed"))
        else:
            response = _tool_error(request_id, f"MCP tool call pending approval: {approval_id}")
            response["result"]["structuredContent"] = {
                "status": "pending_approval",
                "approval_id": approval_id,
            }
            self._send(response)
        return False

    def run(self) -> int:
        child_env = sanitized_child_env()
        with subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env=child_env,
            shell=False,
            start_new_session=os.name == "posix",
        ) as process:
            if os.name == "posix":
                self._upstream_group = process.pid
            reader = threading.Thread(target=self._read_upstream, args=(process,), daemon=True)
            try:
                reader.start()
                if self.config.session.enabled:

                    def watch_stop() -> None:
                        store = SessionStore(self.config.session)
                        while process.poll() is None:
                            try:
                                if store.status(self.session_id)["stopped"]:
                                    self._stop_upstream(process)
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
                    return self._stop_upstream(process)
            finally:
                try:
                    self._stop_upstream(process)
                finally:
                    if reader.ident is not None:
                        reader.join(timeout=1)
                    self._upstream_group = None
