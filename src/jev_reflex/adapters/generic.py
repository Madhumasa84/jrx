"""Shared input normalization for agent hook adapters."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any, Literal, Protocol, TextIO

from ..config import ReflexConfig
from ..context import ContextProvider, RepositoryContextProvider
from ..models import EvaluationContext, EvaluationResult, HookAuditCorrelation, ProposedAction

MAX_HOOK_CHARS = 1_048_576
_SAFE_HOOK_TOOL = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class Adapter(Protocol):
    """Stable contract for translating a host event into a JEV result."""

    def evaluate(
        self,
        payload: Mapping[str, Any],
        *,
        config: ReflexConfig,
        demo: bool = False,
    ) -> tuple[EvaluationResult, dict[str, Any]]: ...


def read_hook_payload(stream: TextIO | None = None) -> dict[str, Any]:
    """Read one JSON hook event without passing the raw payload onward."""

    source = stream or sys.stdin
    raw = source.read(MAX_HOOK_CHARS + 1)
    if len(raw) > MAX_HOOK_CHARS:
        raise ValueError("hook input exceeds the size limit")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("hook input must be a JSON object")
    return payload


def _text(payload: Mapping[str, Any], *names: str) -> str:
    for name in names:
        value = payload.get(name)
        if isinstance(value, str):
            return value
    return ""


def _mapping(payload: Mapping[str, Any], *names: str) -> Mapping[str, Any] | None:
    for name in names:
        value = payload.get(name)
        if isinstance(value, Mapping):
            return value
    return None


def _arguments(payload: Mapping[str, Any], *names: str) -> Mapping[str, Any]:
    for name in names:
        value = payload.get(name)
        if isinstance(value, Mapping):
            return value
        if value is not None:
            return {"value": value}
    return {}


def _tool_call(payload: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
    """Extract tool name and arguments from the common harness payload shapes."""

    nested = _mapping(payload, "toolCall", "tool_call", "tool")
    if nested is not None:
        name = _text(nested, "name", "tool_name", "toolName")
        return name, _arguments(nested, "args", "input", "tool_input", "toolInput")

    name = _text(payload, "tool_name", "toolName", "name")
    return name, _arguments(payload, "tool_input", "toolInput", "input", "args")


_COMMAND_FIELDS = ("command", "CommandLine", "commandLine", "cmd", "script")


def _workspace_cwd(payload: Mapping[str, Any], tool_input: Mapping[str, Any]) -> str:
    value = _text(
        payload,
        "cwd",
        "working_directory",
        "workingDirectory",
    ) or _text(tool_input, "Cwd", "cwd", "working_directory", "workingDirectory")
    if value:
        return value

    workspace_paths = payload.get("workspacePaths")
    if isinstance(workspace_paths, Sequence) and not isinstance(workspace_paths, str | bytes):
        for item in workspace_paths:
            if isinstance(item, str) and item:
                return item
    return ""


def _task_text(payload: Mapping[str, Any]) -> str:
    return _text(
        payload,
        "user_task",
        "original_task",
        "task",
        "user_prompt",
        "userPrompt",
        "prompt",
    )


def _context_text(payload: Mapping[str, Any], *names: str) -> str:
    return _text(payload, *names)


def _changed_files(payload: Mapping[str, Any]) -> list[str] | None:
    for name in ("changed_files", "changedFiles"):
        value = payload.get(name)
        if isinstance(value, Sequence) and not isinstance(value, str | bytes):
            return [str(item) for item in value if isinstance(item, str | int | float)]
    return None


def _hook_audit_correlation(
    payload: Mapping[str, Any],
    *,
    provider: str | None,
    tool_name: str,
    tool_input: Mapping[str, Any],
) -> HookAuditCorrelation | None:
    """Build local audit identifiers without retaining native IDs or arguments."""
    native_provider: Literal["codex", "claude", "antigravity"]
    if provider == "codex":
        native_provider = "codex"
    elif provider == "claude":
        native_provider = "claude"
    elif provider == "antigravity":
        native_provider = "antigravity"
    else:
        return None
    session_field = "conversationId" if native_provider == "antigravity" else "session_id"
    session = payload.get(session_field)
    if not isinstance(session, str) or not session or len(session) > 512:
        return None
    if not _SAFE_HOOK_TOOL.fullmatch(tool_name):
        return None
    try:
        canonical_action = json.dumps(
            {"tool": tool_name, "input": tool_input},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    except (TypeError, ValueError):
        return None
    if len(canonical_action) > MAX_HOOK_CHARS:
        return None
    action_hash = hashlib.sha256(
        (native_provider + "\0" + session + "\0" + canonical_action).encode("utf-8")
    ).hexdigest()
    call_id: Any = None
    for key in ("tool_use_id", "tool_call_id", "toolCallId", "stepIdx"):
        candidate = payload.get(key)
        if candidate is not None and isinstance(candidate, str | int):
            call_id = str(candidate)
            break
    call_hash = (
        hashlib.sha256(
            (native_provider + "\0" + session + "\0" + call_id).encode("utf-8")
        ).hexdigest()
        if call_id is not None and len(call_id) <= 512
        else None
    )
    return HookAuditCorrelation(
        provider=native_provider,
        session_sha256=hashlib.sha256(session.encode("utf-8")).hexdigest(),
        tool_name=tool_name,
        action_sha256=action_hash,
        call_sha256=call_hash,
    )


def context_from_hook_payload(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    provider: ContextProvider | None = None,
    provider_key: str | None = None,
) -> EvaluationContext:
    """Convert native agent hook payloads into the public context contract.

    Codex and Claude Code use snake_case fields. Antigravity uses a nested
    ``toolCall`` object with camelCase arguments, while OpenRouter and Pi use
    camelCase tool fields. Keeping normalization here lets every adapter share
    the same bounded context and deterministic checks.
    """

    tool_name, tool_input = _tool_call(payload)
    if not tool_name.strip():
        raise ValueError("hook input is missing a tool name")
    if not tool_input or not any(
        value is not None
        and (not isinstance(value, str) or bool(value.strip()))
        and (not isinstance(value, Mapping) or bool(value))
        and (not isinstance(value, Sequence) or isinstance(value, str | bytes) or bool(value))
        for value in tool_input.values()
    ):
        raise ValueError("hook input is missing tool arguments")
    command = ""
    for name in _COMMAND_FIELDS:
        if name in tool_input:
            value = tool_input[name]
            if not isinstance(value, str) or not value.strip():
                raise ValueError("hook input contains an invalid command")
            command = value
            break
    is_shell = bool(command.strip())
    action = ProposedAction(
        type="shell_command" if is_shell else "tool_call",
        command=command if is_shell else None,
        input=dict(tool_input),
        description=tool_input.get("description")
        if isinstance(tool_input.get("description"), str)
        else None,
    )
    context_provider = provider or RepositoryContextProvider(
        cwd=_path_or_none(_workspace_cwd(payload, tool_input)),
        include_git_diff=config.context.include_git_diff,
        include_changed_files=config.context.include_changed_files,
        include_tests=config.context.include_tests,
        max_diff_chars=config.context.max_diff_chars,
        max_context_chars=config.context.max_context_chars,
    )
    context = context_provider.build(
        user_task=_task_text(payload),
        proposed_action=action,
        recent_context=_context_text(
            payload, "recent_context", "recent_agent_context", "recentContext"
        ),
        external_content=_context_text(
            payload, "external_content", "retrieved_content", "retrievedContent"
        ),
        test_results=_context_text(payload, "test_results", "testResults"),
        changed_files=_changed_files(payload),
    )
    correlation = _hook_audit_correlation(
        payload,
        provider=provider_key,
        tool_name=tool_name,
        tool_input=tool_input,
    )
    return context.model_copy(update={"hook_audit": correlation})


def _path_or_none(value: str) -> Any:
    if not value:
        return None
    from pathlib import Path

    return Path(value)
