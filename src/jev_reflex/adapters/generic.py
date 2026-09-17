"""Shared input normalization for agent hook adapters."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from typing import Any, Protocol, TextIO

from ..config import ReflexConfig
from ..context import ContextProvider, RepositoryContextProvider
from ..models import EvaluationContext, EvaluationResult, ProposedAction


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
    raw = source.read()
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


def _changed_files(payload: Mapping[str, Any]) -> list[str] | None:
    for name in ("changed_files", "changedFiles"):
        value = payload.get(name)
        if isinstance(value, Sequence) and not isinstance(value, str | bytes):
            return [str(item) for item in value if isinstance(item, str | int | float)]
    return None


def context_from_hook_payload(
    payload: Mapping[str, Any],
    *,
    config: ReflexConfig,
    provider: ContextProvider | None = None,
) -> EvaluationContext:
    """Convert Codex/Claude's common PreToolUse shape into the public context contract."""

    tool_name = _text(payload, "tool_name") or "tool_call"
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, Mapping):
        tool_input = {} if tool_input is None else {"value": tool_input}
    command = tool_input.get("command")
    is_shell = tool_name in {"Bash", "PowerShell", "Shell", "shell"} and isinstance(command, str)
    action = ProposedAction(
        type="shell_command" if is_shell else "tool_call",
        command=command if is_shell else None,
        input=dict(tool_input),
        description=tool_input.get("description")
        if isinstance(tool_input.get("description"), str)
        else None,
    )
    context_provider = provider or RepositoryContextProvider(
        cwd=_path_or_none(_text(payload, "cwd", "working_directory")),
        include_git_diff=config.context.include_git_diff,
        include_changed_files=config.context.include_changed_files,
        include_tests=config.context.include_tests,
        max_diff_chars=config.context.max_diff_chars,
        max_context_chars=config.context.max_context_chars,
    )
    return context_provider.build(
        user_task=_text(payload, "user_task", "original_task", "task", "user_prompt", "prompt"),
        proposed_action=action,
        recent_context=_text(payload, "recent_context", "recent_agent_context"),
        external_content=_text(payload, "external_content", "retrieved_content"),
        test_results=_text(payload, "test_results"),
        changed_files=_changed_files(payload),
    )


def _path_or_none(value: str) -> Any:
    if not value:
        return None
    from pathlib import Path

    return Path(value)
