"""Shared input normalization for agent hook adapters."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal, Protocol, TextIO

from ..config import ReflexConfig
from ..context import ContextProvider, RepositoryContextProvider
from ..models import EvaluationContext, EvaluationResult, HookAuditCorrelation, ProposedAction
from ..serialization import unique_object

MAX_HOOK_CHARS = 1_048_576
_SAFE_HOOK_TOOL = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
# Key that wraps tool arguments which are not a JSON object.
_RAW_ARGUMENT = "value"


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


def _decoded_mapping(value: object) -> Mapping[str, Any] | None:
    """Return tool arguments sent as a mapping or as a JSON-encoded object."""

    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        # OpenRouter and Pi can carry arguments as the model's raw JSON string.
        try:
            decoded = json.loads(value, object_pairs_hook=unique_object)
        except (ValueError, RecursionError):
            return None
        if isinstance(decoded, Mapping):
            return decoded
    return None


def _arguments(payload: Mapping[str, Any], *names: str) -> Mapping[str, Any]:
    for name in names:
        value = payload.get(name)
        decoded = _decoded_mapping(value)
        if decoded is not None:
            return decoded
        if isinstance(value, str):
            # Raw text from a host that passes a string. Shell and file tools fail
            # closed later, because no command or path can be found in this wrapper.
            return {_RAW_ARGUMENT: value}
        if value is not None:
            # Neither an object nor text (a number, boolean or list): nothing a rule can
            # inspect, so the call is treated as having no arguments and denied.
            return {}
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
# Hosts differ in key case ("command", "Command", "CommandLine"), so match keys case-insensitively.
_COMMAND_KEYS = frozenset(field.casefold() for field in _COMMAND_FIELDS)
# Tools whose host runs the arguments as a shell command line.
_SHELL_TOOLS = frozenset(
    {
        "bash",
        "sh",
        "shell",
        "powershell",
        "terminal",
        "exec_command",
        "shell_command",
        "local_shell",
        "container.exec",
        "run_command",
        "run_shell_command",
        "run_terminal_cmd",
        "run_terminal_command",
        "execute_command",
    }
)
# Tools whose host writes the file named in the arguments.
_FILE_WRITE_TOOLS = frozenset(
    {
        "write",
        "edit",
        "multiedit",
        "notebookedit",
        "write_file",
        "edit_file",
        "create_file",
        "write_to_file",
        "replace_file_content",
        "multi_replace_file_content",
    }
)
_PATH_KEYS = frozenset(
    {
        "path",
        "file_path",
        "filepath",
        "file",
        "filename",
        "file_name",
        "target_file",
        "targetfile",
        "target_path",
        "notebook_path",
        "absolute_path",
        "absolutepath",
    }
)
_PATCH_TOOLS = frozenset({"apply_patch", "applypatch"})
_PATCH_KEYS = frozenset({"patch", "patch_text", "input", "diff"})
_PATCH_INVOCATION = re.compile(r"\A\s*(?:apply_patch|applypatch)(?=[ \t<'\"]|\Z)")
_BEGIN_PATCH_LINE = re.compile(r"^[ \t]*\*\*\*[ \t]*begin patch", re.I | re.M)
_PATCH_HEREDOC = re.compile(
    r"\A[ \t]*<<[ \t]*(?P<quote>['\"]?)(?P<tag>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)[ \t]*\n"
)
_PATCH_MARKER = re.compile(
    r"\A\*\*\*[ \t]*(?P<kind>add file|update file|delete file|move to)[ \t]*:[ \t]*(?P<path>.*?)\s*\Z",
    re.I,
)
_PATCH_MARKER_NAMES = {
    "add file": "Add File",
    "update file": "Update File",
    "delete file": "Delete File",
    "move to": "Move to",
}


def _command_fields(tool_input: Mapping[str, Any]) -> list[tuple[str, Any]]:
    return [
        (key, value)
        for key, value in tool_input.items()
        if isinstance(key, str) and key.casefold() in _COMMAND_KEYS
    ]


def _command_text(tool_input: Mapping[str, Any]) -> str:
    """Return the single shell command in ``tool_input``; raise when it is ambiguous."""

    fields = _command_fields(tool_input)
    for _, value in fields:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("hook input contains an invalid command")
    commands = {value for _, value in fields}
    if len(commands) > 1:
        raise ValueError("hook input contains conflicting commands")
    return commands.pop() if commands else ""


def _has_path(tool_input: Mapping[str, Any]) -> bool:
    return any(
        isinstance(key, str)
        and key.casefold() in _PATH_KEYS
        and isinstance(value, str)
        and bool(value.strip())
        for key, value in tool_input.items()
    )


def _normalized_patch(text: str) -> str:
    """Spell file markers the way policy checks read them.

    Codex trims padding (including a trailing CR) around patch markers, so a
    padded marker must still reach the protected-path checks.
    """

    lines = []
    for line in text.split("\n"):
        marker = _PATCH_MARKER.match(line.strip())
        if marker:
            name = _PATCH_MARKER_NAMES[marker["kind"].casefold()]
            line = f"*** {name}: {marker['path']}"
        lines.append(line)
    return "\n".join(lines)


def _heredoc_body(text: str) -> str | None:
    """Return the body of ``<<TAG`` text that ends with its terminator and nothing else."""

    heredoc = _PATCH_HEREDOC.match(text)
    if heredoc is None:
        return None
    tag = heredoc["tag"]
    lines = text[heredoc.end() :].rstrip().split("\n")
    body = lines[:-1]
    # A terminator inside the body would end the heredoc early and run what follows.
    if lines[-1] != tag or tag in body:
        return None
    text = "\n".join(body)
    if not heredoc["quote"] and re.search(r"[$`\\]", text):
        # An unquoted heredoc expands $(...) and backticks before apply_patch runs.
        return None
    return text


def _shell_patch(command: str) -> str | None:
    """Return the patch from a shell command that only invokes ``apply_patch``.

    Returns ``None`` when the command carries no patch. Raises ``ValueError`` for
    any other command carrying a patch, because a shell would run the extra text.
    """

    invocation = _PATCH_INVOCATION.match(command)
    if invocation is None:
        if _BEGIN_PATCH_LINE.search(command):
            raise ValueError("hook input contains an unsupported apply_patch command")
        return None
    rest = command[invocation.end() :]
    body = _heredoc_body(rest)
    if body is None:
        quoted = re.fullmatch(r"[ \t]+'([^']*)'\s*", rest)
        body = quoted[1] if quoted else None
    if body is None or not _BEGIN_PATCH_LINE.search(body):
        raise ValueError("hook input contains an unsupported apply_patch command")
    return body


def _tool_patch(tool_input: Mapping[str, Any]) -> str:
    """Return the patch an ``apply_patch`` tool call carries, whichever field holds it."""

    candidates = {
        value
        for key, value in tool_input.items()
        if isinstance(key, str)
        and (key.casefold() in _PATCH_KEYS | _COMMAND_KEYS or key == _RAW_ARGUMENT)
        and isinstance(value, str)
        and value.strip()
    }
    if len(candidates) != 1:
        raise ValueError("apply_patch input must contain exactly one patch")
    patch = candidates.pop()
    if not _BEGIN_PATCH_LINE.search(patch):
        raise ValueError("apply_patch input does not contain a patch")
    return patch


def is_post_tool_use(payload: Mapping[str, Any]) -> bool:
    event = _text(
        payload,
        "hook_event_name",
        "hookEventName",
        "hookName",
        "hook_name",
        "event",
        "event_name",
        "eventName",
    )
    return event.replace("_", "").replace("-", "").casefold() == "posttooluse"


def ingest_post_tool_use(payload: Mapping[str, Any], config: ReflexConfig) -> None:
    session_id = os.environ.get("JRX_SESSION_ID", "")
    if not session_id or not config.session.track_secret_taint:
        return
    from ..session_security import record_post_tool_use

    tool_name, arguments = _tool_call(payload)
    if not tool_name:
        raise ValueError("PostToolUse requires a tool name")
    output = next(
        (
            payload[key]
            for key in (
                "tool_response",
                "toolResponse",
                "tool_output",
                "toolOutput",
                "output",
                "result",
            )
            if key in payload
        ),
        None,
    )
    # Failed, interrupted, and non-zero-exit tools still return their output to the
    # model, so their evidence is recorded too.
    cwd = Path(_workspace_cwd(payload, arguments) or ".").resolve()
    command = next(
        (value for _, value in _command_fields(arguments) if isinstance(value, str) and value),
        None,
    )
    action = ProposedAction(command=command, input=dict(arguments))
    record_post_tool_use(
        config, session_id, action=action, tool_name=tool_name, cwd=cwd, output=output
    )


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
    kind = tool_name.strip().casefold()
    command = _command_text(tool_input)
    patch = _tool_patch(tool_input) if kind in _PATCH_TOOLS else _shell_patch(command)
    action_input = dict(tool_input)
    policy_tool_name = tool_name
    if patch is not None:
        # The patch is what gets applied, whichever field (or apply_patch command)
        # carried it. Policy checks inspect patch headers only on a patch tool call.
        command = ""
        action_input = {
            key: value
            for key, value in tool_input.items()
            if not isinstance(key, str)
            or (key.casefold() not in _PATCH_KEYS | _COMMAND_KEYS and key != _RAW_ARGUMENT)
        }
        action_input["patch"] = _normalized_patch(patch)
        policy_tool_name = "apply_patch"
    elif kind in _SHELL_TOOLS and not command:
        raise ValueError("hook input is missing a shell command")
    elif kind in _FILE_WRITE_TOOLS and not _has_path(tool_input):
        raise ValueError("hook input is missing a file path")
    is_shell = bool(command)
    action = ProposedAction(
        type="shell_command" if is_shell else "tool_call",
        command=command if is_shell else None,
        input=action_input,
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
    return context.model_copy(update={"hook_audit": correlation, "tool_name": policy_tool_name})


def _path_or_none(value: str) -> Any:
    if not value:
        return None
    return Path(value)
