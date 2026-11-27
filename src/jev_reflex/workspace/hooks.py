"""Preview, merge, back up, and narrowly roll back provider hook settings."""

from __future__ import annotations

import difflib
import json
import os
import re
import secrets
import shlex
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .providers import ProviderSpec
from .state import WorkspaceError, WorkspaceLock, validate_workspace

MAX_CONFIG_BYTES = 2_000_000


# Tools each provider hook must intercept. Every name is spelled out because
# matcher anchoring for simple alternations is not documented consistently;
# the coverage check below requires a full match for each sample name.
_MATCHERS = {
    # Bash is Codex's hook name for shell calls; exec_command/shell_command are
    # covered too, matching the shell tool names the PostToolUse helper lists.
    "codex": "Bash|exec_command|shell_command|apply_patch|mcp__.*",
    "claude": "Bash|Edit|MultiEdit|Write|NotebookEdit|mcp__.*",
    "antigravity": "*",
}
_COVERAGE_SAMPLES = {
    "codex": ("Bash", "exec_command", "shell_command", "apply_patch", "mcp__server__tool"),
    "claude": ("Bash", "Edit", "MultiEdit", "Write", "NotebookEdit", "mcp__server__tool"),
    "antigravity": ("run_command", "write_to_file", "replace_file_content", "mcp__server__tool"),
}


def _hook_entry(provider: str, command: str) -> tuple[str | None, str, dict[str, Any]]:
    group = {
        "matcher": _MATCHERS.get(provider, "*"),
        "hooks": [{"type": "command", "command": command, "timeout": 30}],
    }
    return ("jev-reflex" if provider == "antigravity" else None), "PreToolUse", group


def _legacy_hook_command(provider: ProviderSpec) -> str:
    """The pre-pinning command, which loaded reflex.yaml from the hook's cwd."""
    return "jev-reflex " + " ".join(provider.hook_command)


def hook_command(provider: ProviderSpec, workspace: Path) -> str:
    """Return the hook command, pinned to the workspace policy file.

    Hosts run hooks in the agent's current directory, which moves when the
    agent changes directory, so the policy path is never left implicit.
    """
    if provider.key == "claude":
        # Claude Code exports the project root to hook commands it runs in a shell.
        policy = '"$CLAUDE_PROJECT_DIR"/reflex.yaml'
    else:
        policy = shlex.quote(str(validate_workspace(workspace) / "reflex.yaml"))
    return f"{_legacy_hook_command(provider)} --config {policy}"


def _jrx_commands(provider: ProviderSpec, workspace: Path) -> set[str]:
    return {hook_command(provider, workspace), _legacy_hook_command(provider)}


def _target(root: Path, provider: ProviderSpec) -> Path:
    path = root / provider.hooks_path
    cursor = root
    for part in Path(provider.hooks_path).parts[:-1]:
        cursor = cursor / part
        try:
            parent_mode = cursor.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(parent_mode) or not stat.S_ISDIR(parent_mode):
            raise WorkspaceError("provider configuration parent must be a real directory")
    try:
        file_mode: int | None = path.lstat().st_mode
    except FileNotFoundError:
        file_mode = None
    if file_mode is not None and (stat.S_ISLNK(file_mode) or not stat.S_ISREG(file_mode)):
        raise WorkspaceError("provider configuration must be a regular file")
    return path


def _read_config(path: Path) -> tuple[dict[str, Any], bytes, int]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {}, b"", 0o600
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise WorkspaceError("provider configuration must be a regular file")
    if info.st_size > MAX_CONFIG_BYTES:
        raise WorkspaceError("provider configuration exceeds the safe size limit")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise WorkspaceError(
            "provider configuration is not valid JSON; it was left untouched"
        ) from None
    if not isinstance(value, dict):
        raise WorkspaceError("provider configuration root must be a JSON object")
    return value, raw, stat.S_IMODE(info.st_mode)


def _group_runs(group: Any, command: str) -> bool:
    return (
        isinstance(group, dict)
        and isinstance(group.get("hooks"), list)
        and any(
            isinstance(hook, dict) and hook.get("command") == command for hook in group["hooks"]
        )
    )


def _matcher_covers(matcher: Any, tool: str) -> bool:
    if matcher is None:
        return True
    if not isinstance(matcher, str):
        return False
    if matcher in {"", "*"}:
        return True
    try:
        return re.fullmatch(matcher, tool) is not None
    except re.error:
        return False


def _covers(event_list: Any, provider: str, command: str) -> bool:
    """True when the groups running ``command`` match every required tool."""
    if not isinstance(event_list, list):
        return False
    matchers = [group.get("matcher") for group in event_list if _group_runs(group, command)]
    return bool(matchers) and all(
        any(_matcher_covers(matcher, tool) for matcher in matchers)
        for tool in _COVERAGE_SAMPLES.get(provider, ("*",))
    )


def _merge_provider_hook(
    config: dict[str, Any], provider: str, command: str, replaced: set[str] | None = None
) -> bool:
    namespace, event, group = _hook_entry(provider, command)
    if provider == "antigravity":
        if namespace is None:
            raise WorkspaceError("Antigravity hook namespace is unavailable")
        hooks = config.get(namespace)
        if hooks is None:
            hooks = {}
            config[namespace] = hooks
        if not isinstance(hooks, dict):
            raise WorkspaceError("Antigravity jev-reflex hook namespace has an incompatible type")
        event_list = hooks.get(event)
        if event_list is None:
            event_list = []
            hooks[event] = event_list
    else:
        hooks = config.get("hooks")
        if hooks is None:
            hooks = {}
            config["hooks"] = hooks
        if not isinstance(hooks, dict):
            raise WorkspaceError("provider hooks setting has an incompatible type")
        event_list = hooks.get(event)
        if event_list is None:
            event_list = []
            hooks[event] = event_list
    if not isinstance(event_list, list):
        raise WorkspaceError("provider hook event has an incompatible type")
    stale = set(replaced or ())
    if _covers(event_list, provider, command) and not any(
        _group_runs(existing, old) for existing in event_list for old in stale
    ):
        return False
    # Replace JRX's own entries (partial-matcher or unpinned legacy ones) with
    # one canonical group; other hooks sharing those groups are kept. Removal
    # rebuilds the event list and may drop an emptied mapping, so re-attach it.
    _remove_provider_hook(config, provider, {command, *stale})
    hooks[event] = [*hooks[event], group]
    config[namespace or "hooks"] = hooks
    return True


def _remove_provider_hook(config: dict[str, Any], provider: str, commands: str | set[str]) -> bool:
    removed = {commands} if isinstance(commands, str) else commands
    namespace = "jev-reflex" if provider == "antigravity" else None
    hooks = config.get(namespace) if namespace else config.get("hooks")
    if not isinstance(hooks, dict):
        return False
    event_list = hooks.get("PreToolUse")
    if not isinstance(event_list, list):
        return False
    kept = []
    changed = False
    for item in event_list:
        if not isinstance(item, dict) or not isinstance(item.get("hooks"), list):
            kept.append(item)
            continue
        remaining = [
            hook
            for hook in item["hooks"]
            if not (isinstance(hook, dict) and hook.get("command") in removed)
        ]
        if len(remaining) == len(item["hooks"]):
            kept.append(item)
            continue
        changed = True
        if remaining:
            kept.append({**item, "hooks": remaining})
    if changed:
        hooks["PreToolUse"] = kept
    if namespace and not hooks:
        config.pop(namespace, None)
    elif not namespace and not hooks:
        config.pop("hooks", None)
    return changed


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _backup(path: Path, original: bytes) -> Path | None:
    if not original:
        return None
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = path.with_name(f"{path.name}.jrx-backup-{stamp}-{secrets.token_hex(3)}")
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(original)
        handle.flush()
        os.fsync(handle.fileno())
    return backup


def _write_config(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=".jrx-settings-", dir=path.parent)
    temporary = Path(temp_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def _change(config: dict[str, Any], root: Path, provider: ProviderSpec, *, rollback: bool) -> bool:
    if rollback:
        return _remove_provider_hook(config, provider.key, _jrx_commands(provider, root))
    return _merge_provider_hook(
        config, provider.key, hook_command(provider, root), {_legacy_hook_command(provider)}
    )


def preview_hook_change(
    workspace: Path, provider: ProviderSpec, *, rollback: bool = False
) -> tuple[Path, str, bool]:
    root = validate_workspace(workspace)
    path = _target(root, provider)
    config, original, _mode = _read_config(path)
    updated = json.loads(json.dumps(config))
    changed = _change(updated, root, provider, rollback=rollback)
    if not changed:
        return path, "No JRX hook change is needed.\n", False
    old_text = original.decode("utf-8", errors="replace").splitlines(keepends=True)
    new_text = _json_bytes(updated).decode("utf-8").splitlines(keepends=True)
    diff = "".join(
        difflib.unified_diff(
            old_text, new_text, fromfile=str(path), tofile=str(path) + " (JRX preview)"
        )
    )
    return path, diff, True


def hook_configured(workspace: Path, provider: ProviderSpec) -> tuple[bool, str]:
    """Check the local configuration files; this does not prove provider activation."""
    root = validate_workspace(workspace)
    path = _target(root, provider)
    try:
        config, _raw, _mode = _read_config(path)
        # Claude Code also applies .claude/settings.local.json (hooks and
        # disableAllHooks); it shares the parent checked by _target.
        local = (
            _read_config(path.with_name("settings.local.json"))[0]
            if provider.key == "claude"
            else {}
        )
    except WorkspaceError as exc:
        return False, str(exc)
    if provider.key == "claude" and any(
        settings.get("disableAllHooks") is True for settings in (config, local)
    ):
        return False, "Claude Code settings disable all hooks"
    namespace = config.get("jev-reflex") if provider.key == "antigravity" else config.get("hooks")
    if (
        provider.key == "antigravity"
        and isinstance(namespace, dict)
        and namespace.get("enabled") is False
    ):
        return False, "Antigravity JRX hook namespace is disabled"
    groups: list[Any] = []
    for hooks in (namespace, local.get("hooks")):
        event_list = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
        if isinstance(event_list, list):
            groups.extend(event_list)
    if _covers(groups, provider.key, hook_command(provider, root)):
        return True, "configured; provider activation or hook trust is not verifiable by JRX"
    if any(
        _group_runs(group, command) for group in groups for command in _jrx_commands(provider, root)
    ):
        return False, (
            "JRX hook is not pinned to the workspace policy or does not cover every "
            "required tool; preview setup again"
        )
    return False, "not configured"


def apply_hook_change(
    workspace: Path, provider: ProviderSpec, *, rollback: bool = False
) -> tuple[Path, Path | None, bool]:
    root = validate_workspace(workspace)
    with WorkspaceLock(root):
        path = _target(root, provider)
        config, original, mode = _read_config(path)
        updated = json.loads(json.dumps(config))
        changed = _change(updated, root, provider, rollback=rollback)
        if not changed:
            return path, None, False
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _target(root, provider)
        backup = _backup(path, original)
        _write_config(path, _json_bytes(updated), mode)
        return path, backup, True
