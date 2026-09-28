"""Preview, merge, back up, and narrowly roll back provider hook settings."""

from __future__ import annotations

import difflib
import json
import os
import secrets
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .providers import ProviderSpec
from .state import WorkspaceError, WorkspaceLock, validate_workspace

MAX_CONFIG_BYTES = 2_000_000


def _hook_entry(provider: str, command: str) -> tuple[str | None, str, dict[str, Any]]:
    if provider == "codex":
        return (
            None,
            "PreToolUse",
            {
                "matcher": "Bash|apply_patch|mcp__.*",
                "hooks": [{"type": "command", "command": command, "timeout": 30}],
            },
        )
    if provider == "claude":
        return (
            None,
            "PreToolUse",
            {
                "matcher": "Bash|Edit|Write|mcp__.*",
                "hooks": [{"type": "command", "command": command, "timeout": 30}],
            },
        )
    return (
        "jev-reflex",
        "PreToolUse",
        {
            "matcher": "*",
            "hooks": [{"type": "command", "command": command, "timeout": 30}],
        },
    )


def hook_command(provider: ProviderSpec) -> str:
    return "jev-reflex " + " ".join(provider.hook_command)


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


def _contains_command(value: Any, command: str) -> bool:
    if isinstance(value, dict):
        return value.get("command") == command or any(
            _contains_command(item, command) for item in value.values()
        )
    if isinstance(value, list):
        return any(_contains_command(item, command) for item in value)
    return False


def _merge_provider_hook(config: dict[str, Any], provider: str, command: str) -> bool:
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
    if any(_contains_command(existing, command) for existing in event_list):
        return False
    event_list.append(group)
    return True


def _remove_provider_hook(config: dict[str, Any], provider: str, command: str) -> bool:
    namespace = "jev-reflex" if provider == "antigravity" else None
    hooks = config.get(namespace) if namespace else config.get("hooks")
    if not isinstance(hooks, dict):
        return False
    event_list = hooks.get("PreToolUse")
    if not isinstance(event_list, list):
        return False
    kept = [item for item in event_list if not _contains_command(item, command)]
    changed = len(kept) != len(event_list)
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
        with os.fdopen(descriptor, "wb") as handle:
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
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def preview_hook_change(
    workspace: Path, provider: ProviderSpec, *, rollback: bool = False
) -> tuple[Path, str, bool]:
    root = validate_workspace(workspace)
    path = _target(root, provider)
    config, original, _mode = _read_config(path)
    updated = json.loads(json.dumps(config))
    command = hook_command(provider)
    changed = (
        _remove_provider_hook(updated, provider.key, command)
        if rollback
        else _merge_provider_hook(updated, provider.key, command)
    )
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
    """Check the local configuration file; this does not prove provider activation."""
    root = validate_workspace(workspace)
    path = _target(root, provider)
    try:
        config, _raw, _mode = _read_config(path)
    except WorkspaceError as exc:
        return False, str(exc)
    command = hook_command(provider)
    namespace = config.get("jev-reflex") if provider.key == "antigravity" else config.get("hooks")
    if provider.key == "claude" and config.get("disableAllHooks") is True:
        return False, "Claude Code settings disable all hooks"
    if (
        provider.key == "antigravity"
        and isinstance(namespace, dict)
        and namespace.get("enabled") is False
    ):
        return False, "Antigravity JRX hook namespace is disabled"
    configured = isinstance(namespace, dict) and _contains_command(
        namespace.get("PreToolUse", []), command
    )
    if configured:
        return True, "configured; provider activation or hook trust is not verifiable by JRX"
    return False, "not configured"


def apply_hook_change(
    workspace: Path, provider: ProviderSpec, *, rollback: bool = False
) -> tuple[Path, Path | None, bool]:
    root = validate_workspace(workspace)
    with WorkspaceLock(root):
        path = _target(root, provider)
        config, original, mode = _read_config(path)
        updated = json.loads(json.dumps(config))
        command = hook_command(provider)
        changed = (
            _remove_provider_hook(updated, provider.key, command)
            if rollback
            else _merge_provider_hook(updated, provider.key, command)
        )
        if not changed:
            return path, None, False
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _target(root, provider)
        backup = _backup(path, original)
        _write_config(path, _json_bytes(updated), mode)
        return path, backup, True
