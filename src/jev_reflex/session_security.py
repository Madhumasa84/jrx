"""Session-scoped credential evidence and protected file integrity checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Iterable
from pathlib import Path

from .checks import tamper
from .checks.common import absolute_path, roots
from .checks.execution import egress
from .checks.repo_boundary import input_paths
from .checks.secrets import (
    concrete_credential_value,
    credential_values,
    sensitive_credential_path,
    structured_text,
)
from .checks.shell import inspect, program
from .config import ReflexConfig
from .models import DeterministicFinding, EvaluationContext, ProposedAction
from .redaction import looks_secret_key
from .session_limits import MAX_TAINTS_PER_SESSION, SessionStore

_READ_TOOLS = re.compile(r"(?:^|[._:])(?:read|view|get_file|open_file)(?:$|_)", re.I)
_READ_COMMANDS = {
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "awk",
    "sed",
    "rg",
    "grep",
    "bat",
    "source",
    ".",
}
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]{6,}={0,2}")
_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.+?)\s*$", re.M)
_MAX_FILE_BYTES = 1_048_576
_MAX_SCAN_ENTRIES = 100_000
_SKIP_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
_PRIVATE_REASONS = {
    "RECORDED_SECRET_MATCH",
    "SESSION_TAINT_STATE_UNAVAILABLE",
    "SESSION_TAINT_CAPACITY",
}


def _read_paths(action: ProposedAction, tool_name: str, cwd: Path) -> set[str]:
    names = input_paths(action.input) if _READ_TOOLS.search(tool_name) else []
    directories = {cwd}
    results: set[str] = set()
    for command in inspect(action).commands:
        names.extend(target for operator, target in command.redirects if operator == "<")
        if command.argv:
            name, args = program(command.argv[0]), command.argv[1:]
            if name in {"cd", "pushd"}:
                operand = next((arg for arg in args if not arg.startswith("-")), "")
                if operand and len(directories) < 16:
                    directories.update(absolute_path(operand, base) for base in tuple(directories))
            if name in _READ_COMMANDS:
                names.extend(arg for arg in args if not arg.startswith("-"))
    home = Path.home()
    for name in names:
        for directory in directories:
            path = absolute_path(name, directory)
            try:
                resolved = path.resolve()
            except (OSError, RuntimeError):
                resolved = path
            if sensitive_credential_path(path, home) or sensitive_credential_path(
                resolved, home.resolve()
            ):
                results.add(str(resolved))
    return results


def record_post_tool_use(
    config: ReflexConfig,
    session_id: str,
    *,
    action: ProposedAction,
    tool_name: str,
    cwd: Path,
    output: object,
) -> None:
    """Fingerprint output evidence and reads without storing tool payloads."""
    if not session_id or not config.session.track_secret_taint:
        return
    paths = _read_paths(action, tool_name, cwd)
    values: set[str] = set()
    truncated = len(paths) > MAX_TAINTS_PER_SESSION
    for key, text in structured_text(output):
        if key and looks_secret_key(key) and concrete_credential_value(text):
            values.add(text)
            if len(values) > MAX_TAINTS_PER_SESSION:
                truncated = True
                break
        for _, value in credential_values(text):
            values.add(value)
            if len(values) > MAX_TAINTS_PER_SESSION:
                truncated = True
                break
        if truncated:
            break
        if paths:
            for match in _ASSIGNMENT.finditer(text):
                value = match[1].strip("'\"")
                if len(value) >= 8:
                    values.add(value)
                if len(values) > MAX_TAINTS_PER_SESSION:
                    truncated = True
                    break
        if truncated:
            break
    SessionStore(config.session).record_taints(
        session_id, values, set(sorted(paths)[:MAX_TAINTS_PER_SESSION]), truncated=truncated
    )


def _candidates(context: EvaluationContext) -> set[str]:
    action = context.proposed_action
    texts = [action.command or "", *action.argv]
    if context.proposed_diff or action.type == "observation":
        texts.append(context.git_diff)
    texts.extend(value for _, value in structured_text(action.input))
    values = {text for text in texts if text}
    for text in texts:
        values.update(_TOKEN.findall(text))
        values.update(value for _, value in credential_values(text))
    for command in inspect(action).commands:
        values.update(command.argv[1:])
        values.update(arg.split("=", 1)[1] for arg in command.argv[1:] if "=" in arg)
    return values


def _file_digest(path: Path) -> str | None:
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        if path.is_symlink():
            raise ValueError("unresolved protected file") from None
        return None
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(resolved, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_FILE_BYTES:
            raise ValueError("protected file is not a bounded regular file")
        data = stream.read(_MAX_FILE_BYTES + 1)
        after = os.fstat(stream.fileno())
        if len(data) != before.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise ValueError("protected file changed while being read")
    return hashlib.sha256(data).hexdigest()


def _repository_controls(start: Path, home: Path) -> Iterable[Path]:
    entries = 0

    def walk_error(error: OSError) -> None:
        raise error

    for directory, dirs, files in os.walk(start, onerror=walk_error, followlinks=False):
        entries += len(dirs) + len(files)
        if entries > _MAX_SCAN_ENTRIES:
            raise ValueError("protected file scan limit reached")
        dirs[:] = [name for name in dirs if name not in _SKIP_DIRECTORIES]
        for name in files:
            candidate = Path(directory, name)
            if tamper.protected(candidate, home):
                yield candidate


def _integrity_manifest(root: Path, config: ReflexConfig) -> str:
    home = Path.home()
    paths = {root / path for path in tamper.CONTROL_FILES}
    paths.update(home / path for path in tamper.HOME_FILES)
    paths.update(
        {
            root / "reflex.yaml",
            root / "bootstrap.yaml",
            Path("/etc/jrx/bootstrap.yaml"),
            home / ".jev-reflex/bootstrap.yaml",
        }
    )
    if config._source_path is not None:
        paths.add(config._source_path)
    paths.update(_repository_controls(root, home))
    paths.update(
        _repository_controls(root / ".git/hooks", home) if (root / ".git/hooks").is_dir() else ()
    )
    manifest = {}
    for path in sorted(paths):
        if (digest := _file_digest(path)) is not None:
            manifest[hashlib.sha256(os.fsencode(path)).hexdigest()] = digest
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"))


def _taint_finding(reason: str) -> DeterministicFinding:
    return DeterministicFinding(
        check="taint_exfiltration",
        triggered=True,
        severity="high",
        reason_code=reason,
        blocking=True,
    )


def security_findings(
    context: EvaluationContext, config: ReflexConfig, session_id: str
) -> list[DeterministicFinding]:
    if not session_id or not (
        config.session.track_secret_taint or config.session.pin_protected_files
    ):
        return []
    findings = []
    try:
        store = SessionStore(config.session)
    except (OSError, ValueError):
        return [
            *(
                [_taint_finding("SESSION_TAINT_STATE_UNAVAILABLE")]
                if config.session.track_secret_taint
                else []
            ),
            *(
                [tamper.finding("SESSION_INTEGRITY_UNAVAILABLE")]
                if config.session.pin_protected_files
                else []
            ),
        ]
    if config.session.track_secret_taint:
        try:
            tainted, matched, overflow = store.check_taints(session_id, _candidates(context))
            if matched:
                findings.append(_taint_finding("RECORDED_SECRET_MATCH"))
            elif overflow:
                findings.append(_taint_finding("SESSION_TAINT_CAPACITY"))
            elif tainted:
                plan = inspect(context.proposed_action)
                if plan.opaque or any(egress(command) for command in plan.commands):
                    findings.append(_taint_finding("TAINTED_SESSION_EGRESS"))
        except (OSError, RuntimeError, ValueError, sqlite3.Error):
            findings.append(_taint_finding("SESSION_TAINT_STATE_UNAVAILABLE"))
    if config.session.pin_protected_files:
        try:
            _, root = roots(context)
            scope = hashlib.sha256(os.fsencode(root)).digest()
            if not store.check_integrity(session_id, scope, _integrity_manifest(root, config)):
                findings.append(tamper.finding("PROTECTED_PATH_DRIFT"))
        except (OSError, RuntimeError, ValueError, sqlite3.Error):
            findings.append(tamper.finding("SESSION_INTEGRITY_UNAVAILABLE"))
    return findings


def private_action(findings: Iterable[DeterministicFinding]) -> bool:
    return any(
        finding.check == "taint_exfiltration" and finding.reason_code in _PRIVATE_REASONS
        for finding in findings
    )
