"""Bounded workspace tools for the optional Deep Agents harness.

Mutations must additionally be placed behind the harness HITL middleware. Human
approval permits REVIEW, but never bypasses a degraded evaluation or HOLD.
"""

from __future__ import annotations

import hashlib
import os
import selectors
import shlex
import signal
import stat
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

from ..config import ReflexConfig
from ..context import sanitized_child_env
from ..evaluator import DefaultEvaluator
from ..models import EvaluationContext, ProposedAction
from ..redaction import redact_text
from ..sandbox import (
    build_sandbox_command,
    prepare_sandbox_egress,
    remove_sandbox_container,
    remove_sandbox_egress,
)

_MAX_FILE = 1_048_576
_MAX_OUTPUT = 65_536
_BLOCKED = {
    ".git",
    ".env",
    ".codex",
    ".agents",
    ".ssh",
    ".aws",
    ".azure",
    ".gnupg",
    ".jev-reflex",
    ".jrx",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
}
_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


def _parts(path: str, *, directory: bool = False) -> tuple[str, ...]:
    if not path or "\x00" in path or "\\" in path:
        raise ValueError("a relative workspace path is required")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or ".." in parsed.parts:
        raise ValueError("path must stay inside the workspace")
    parts = parsed.parts
    if not parts and not directory:
        raise ValueError("a file path is required")
    for part in parts:
        lower = part.lower()
        if (
            lower in _BLOCKED
            or lower.startswith(".env.")
            or lower.endswith((".pem", ".key", ".p12", ".pfx", ".sqlite", ".sqlite3", ".db"))
            or any(word in lower for word in ("secret", "credential", "private_key"))
            or lower in {"id_rsa", "id_ed25519", ".netrc", ".npmrc", ".pypirc"}
        ):
            raise ValueError("sensitive or internal workspace paths are unavailable")
    return parts


@contextmanager
def _directory(root: Path, parts: tuple[str, ...]) -> Iterator[int]:
    """Walk each component with directory descriptors; never follow a symlink."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for part in parts:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _read(parent: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("only regular files without hard links are supported")
        if info.st_size > _MAX_FILE:
            raise ValueError("file exceeds the 1 MiB limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(_MAX_FILE + 1)
        if len(data) > _MAX_FILE:
            raise ValueError("file exceeds the 1 MiB limit")
        return data
    finally:
        os.close(fd)


def _terminate(process: subprocess.Popen[bytes]) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            continue
    process.wait(timeout=2)


def enforce_harness_action(
    action: ProposedAction,
    workspace: Path,
    config: ReflexConfig,
    objective: str,
    session_id: str,
    *,
    changed_files: list[str] | None = None,
    deadline: float | None = None,
) -> None:
    """Apply the harness policy gate to an action before its side effect."""
    if config.access is not None:
        raise ValueError("enterprise access configuration is unsupported by this harness")
    root = Path(workspace).resolve(strict=True)
    if not root.is_dir() or root == Path("/"):
        raise ValueError("a workspace directory below the filesystem root is required")
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("harness deadline reached")
    result = DefaultEvaluator(config).evaluate(
        EvaluationContext(
            user_task=objective,
            repository=str(root),
            repository_root=str(root),
            working_directory=str(root),
            proposed_action=action,
            changed_files=changed_files or [],
            recent_context=f"Harness session: {session_id}",
        )
    )
    if result.degraded or result.decision == "HOLD":
        raise PermissionError("JRX blocked the action: " + result.reason_summary())
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("harness deadline reached")


def build_tools(
    workspace: Path,
    config: ReflexConfig,
    objective: str,
    session_id: str,
    *,
    before_tool: Callable[[str], None] | None = None,
    deadline: float | None = None,
) -> list[Any]:
    """Create tools; caller must interrupt workspace_write and run_command.

    ``before_tool`` can enforce shared harness budgets/cancellation. ``deadline``
    is an absolute monotonic time. Imports stay lazy for the base installation.
    Existing parent directories are required for file writes.
    """
    from langchain_core.tools import StructuredTool

    if config.access is not None:
        raise ValueError("enterprise access configuration is unsupported by this harness")
    root = Path(workspace).resolve(strict=True)
    if not root.is_dir() or root == Path("/"):
        raise ValueError("a workspace directory below the filesystem root is required")
    with _LOCKS_GUARD:
        lock = _LOCKS.setdefault(str(root), threading.RLock())

    def begin(name: str) -> None:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("harness deadline reached")
        if before_tool is not None:
            before_tool(name)

    def gate(action: ProposedAction, changed: list[str] | None = None) -> None:
        enforce_harness_action(
            action,
            root,
            config,
            objective,
            session_id,
            changed_files=changed,
            deadline=deadline,
        )

    def workspace_list(path: str = ".") -> dict[str, Any]:
        """List up to 200 immediate safe entries in a relative workspace directory."""
        begin("workspace_list")
        parts = _parts(path, directory=True)
        entries: list[dict[str, str]] = []
        truncated = False
        with lock, _directory(root, parts) as fd, os.scandir(fd) as iterator:
            for index, entry in enumerate(iterator):
                if index >= 2000 or len(entries) >= 200:
                    truncated = True
                    break
                try:
                    _parts("/".join((*parts, entry.name)))
                    info = entry.stat(follow_symlinks=False)
                except (ValueError, OSError):
                    continue
                if stat.S_ISDIR(info.st_mode):
                    kind = "directory"
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    kind = "file"
                else:
                    continue
                entries.append({"name": entry.name, "kind": kind})
        return {"entries": sorted(entries, key=lambda entry: entry["name"]), "truncated": truncated}

    def workspace_read(path: str) -> dict[str, Any]:
        """Read a UTF-8 workspace file (maximum 1 MiB), returning its write precondition SHA256."""
        begin("workspace_read")
        parts = _parts(path)
        with lock, _directory(root, parts[:-1]) as fd:
            data = _read(fd, parts[-1])
        return {
            "path": path,
            "content": redact_text(data.decode("utf-8")),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def workspace_write(path: str, content: str, expected_sha256: str) -> dict[str, Any]:
        """Write a UTF-8 file after approval and JRX evaluation. Supply its read SHA256, or 'new'."""
        begin("workspace_write")
        parts = _parts(path)
        data = content.encode("utf-8")
        if len(data) > _MAX_FILE:
            raise ValueError("content exceeds the 1 MiB limit")
        if expected_sha256 != "new" and (
            len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256)
        ):
            raise ValueError("expected_sha256 must be the read SHA256 or 'new'")
        # Evaluate outside the file lock: no network request holds a file descriptor.
        gate(
            ProposedAction(
                type="file_write",
                input={"path": str(root / path), "content": content},
                description=f"Write workspace file {path}",
            ),
            [path],
        )
        with lock, _directory(root, parts[:-1]) as fd:
            mode = 0o600
            try:
                previous = _read(fd, parts[-1])
            except FileNotFoundError:
                if expected_sha256 != "new":
                    raise ValueError("file disappeared; read it again before writing") from None
            else:
                mode = (
                    stat.S_IMODE(os.stat(parts[-1], dir_fd=fd, follow_symlinks=False).st_mode)
                    & 0o777
                )
                if (
                    expected_sha256 == "new"
                    or hashlib.sha256(previous).hexdigest() != expected_sha256
                ):
                    raise ValueError("file changed; read it again before writing")
            temporary = f".jrx-write-{uuid.uuid4().hex}"
            out = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
            )
            try:
                with os.fdopen(out, "wb") as stream:
                    os.fchmod(stream.fileno(), mode)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                if expected_sha256 == "new":
                    # link fails if another process created the destination after our check.
                    os.link(
                        temporary, parts[-1], src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False
                    )
                else:
                    # Recheck immediately before replacement to detect external edits.
                    if hashlib.sha256(_read(fd, parts[-1])).hexdigest() != expected_sha256:
                        raise ValueError("file changed; read it again before writing")
                    os.replace(temporary, parts[-1], src_dir_fd=fd, dst_dir_fd=fd)
                os.fsync(fd)
            finally:
                try:
                    os.unlink(temporary, dir_fd=fd)
                except FileNotFoundError:
                    pass
        return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}

    def run_command(argv: list[str]) -> dict[str, Any]:
        """Run an approved argument list in the configured JRX sandbox with bounded output/time."""
        begin("run_command")
        if not argv or len(argv) > 256 or any(not isinstance(a, str) or "\x00" in a for a in argv):
            raise ValueError("a nonempty argument list without NUL bytes is required")
        if sum(len(a) for a in argv) > 65_536:
            raise ValueError("command arguments exceed the size limit")
        if not config.sandbox.enabled:
            raise PermissionError("run_command requires sandbox.enabled and sandbox.image")
        gate(ProposedAction(type="shell_command", argv=argv, command=shlex.join(argv)))
        command, container = build_sandbox_command(argv, root, config.sandbox)
        process = None
        egress = bool(config.sandbox.allowed_hosts)
        output = bytearray()
        truncated = False
        try:
            if egress:
                prepare_sandbox_egress(config.sandbox, container)
            stop = time.monotonic() + config.sandbox.max_execution_seconds
            if deadline is not None:
                stop = min(stop, deadline)
            if time.monotonic() >= stop:
                raise TimeoutError("harness deadline reached")
            process = subprocess.Popen(
                command,
                cwd=root,
                env=sanitized_child_env(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                shell=False,
            )
            assert process.stdout is not None
            with process.stdout, selectors.DefaultSelector() as selector:
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic() >= stop:
                        raise TimeoutError("sandbox execution deadline reached")
                    for key, _ in selector.select(
                        timeout=min(0.1, max(0, stop - time.monotonic()))
                    ):
                        chunk = os.read(key.fd, 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            break
                        remaining = _MAX_OUTPUT - len(output)
                        output.extend(chunk[:remaining])
                        truncated |= len(chunk) > remaining
                code = process.wait(timeout=max(0.001, stop - time.monotonic()))
            return {
                "returncode": code,
                "output": redact_text(output.decode("utf-8", errors="replace")),
                "truncated": truncated,
            }
        finally:
            try:
                if process is not None:
                    _terminate(process)
            finally:
                try:
                    remove_sandbox_container(config.sandbox, container)
                finally:
                    if egress:
                        remove_sandbox_egress(config.sandbox, container)

    return [
        StructuredTool.from_function(fn)
        for fn in (workspace_list, workspace_read, workspace_write, run_command)
    ]
