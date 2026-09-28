"""Private workspace metadata, locking, and factual Git snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import tempfile
import uuid
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..config import ReflexConfig
from ..git_inspection import inspect_git

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows doctor/setup remain available.
    fcntl = None  # type: ignore[assignment]

TASK_VERSION = 1
MAX_CHANGED_FILES = 500
MAX_FILE_PATH_CHARS = 1024
MAX_HANDOFF_CHARS = 64_000
MAX_TASK_RECORD_BYTES = 1_000_000
MAX_FINGERPRINT_FILE_BYTES = 1_000_000
MAX_FINGERPRINT_TOTAL_BYTES = 16_000_000


class WorkspaceError(ValueError):
    """An unsafe, stale, or incompatible workspace record or lock."""


def state_directory() -> Path:
    configured = os.environ.get("XDG_STATE_HOME", "").strip()
    root = Path(configured).expanduser() if configured else Path.home() / ".local" / "state"
    return root / "jev-reflex"


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise WorkspaceError("JRX state directory must be a real directory")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise WorkspaceError("JRX state directory must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise WorkspaceError("JRX state directory permissions must be 0700")


def private_state_directory() -> Path:
    root = state_directory()
    _private_directory(root)
    for child in (root / "tasks", root / "handoffs"):
        _private_directory(child)
    return root


def atomic_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Atomically replace one private file in its existing directory."""
    _private_directory(path.parent)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)
    ):
        raise WorkspaceError("refusing to replace a non-regular JRX state file")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".jrx-write-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
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


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    body = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    atomic_write(path, (body + "\n").encode("utf-8"))


class WorkspaceLock(AbstractContextManager["WorkspaceLock"]):
    """Kernel-managed exclusive writer lock; abandoned PIDs cannot retain it."""

    def __init__(self, workspace: Path, *, blocking: bool = False) -> None:
        self.workspace = validate_workspace(workspace)
        self.blocking = blocking
        self.handle: Any | None = None
        digest = hashlib.sha256(os.fsencode(str(self.workspace))).hexdigest()
        self.path = private_state_directory() / f"workspace-{digest}.lock"

    def acquire(self) -> WorkspaceLock:
        if fcntl is None:
            raise WorkspaceError("managed workspace locking currently requires Linux or macOS")
        if self.handle is not None:
            return self
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            os.close(descriptor)
            raise WorkspaceError("unsafe workspace lock file")
        handle = os.fdopen(descriptor, "r+b", buffering=0)
        operation = fcntl.LOCK_EX | (0 if self.blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(handle.fileno(), operation)
        except BlockingIOError:
            handle.close()
            raise WorkspaceError(
                "another JRX-managed agent is already writing in this workspace"
            ) from None
        owner = {
            "pid": os.getpid(),
            "workspace": str(self.workspace),
            "started_at": datetime.now(UTC).isoformat(),
            "nonce": secrets.token_hex(16),
        }
        handle.seek(0)
        handle.truncate()
        handle.write((json.dumps(owner, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(handle.fileno())
        self.handle = handle
        return self

    def release(self) -> None:
        if self.handle is not None:
            if fcntl is None:  # pragma: no cover - a lock cannot be acquired here.
                self.handle.close()
                self.handle = None
                return
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
            self.handle = None

    def __enter__(self) -> WorkspaceLock:
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.release()


def validate_workspace(workspace: Path) -> Path:
    candidate = workspace.expanduser()
    try:
        canonical = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        raise WorkspaceError("workspace does not exist or cannot be resolved") from None
    if not canonical.is_dir():
        raise WorkspaceError("workspace must be a directory")
    return canonical


def _path_is_sensitive(relative: str) -> bool:
    parts = [part.casefold() for part in relative.replace("\\", "/").split("/")]
    base = parts[-1] if parts else ""
    if base.startswith(".env") or base in {"credentials", "credentials.json", "secrets.json"}:
        return True
    if any(part in {".ssh", ".aws", ".azure", ".gnupg", "auth", "credentials"} for part in parts):
        return True
    return base.endswith((".pem", ".key", ".p12", ".pfx", ".keystore")) or any(
        word in base for word in ("credential", "secret", "token", "private-key")
    )


def _porcelain_entries(raw: bytes) -> list[dict[str, str]]:
    entries = iter(raw.split(b"\0"))
    result: list[dict[str, str]] = []
    for item in entries:
        if not item:
            continue
        if len(item) < 4 or item[2:3] != b" ":
            raise WorkspaceError("Git returned malformed workspace status")
        code = os.fsdecode(item[:2])
        path = os.fsdecode(item[3:])
        result.append({"path": path, "status": code})
        if "R" in code or "C" in code:
            source = next(entries, b"")
            if not source:
                raise WorkspaceError("Git returned an incomplete rename record")
            result.append({"path": os.fsdecode(source), "status": f"{code} (source)"})
    return result


def _fingerprint_file(
    git_root: Path,
    relative_parts: tuple[str, ...],
    expected: os.stat_result,
) -> str:
    """Hash a bounded regular file through no-follow directory descriptors."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory_flag or not relative_parts:
        raise WorkspaceError("safe file fingerprinting is unavailable on this platform")
    directory_fd = os.open(git_root, os.O_RDONLY | directory_flag | nofollow)
    file_fd: int | None = None
    try:
        for part in relative_parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | directory_flag | nofollow,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            relative_parts[-1],
            os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        opened = os.fstat(file_fd)

        def identity(info: os.stat_result) -> tuple[int, int, int, int]:
            return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns

        if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(expected):
            raise WorkspaceError("workspace file changed during checkpoint capture")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(file_fd, min(65_536, MAX_FINGERPRINT_FILE_BYTES + 1 - total))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if total > MAX_FINGERPRINT_FILE_BYTES:
                raise WorkspaceError("workspace file exceeded the fingerprint size limit")
        if identity(os.fstat(file_fd)) != identity(opened) or total != opened.st_size:
            raise WorkspaceError("workspace file changed during checkpoint capture")
        return digest.hexdigest()
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


def collect_workspace_state(workspace: Path) -> dict[str, Any]:
    """Read Git/worktree facts without reading file contents or following links."""
    root = validate_workspace(workspace)
    top = inspect_git(root, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        return {
            "root": str(root),
            "git": False,
            "branch": None,
            "base_commit": None,
            "base_reference": None,
            "current_commit": None,
            "files": [],
            "capabilities": "reduced (not a Git worktree)",
        }
    git_root = Path(os.fsdecode(top.stdout).strip()).resolve(strict=True)
    if not git_root.is_relative_to(root) and not root.is_relative_to(git_root):
        raise WorkspaceError("Git root is outside the selected workspace")
    branch_result = inspect_git(git_root, "rev-parse", "--abbrev-ref", "HEAD")
    commit_result = inspect_git(git_root, "rev-parse", "--verify", "HEAD")
    branch = os.fsdecode(branch_result.stdout).strip() if branch_result.returncode == 0 else None
    current_commit = (
        os.fsdecode(commit_result.stdout).strip() if commit_result.returncode == 0 else None
    )
    status_result = inspect_git(git_root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if status_result.returncode != 0:
        raise WorkspaceError("Git could not inspect workspace changes")
    files: list[dict[str, Any]] = []
    fingerprint_bytes = 0
    for entry in _porcelain_entries(status_result.stdout):
        relative = entry["path"]
        if len(relative) > MAX_FILE_PATH_CHARS or _path_is_sensitive(relative):
            continue
        candidate = git_root / relative
        try:
            lexical = Path(os.path.normpath(os.fspath(candidate)))
            if not lexical.is_relative_to(root):
                continue
            # Inspect each path component without resolving symlinks. A tracked
            # or untracked symlink is metadata only; never stat its target.
            relative_parts = Path(relative).parts
            cursor = git_root
            unsafe_parent = False
            for part in relative_parts[:-1]:
                cursor = cursor / part
                parent_info = cursor.lstat()
                if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
                    unsafe_parent = True
                    break
            if unsafe_parent:
                info = None
            else:
                info = candidate.lstat()
        except (OSError, RuntimeError):
            info = None
        kind = (
            "symlink"
            if info is not None and stat.S_ISLNK(info.st_mode)
            else "file"
            if info is not None and stat.S_ISREG(info.st_mode)
            else "directory"
            if info is not None and stat.S_ISDIR(info.st_mode)
            else "deleted-or-unavailable"
        )
        item: dict[str, Any] = {
            "path": relative,
            "status": entry["status"],
            "kind": kind,
            "size_bytes": info.st_size if info is not None and kind == "file" else None,
            "mtime_ns": info.st_mtime_ns if info is not None else None,
        }
        if kind == "file" and info is not None:
            size = info.st_size
            if (
                size <= MAX_FINGERPRINT_FILE_BYTES
                and fingerprint_bytes + size <= MAX_FINGERPRINT_TOTAL_BYTES
            ):
                try:
                    item["sha256"] = _fingerprint_file(git_root, tuple(relative_parts), info)
                    item["fingerprint"] = "sha256"
                    fingerprint_bytes += size
                except (OSError, WorkspaceError):
                    # An unstable or unsafe path makes this snapshot unusable
                    # for handoff rather than silently weakening revalidation.
                    raise WorkspaceError(
                        "workspace changed or was unsafe during snapshot"
                    ) from None
            else:
                item["fingerprint"] = "stat-only (file or total fingerprint limit)"
        files.append(item)
        if len(files) >= MAX_CHANGED_FILES:
            break
    return {
        "root": str(root),
        "git": True,
        "branch": branch if branch != "HEAD" else "(detached HEAD)",
        # The checkpoint's base is the exact HEAD observed alongside the
        # changed-file snapshot. This is not a pull-request merge base.
        "base_commit": current_commit,
        "base_reference": "HEAD at checkpoint capture" if current_commit else None,
        "current_commit": current_commit,
        "files": files,
        "capabilities": "full Git metadata; base is checkpoint HEAD, not a branch merge base",
    }


def policy_identity(config: ReflexConfig) -> dict[str, str]:
    serialized = json.dumps(config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return {
        "version": "jev-reflex-0.1.0",
        "sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "mode": config.mode,
    }


def new_task_record(
    *,
    workspace: Path,
    config: ReflexConfig,
    objective: str,
    constraints: list[str],
    source_provider: str | None,
    source_session: str | None,
    destination_provider: str,
    agent_summary: str = "",
) -> dict[str, Any]:
    snapshot = collect_workspace_state(workspace)
    now = datetime.now(UTC).isoformat()
    task_id = str(uuid.uuid4())
    return {
        "schema_version": TASK_VERSION,
        "task_id": task_id,
        "created_at": now,
        "updated_at": now,
        "objective": objective,
        "constraints": constraints,
        "approved_decisions": [],
        "completed_work": [],
        "pending_work": [],
        "workspace": snapshot,
        "tests": [],
        "open_questions": [],
        "known_failures": [],
        "agent_authored_summary": agent_summary,
        "policy": policy_identity(config),
        "enforcement_coverage": {
            "mode": config.mode,
            "status": "hook activation is not verifiable by JRX",
        },
        "source": {"provider": source_provider, "session_id": source_session},
        "destination": {"provider": destination_provider},
        "context_delivery": "prepared; awaiting user review",
    }


def save_task_record(record: dict[str, Any]) -> Path:
    if record.get("schema_version") != TASK_VERSION:
        raise WorkspaceError("unsupported task record version")
    try:
        uuid.UUID(str(record.get("task_id")))
    except (ValueError, TypeError, AttributeError):
        raise WorkspaceError("invalid task record identity") from None
    directory = private_state_directory() / "tasks"
    path = directory / f"{record['task_id']}.json"
    body = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    if len(body.encode("utf-8")) > MAX_TASK_RECORD_BYTES:
        raise WorkspaceError("task record exceeds the safe size limit")
    atomic_write(path, body.encode("utf-8"))
    return path


def load_task_record(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise WorkspaceError("task record is not a regular file")
        if info.st_size > MAX_TASK_RECORD_BYTES:
            raise WorkspaceError("task record exceeds the safe size limit")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise WorkspaceError("task record permissions are not private")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise WorkspaceError("task record is missing or corrupt") from None
    if not isinstance(value, dict) or value.get("schema_version") != TASK_VERSION:
        raise WorkspaceError("task record version is unsupported")
    return value


def list_task_records(workspace: Path, provider: str, *, limit: int = 100) -> list[dict[str, Any]]:
    """Load recent compatible session references for this exact workspace/provider."""
    canonical = validate_workspace(workspace)
    directory = private_state_directory() / "tasks"
    records: list[dict[str, Any]] = []
    try:
        paths = list(directory.glob("*.json"))
    except OSError:
        return []
    for path in paths:
        try:
            record = load_task_record(path)
        except WorkspaceError:
            continue
        snapshot = record.get("workspace")
        session = record.get("session")
        if not isinstance(snapshot, dict) or snapshot.get("root") != str(canonical):
            continue
        if not isinstance(session, dict) or session.get("provider") != provider:
            continue
        records.append(record)
    records.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
    return records[: max(1, min(limit, 500))]


def snapshot_digest(snapshot: dict[str, Any]) -> str:
    body = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()
