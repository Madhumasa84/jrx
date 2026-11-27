"""Whether the evaluating user can rewrite or replace a local trust input.

Signatures prove what a file says. Which file is consulted, whether a signature is
required, and which key verifies it are only trustworthy when the user whose
actions are being evaluated cannot change them. This module owns that question.

The check models ownership, mode bits, sticky directories and symlinks, and asks
the kernel (``access(2)``) about the files it inspects so POSIX ACL grants count as
write access. It cannot see bind mounts or overlays set up outside the evaluator's
view, mandatory access control (SELinux, AppArmor, macOS sandbox profiles) that
might further restrict writes, or a host that runs the agent with more privileges
than the evaluator. Root and Linux processes holding a capability that overrides
file permissions are treated as able to change anything.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

# Linux capabilities that override file ownership or permission checks, or allow
# mounting over a path (CapEff bit number -> name).
_BYPASSING_CAPABILITIES = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    3: "CAP_FOWNER",
    21: "CAP_SYS_ADMIN",
}


@dataclass(frozen=True)
class Identity:
    """The user whose writes evaluation cannot trust."""

    uid: int
    groups: frozenset[int]
    # Root, or a Linux capability that overrides file permissions: nothing is protected.
    privileged: bool = False
    # Also ask the kernel, which applies ACLs the mode bits do not show. Only the real
    # process identity can be asked; tests that simulate another uid leave this off.
    kernel: bool = False


def bypassing_capabilities(status: Path = Path("/proc/self/status")) -> list[str]:
    """Names of effective Linux capabilities that override file permissions."""
    try:
        lines = status.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return []  # not Linux, or no procfs: only the uid check applies
    for line in lines:
        if line.startswith("CapEff:"):
            mask = int(line.split()[1], 16)
            return [name for bit, name in _BYPASSING_CAPABILITIES.items() if mask >> bit & 1]
    return []


def evaluator_identity() -> Identity:
    """The effective uid and groups of this process, as the kernel will judge them."""
    uid = os.geteuid()
    return Identity(
        uid,
        frozenset({os.getegid(), *os.getgroups()}),
        privileged=uid == 0 or bool(bypassing_capabilities()),
        kernel=True,
    )


def _kernel_allows_write(path: Path) -> bool:
    try:
        if (os.geteuid(), os.getegid()) != (os.getuid(), os.getgid()):
            if os.access not in os.supports_effective_ids:
                return True  # cannot ask for the effective ids: assume writable
            return os.access(path, os.W_OK, effective_ids=True)
        return os.access(path, os.W_OK)
    except OSError:
        return True


def _writable(details: os.stat_result, identity: Identity, path: Path) -> bool:
    if details.st_uid == identity.uid:
        return True  # an owner can always chmod and then write
    if details.st_mode & stat.S_IWOTH:
        return True
    if details.st_mode & stat.S_IWGRP and details.st_gid in identity.groups:
        return True
    # An ACL entry can grant write access that the mode bits do not show.
    return identity.kernel and _kernel_allows_write(path)


def protected_location(path: Path, identity: Identity, depth: int = 0) -> Path | None:
    """Return the real path when ``identity`` can neither rewrite nor replace it, else None.

    Every component is checked from the root: the user must not own it, and its directory
    must not let the user rename or unlink entries (a sticky directory protects entries
    the user does not own). Symlinks are followed only after that check, so the user cannot
    re-point them. A missing final component is protected when its directory is, since
    the user could then neither have removed it nor create it. Read the file through the
    returned path so the bytes used are the bytes whose location was checked.
    """
    if identity.privileged or identity.uid == 0 or depth > 32 or not path.is_absolute():
        return None
    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, name in enumerate(parts):
        if name == "..":
            # As the kernel does: the parent of the directory reached so far, whose
            # symlinks are already resolved, so it is an ancestor checked on the way.
            current = current.parent
            continue
        directory = os.stat(current)
        child_path = current / name
        if directory.st_uid == identity.uid:
            return None
        directory_writable = _writable(directory, identity, current)
        try:
            child = os.lstat(child_path)
        except FileNotFoundError:
            # Absent, and the user cannot create it unless the directory is writable.
            return None if directory_writable else Path(current, *parts[index:])
        if child.st_uid == identity.uid:
            return None
        if directory_writable and not directory.st_mode & stat.S_ISVTX:
            return None
        if stat.S_ISLNK(child.st_mode):
            target = Path(os.readlink(child_path))
            resolved = protected_location(
                target if target.is_absolute() else current / target, identity, depth + 1
            )
            if resolved is None:
                return None
            current = resolved
        else:
            current = child_path
    # A symlink target may be an intermediate directory; only the full path names a file.
    if depth == 0 and current.exists():
        final = os.stat(current)
        if not stat.S_ISREG(final.st_mode) or _writable(final, identity, current):
            return None
    return current


def operator_controlled(path: Path | str | None, identity: Identity | None = None) -> bool:
    """Whether the evaluating user can neither rewrite nor replace ``path``."""
    if path is None:
        return False
    who = identity if identity is not None else evaluator_identity()
    return protected_location(Path(path).expanduser().absolute(), who) is not None
