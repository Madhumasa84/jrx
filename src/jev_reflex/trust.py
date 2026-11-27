"""Whether the evaluating user can rewrite or replace a local trust input.

Signatures prove what a file says. Which file is consulted, whether a signature is
required, and which key verifies it are only trustworthy when the user whose
actions are being evaluated cannot change them. This module owns that question.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


def evaluator_identity() -> tuple[int, frozenset[int]]:
    """The effective uid and groups whose writes evaluation cannot trust."""
    return os.geteuid(), frozenset({os.getegid(), *os.getgroups()})


def _writable(details: os.stat_result, uid: int, groups: frozenset[int]) -> bool:
    if details.st_uid == uid:
        return True  # an owner can always chmod and then write
    if details.st_mode & stat.S_IWOTH:
        return True
    return bool(details.st_mode & stat.S_IWGRP) and details.st_gid in groups


def protected_location(path: Path, uid: int, groups: frozenset[int], depth: int = 0) -> Path | None:
    """Return the real path when ``uid`` can neither rewrite nor replace it, else None.

    Every component is checked from the root: the uid must not own it, and its directory
    must not let the uid rename or unlink entries (a sticky directory protects entries
    the uid does not own). Symlinks are followed only after that check, so the uid cannot
    re-point them. A missing final component is protected when its directory is, since
    the uid could then neither have removed it nor create it. Root can change anything,
    and ACLs or capabilities beyond the mode bits are not modelled.
    """
    if uid == 0 or depth > 32 or not path.is_absolute() or ".." in path.parts:
        return None
    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, name in enumerate(parts):
        directory = os.stat(current)
        child_path = current / name
        if directory.st_uid == uid:
            return None
        try:
            child = os.lstat(child_path)
        except FileNotFoundError:
            # Absent, and the uid cannot create it unless the directory is writable.
            return None if _writable(directory, uid, groups) else Path(current, *parts[index:])
        if child.st_uid == uid:
            return None
        if _writable(directory, uid, groups) and not directory.st_mode & stat.S_ISVTX:
            return None
        if stat.S_ISLNK(child.st_mode):
            target = Path(os.readlink(child_path))
            resolved = protected_location(
                target if target.is_absolute() else current / target, uid, groups, depth + 1
            )
            if resolved is None:
                return None
            current = resolved
        else:
            current = child_path
    # A symlink target may be an intermediate directory; only the full path names a file.
    if depth == 0 and current.exists():
        final = os.stat(current)
        if not stat.S_ISREG(final.st_mode) or _writable(final, uid, groups):
            return None
    return current
