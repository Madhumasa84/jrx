"""Deterministic repository-boundary and canonical-path checks."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from ..models import DeterministicFinding, EvaluationContext
from .common import action_argv

_URL_RE = re.compile(r"(?i)^(?:[a-z][a-z0-9+.-]*:)?//")
_PATHISH_RE = re.compile(r"(?:^~|^/|^\.\.?/|/|\\|\.{2}(?:$|/|\\))")
_INPUT_PATH_KEYS = {
    "path",
    "file_path",
    "filepath",
    "target_path",
    "target_file",
    "working_directory",
    "cwd",
    "directory",
    "workdir",
    "destination",
    "output",
}


def _clear() -> DeterministicFinding:
    return DeterministicFinding(
        check="repo_boundary",
        triggered=False,
        severity="low",
        reason_code="CLEAR",
    )


def _trigger(reason_code: str) -> DeterministicFinding:
    return DeterministicFinding(
        check="repo_boundary",
        triggered=True,
        severity="high",
        reason_code=reason_code,
        blocking=True,
    )


def _canonical(value: str, base: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve(strict=False)


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _candidate_paths(argv: list[str]) -> list[str]:
    if not argv:
        return []
    candidates: list[str] = []
    skip_next = False
    # The first token is the executable. Flags with known path values are inspected,
    # while remote names, URLs, and package identifiers are not treated as paths.
    path_value_flags = {
        "-C",
        "--cwd",
        "--directory",
        "--work-tree",
        "--git-dir",
        "-o",
        "--output",
    }
    for index, item in enumerate(argv[1:], start=1):
        if skip_next:
            skip_next = False
            continue
        if item in path_value_flags:
            if index + 1 < len(argv):
                candidates.append(argv[index + 1])
            skip_next = True
            continue
        if any(item.startswith(flag + "=") for flag in path_value_flags if flag.startswith("--")):
            candidates.append(item.split("=", 1)[1])
            continue
        if item.startswith("-") or _URL_RE.match(item):
            continue
        if _PATHISH_RE.search(item):
            candidates.append(item)
    return candidates


def _input_paths(value: object) -> list[str]:
    """Extract only explicitly path-shaped tool-input fields."""

    if not isinstance(value, Mapping):
        return []
    candidates: list[str] = []
    for key, nested in value.items():
        name = str(key).lower()
        if name in _INPUT_PATH_KEYS:
            if isinstance(nested, str):
                candidates.append(nested)
            elif isinstance(nested, list | tuple):
                candidates.extend(str(item) for item in nested if isinstance(item, str))
        elif isinstance(nested, Mapping):
            candidates.extend(_input_paths(nested))
    return candidates


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    working_directory = Path(context.working_directory or context.repository_root or ".").resolve(
        strict=False
    )
    repository_root = Path(context.repository_root or context.working_directory or ".").resolve(
        strict=False
    )
    if not _within(working_directory, repository_root):
        return [_trigger("CWD_OUTSIDE_REPO")]

    candidates = [
        *_candidate_paths(action_argv(context)),
        *_input_paths(context.proposed_action.input),
    ]
    for value in candidates:
        if _URL_RE.match(value):
            continue
        if not _within(_canonical(value, working_directory), repository_root):
            return [_trigger("TARGET_OUTSIDE_REPO")]
    return [_clear()]
