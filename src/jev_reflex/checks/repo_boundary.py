"""Deterministic repository-boundary and canonical-path checks."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import unquote, urlparse

from ..models import DeterministicFinding, EvaluationContext
from .common import git_command, roots
from .shell import SHELLS, WRAPPERS, inspect, program

# A leading ``//`` is an absolute POSIX path, not necessarily a URL. ``file://``
# is also a local path form and must be canonicalized instead of skipped.
_URL_RE = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://")
_PATHISH_RE = re.compile(r"(?:^~|^/|^\.\.?/|/|\\|\.{2}(?:$|/|\\))")
_PATH_LITERAL_RE = re.compile(r"(?P<quote>['\"])(?P<value>[^'\"\r\n]+)(?P=quote)")
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


def _is_remote_url(value: str) -> bool:
    return bool(_URL_RE.match(value)) and not value.lower().startswith("file://")


def _embedded_path_literals(value: str) -> list[str]:
    return [
        match.group("value")
        for match in _PATH_LITERAL_RE.finditer(value)
        if _PATHISH_RE.search(match.group("value"))
    ]


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
    parsed = urlparse(value)
    if parsed.scheme.lower() == "file":
        if parsed.netloc.lower() not in {"", "localhost"} or not parsed.path:
            raise ValueError("non-local file URI")
        value = unquote(parsed.path)
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


def _candidate_paths(argv: tuple[str, ...]) -> list[str]:
    if not argv:
        return []
    candidates: list[str] = []
    name = program(argv[0])
    if name in WRAPPERS | SHELLS | {"eval"}:
        # The shell plan supplies the executable payload as its own command.
        return candidates
    path_value_flags = {
        "--cwd",
        "--directory",
        "--work-tree",
        "--git-dir",
        "--output",
        "--rootdir",
        "--confcutdir",
        "--basetemp",
        "--project",
        "--prefix",
        "--chdir",
        "--workdir",
        "--work-directory",
        "--config-file",
        "--output-dir",
        "--cache-dir",
        "--temp-dir",
    }
    if name == "git":
        path_value_flags.add("-C")
    if name in {"curl", "wget", "gcc", "clang", "cc", "rustc"}:
        path_value_flags.add("-o")
    if name == "wget":
        path_value_flags.add("-O")
    code_next = False
    literal = False
    skip_next = False
    for item in argv[1:]:
        if skip_next:
            skip_next = False
            candidates.append(item)
            continue
        if code_next:
            candidates.extend(_embedded_path_literals(item))
            code_next = False
            continue
        if not literal and item == "--":
            literal = True
            continue
        if not literal and item in path_value_flags:
            skip_next = True
            continue
        if not literal:
            flag, sep, value = item.partition("=")
            if sep and flag in path_value_flags:
                candidates.append(value)
                continue
            if item.startswith("-o") and len(item) > 2 and "-o" in path_value_flags:
                candidates.append(item[2:])
                continue
            if item.startswith("-"):
                code_next = name.startswith(("python", "node", "perl", "ruby")) and item in {
                    "-c",
                    "-e",
                    "--eval",
                }
                continue
        if _PATHISH_RE.search(item) and not _is_remote_url(item):
            candidates.append(item)
    return candidates


def input_paths(value: object) -> list[str]:
    """Extract only explicitly path-shaped tool-input fields."""

    if isinstance(value, list | tuple):
        return [path for item in value for path in input_paths(item)]
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
        if isinstance(nested, Mapping | list | tuple):
            candidates.extend(input_paths(nested))
    return candidates


def _inside_paths(values: list[str], directories: set[Path], root: Path) -> bool:
    return all(
        _is_remote_url(value) or _within(_canonical(value, directory), root)
        for directory in directories
        for value in values
    )


def _alternate_directories(argv: tuple[str, ...], assignments: tuple[str, ...]) -> list[str]:
    values = []
    if argv and program(argv[0]) == "env":
        assignments += argv[1:]
        for index, word in enumerate(argv[1:], 1):
            if word in {"-C", "--chdir"} and index + 1 < len(argv):
                values.append(argv[index + 1])
            elif word.startswith("--chdir="):
                values.append(word.split("=", 1)[1])
            elif word.startswith("-C") and len(word) > 2:
                values.append(word[2:])
    for assignment in assignments:
        if assignment.startswith("CDPATH="):
            values.extend(part for part in assignment[7:].split(":") if part)
    return values


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    try:
        working_directory, repository_root = roots(context)
    except (OSError, RuntimeError, ValueError):
        return [_trigger("CWD_OUTSIDE_REPO")]
    if not _within(working_directory, repository_root):
        return [_trigger("CWD_OUTSIDE_REPO")]

    directories = {working_directory}
    try:
        if not _inside_paths(
            input_paths(context.proposed_action.input), directories, repository_root
        ):
            return [_trigger("TARGET_OUTSIDE_REPO")]
        for command in inspect(context.proposed_action).commands:
            alternate = _alternate_directories(command.argv, command.assignments)
            if not _inside_paths(alternate, directories, repository_root):
                return [_trigger("TARGET_OUTSIDE_REPO")]
            directories.update(
                _canonical(path, base) for base in tuple(directories) for path in alternate
            )
            if len(directories) > 16:
                return [_trigger("TARGET_OUTSIDE_REPO")]
            values = [
                target
                for operator, target in command.redirects
                if target != "/dev/null"
                and operator not in {"<<<", "<<", "<<-"}
                and not (operator in {"<&", ">&"} and (target.isdecimal() or target == "-"))
            ]
            if command.argv:
                git = git_command(command)
                if git is not None:
                    for key, value in git.options:
                        if key in {"--git-dir", "--work-tree"}:
                            values.append(value)
                    git_dirs = directories.copy()
                    for key, value in git.options:
                        if key == "-C" and value:
                            git_dirs = {_canonical(value, base) for base in git_dirs}
                            if not all(_within(base, repository_root) for base in git_dirs):
                                return [_trigger("TARGET_OUTSIDE_REPO")]
                    if not _inside_paths(
                        _candidate_paths(("git", *git.args)), git_dirs, repository_root
                    ):
                        return [_trigger("TARGET_OUTSIDE_REPO")]
                else:
                    values.extend(_candidate_paths(command.argv))
                if program(command.argv[0]) in {"cd", "pushd"}:
                    args = [arg for arg in command.argv[1:] if arg not in {"-P", "-L", "--"}]
                    if not args:
                        return [_trigger("TARGET_OUTSIDE_REPO")]
                    if args[0] != "-":
                        next_cwds = {_canonical(args[0], base) for base in directories}
                        if not all(_within(base, repository_root) for base in next_cwds):
                            return [_trigger("TARGET_OUTSIDE_REPO")]
                        # Keep both paths when a conditional or subshell can keep the old CWD.
                        directories.update(next_cwds)
                        if len(directories) > 16:
                            return [_trigger("TARGET_OUTSIDE_REPO")]
            if not _inside_paths(values, directories, repository_root):
                return [_trigger("TARGET_OUTSIDE_REPO")]
    except (OSError, RuntimeError, ValueError):
        return [_trigger("TARGET_OUTSIDE_REPO")]
    return [_clear()]
