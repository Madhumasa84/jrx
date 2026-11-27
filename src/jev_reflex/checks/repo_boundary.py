"""Deterministic repository-boundary and canonical-path checks."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import unquote, urlparse

from ..models import DeterministicFinding, EvaluationContext
from .common import expand_home, git_command, roots, unresolved_word, write_destinations
from .shell import SHELLS, WRAPPERS, container_exec, inspect, program, ssh_invocation

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
    # Claude Code NotebookEdit and Antigravity file tools (keys are case-folded).
    "notebook_path",
    "targetfile",
    "absolutepath",
    "directorypath",
    "searchpath",
    "searchdirectory",
    "new_path",
    "old_path",
    "source_path",
    "destination_path",
    "target_directory",
}
# Commands whose every operand is a file, so a bare ``$VAR`` operand is a path.
_FILE_OPERAND_COMMANDS = frozenset(
    {
        "cat",
        "tac",
        "nl",
        "head",
        "tail",
        "bat",
        "less",
        "more",
        "base64",
        "xxd",
        "od",
        "strings",
        "cp",
        "mv",
        "ln",
        "install",
        "rsync",
        "scp",
        "tee",
        "touch",
        "rm",
        "rmdir",
        "unlink",
        "shred",
        "source",
        ".",
    }
)
_OUTPUT_ONLY_COMMANDS = frozenset({"echo", "printf", ":", "true", "false", "test", "[", "[["})
# A Git message option: ``-m MSG``, ``-am MSG``, ``-mMSG``, ``--message[=MSG]``.
_GIT_MESSAGE_RE = re.compile(r"^(?:-[A-Za-z]*m.*|--message(?:=.*)?)$")
_GIT_MESSAGE_COMMANDS = {(name,) for name in ("commit", "tag", "merge", "stash", "notes")}
# ``field@path`` (HTTPie file fields) and similar attached file references.
_FIELD_FILE_RE = re.compile(r"^[\w.:-]+@(.+)$")


def _is_remote_url(value: str) -> bool:
    return bool(_URL_RE.match(value)) and not value.lower().startswith("file://")


def _embedded_path_literals(value: str) -> list[str]:
    return [
        match.group("value")
        for match in _PATH_LITERAL_RE.finditer(value)
        if _PATHISH_RE.search(match.group("value"))
    ]


def _path_values(item: str, *, bare: bool = False) -> list[str]:
    """Path-shaped values in a word, including ``key=value`` and ``@file`` forms."""

    values = [item]
    _, separator, value = item.partition("=")
    if separator and value:
        values.append(value)
    if match := _FIELD_FILE_RE.match(item):
        values.append(match.group(1))
    values.extend(value[1:] for value in tuple(values) if len(value) > 1 and value[0] in "@<")
    return [
        value
        for value in dict.fromkeys(values)
        if not _is_remote_url(value)
        and (
            _PATHISH_RE.search(value)
            or (bare and (unresolved_word(value) or expand_home(value) != value))
        )
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


def _review(reason_code: str) -> DeterministicFinding:
    return DeterministicFinding(
        check="repo_boundary",
        triggered=True,
        severity="medium",
        reason_code=reason_code,
    )


def _canonical(value: str, base: Path) -> Path:
    parsed = urlparse(value)
    if parsed.scheme.lower() == "file":
        if parsed.netloc.lower() not in {"", "localhost"} or not parsed.path:
            raise ValueError("non-local file URI")
        value = unquote(parsed.path)
    path = Path(expand_home(value)).expanduser()
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
    if name in WRAPPERS | SHELLS | {"eval", "su", "runuser"}:
        # The shell plan supplies the executable payload as its own command.
        return candidates
    # Remote and container payloads name paths on another filesystem; only these
    # options name files on this machine.
    if name == "ssh":
        return list(ssh_invocation(argv).files)
    if name in {"docker", "podman"} and (exec_form := container_exec(argv)) is not None:
        return list(exec_form.files)
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
    bare = name in _FILE_OPERAND_COMMANDS
    message_next = False
    for item in argv[1:]:
        if skip_next:
            skip_next = False
            candidates.append(item)
            continue
        if code_next:
            candidates.extend(_embedded_path_literals(item))
            code_next = False
            continue
        if message_next:
            message_next = False
            continue
        if not literal and item == "--":
            literal = True
            continue
        if not literal and item in path_value_flags:
            skip_next = True
            continue
        if (
            not literal
            and name == "git"
            and argv[1:2] in _GIT_MESSAGE_COMMANDS
            and _GIT_MESSAGE_RE.match(item)
        ):
            # Commit, tag, merge and stash messages are prose, not paths.
            message_next = item.endswith("m") or item == "--message"
            continue
        if not literal and item.startswith("-") and item != "-":
            flag, sep, value = item.partition("=")
            if sep and flag in path_value_flags:
                candidates.append(value)
                continue
            if item.startswith("-o") and len(item) > 2 and "-o" in path_value_flags:
                candidates.append(item[2:])
                continue
            code_next = name.startswith(("python", "node", "perl", "ruby")) and item in {
                "-c",
                "-e",
                "--eval",
            }
            # Values attached to an option: ``--target-directory=/tmp``, ``-C/tmp``.
            # A one-character value is a delimiter (``cut -d/``, ``awk -F/``).
            attached = value if sep and flag.startswith("--") else item[2:]
            if not item.startswith("--") or sep:
                if len(attached) > 1:
                    candidates.extend(_path_values(attached))
            continue
        candidates.extend(_path_values(item, bare=bare))
    if name in _OUTPUT_ONLY_COMMANDS:
        # Their arguments are printed, never opened: only literal paths matter.
        return [candidate for candidate in candidates if not unresolved_word(candidate)]
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


def _inside_paths(
    values: list[str], directories: set[Path], root: Path, unresolved: list[str] | None
) -> bool:
    """Whether every concrete value stays in the repository.

    Shell words that still hold a run-time expansion are collected in
    ``unresolved`` instead; ``None`` treats every value as a literal path.
    """

    for value in values:
        if _is_remote_url(value):
            continue
        if unresolved is not None and unresolved_word(value):
            unresolved.append(value)
            continue
        if not all(_within(_canonical(value, directory), root) for directory in directories):
            return False
    return True


def _alternate_directories(argv: tuple[str, ...], assignments: tuple[str, ...]) -> list[str]:
    values = []
    name = program(argv[0]) if argv else ""
    if name in {"env", "sudo"}:
        short = "-C" if name == "env" else "-D"
        if name == "env":
            assignments += argv[1:]
        for index, word in enumerate(argv[1:], 1):
            if word in {short, "--chdir"} and index + 1 < len(argv):
                values.append(argv[index + 1])
            elif word.startswith("--chdir="):
                values.append(word.split("=", 1)[1])
            elif word.startswith(short) and len(word) > 2:
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
    # Shell words whose expansion is only known at run time (``$VAR``, ``$(...)``).
    unresolved: list[str] = []
    try:
        # Tool-input paths are literal file names (``posts.$slug.tsx`` is valid).
        if not _inside_paths(
            input_paths(context.proposed_action.input),
            directories,
            repository_root,
            None,
        ):
            return [_trigger("TARGET_OUTSIDE_REPO")]
        for command in inspect(context.proposed_action).commands:
            if command.context != "local":
                continue  # its paths are on the remote host or in the container
            alternate = _alternate_directories(command.argv, command.assignments)
            if not _inside_paths(alternate, directories, repository_root, unresolved):
                return [_trigger("TARGET_OUTSIDE_REPO")]
            directories.update(
                _canonical(path, base)
                for base in tuple(directories)
                for path in alternate
                if not unresolved_word(path)
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
                            if unresolved_word(value):
                                unresolved.append(value)
                                continue
                            git_dirs = {_canonical(value, base) for base in git_dirs}
                            if not all(_within(base, repository_root) for base in git_dirs):
                                return [_trigger("TARGET_OUTSIDE_REPO")]
                    if not _inside_paths(
                        _candidate_paths(("git", *git.args)),
                        git_dirs,
                        repository_root,
                        unresolved,
                    ):
                        return [_trigger("TARGET_OUTSIDE_REPO")]
                else:
                    values.extend(_candidate_paths(command.argv))
                if program(command.argv[0]) in {"cd", "pushd"}:
                    args = [arg for arg in command.argv[1:] if arg not in {"-P", "-L", "--"}]
                    if not args:
                        return [_trigger("TARGET_OUTSIDE_REPO")]
                    if args[0] != "-" and unresolved_word(args[0]):
                        unresolved.append(args[0])
                    elif args[0] != "-":
                        next_cwds = {_canonical(args[0], base) for base in directories}
                        if not all(_within(base, repository_root) for base in next_cwds):
                            return [_trigger("TARGET_OUTSIDE_REPO")]
                        # Keep both paths when a conditional or subshell can keep the old CWD.
                        directories.update(next_cwds)
                        if len(directories) > 16:
                            return [_trigger("TARGET_OUTSIDE_REPO")]
            if not _inside_paths(values, directories, repository_root, unresolved):
                return [_trigger("TARGET_OUTSIDE_REPO")]
            for base in tuple(directories):
                # Extraction directories and git apply patch targets must stay inside.
                destinations = write_destinations(command, base, repository_root)
                if destinations is not None and not _inside_paths(
                    list(destinations.paths), {base}, repository_root, unresolved
                ):
                    return [_trigger("TARGET_OUTSIDE_REPO")]
    except (OSError, RuntimeError, ValueError):
        return [_trigger("TARGET_OUTSIDE_REPO")]
    if unresolved:
        return [_review("PATH_UNRESOLVED")]
    return [_clear()]
