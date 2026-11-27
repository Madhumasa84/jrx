"""Protect explicit writes to agent instructions, hooks, and policy inputs."""

from __future__ import annotations

import ast
import fnmatch
import os
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Literal

from ..config import ReflexConfig
from ..context import MAX_DETERMINISTIC_DIFF_CHARS, TRUNCATION_MARKER
from ..models import DeterministicFinding, EvaluationContext
from .common import (
    absolute_path,
    expand_home,
    git_command,
    inplace_files,
    long_option,
    mask_expansions,
    python_inline_code,
    roots,
    unresolved_word,
    write_destinations,
)
from .diff import proposed_changes
from .execution import inline_code, is_python
from .repo_boundary import input_paths
from .shell import Command, inspect, program

CONTROL_NAMES = frozenset(
    {"agents.md", "claude.md", ".cursorrules", "reflex.yaml", "bootstrap.yaml"}
)
CONTROL_FILES = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".codex/hooks.json",
    ".agents/hooks.json",
    ".github/copilot-instructions.md",
    ".git/config",
)
HOME_FILES = (".bashrc", ".zshrc", ".profile")
WRITE_COMMANDS = {
    "rm",
    "mv",
    "rmdir",
    "touch",
    "tee",
    "truncate",
    "shred",
    "chmod",
    "chown",
    "chgrp",
    "unlink",
    "patch",
    "mkdir",
}
_OUTPUT = {">", ">>", ">|", "&>", "&>>", "<>"}
_PATCH_HEADER = re.compile(r"^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$", re.M)
# Any tool whose name mentions a write verb anywhere: ``Edit``, ``MultiEdit``,
# ``NotebookEdit``, ``str_replace_editor``, ``apply_patch``, ``write_to_file``,
# ``replace_file_content``, ``multi_replace_file_content`` and MCP variants.
_WRITE_TOOL = re.compile(
    r"edit|write|replace|append|patch|delete|remove|move|rename|create|update|insert|"
    r"overwrite|save",
    re.I,
)
# Options taking a separate value, so the value is never mistaken for a path.
_VALUE_OPTIONS = {
    "touch": {"-d", "--date", "-t", "-r", "--reference"},
    "truncate": {"-s", "--size", "-r", "--reference"},
    "mkdir": {"-m", "--mode"},
    "shred": {"-n", "--iterations", "-s", "--size", "--random-source"},
    "chmod": {"--reference"},
    "chown": {"--reference", "--from"},
    "chgrp": {"--reference"},
}
_COPY_COMMANDS = {"cp", "mv", "install", "ln", "rsync", "scp"}
# Short options taking a value (attached or next word) per copy command.
_COPY_SHORT_VALUES = {
    "cp": "St",
    "mv": "St",
    "ln": "St",
    "install": "Stmog",
    "rsync": "efTBM",
    "scp": "cFiJloPSX",
}
_COPY_LONG_VALUES = {
    "cp": {"--suffix", "--target-directory"},
    "mv": {"--suffix", "--target-directory"},
    "ln": {"--suffix", "--target-directory"},
    "install": {
        "--suffix",
        "--target-directory",
        "--mode",
        "--owner",
        "--group",
        "--strip-program",
    },
    "rsync": {
        "--rsh",
        "--filter",
        "--exclude",
        "--include",
        "--exclude-from",
        "--include-from",
        "--files-from",
        "--temp-dir",
        "--partial-dir",
        "--backup-dir",
        "--compare-dest",
        "--copy-dest",
        "--link-dest",
        "--chmod",
        "--chown",
        "--suffix",
        "--block-size",
        "--port",
        "--log-file",
        "--out-format",
        "--password-file",
        "--remote-option",
        "--rsync-path",
        "--max-size",
        "--min-size",
        "--bwlimit",
        "--timeout",
    },
    "scp": set(),
}
# Copy forms that recreate a source directory's whole subtree at the destination.
_TREE_COPIES = {"cp", "rsync", "scp"}
# A control file that sits directly in each control directory (see CONTROL_FILES).
_DIRECTORY_CONTROL_FILES = {
    ".git": "config",
    ".github": "copilot-instructions.md",
    ".claude": "settings.json",
    ".codex": "hooks.json",
    ".agents": "hooks.json",
}
_MAX_TREE_ENTRIES = 4096
_MAX_DIRECTORIES = 16


class _Unresolved(Exception):
    """A write target that cannot be resolved to concrete paths."""


def protected(path: Path, home: Path) -> bool:
    parts = tuple(part.casefold() for part in path.parts)
    if parts[-1] in CONTROL_NAMES:
        return True
    if path.parent == home and parts[-1] in HOME_FILES:
        return True
    if any(parts[index : index + 2] == (".git", "hooks") for index in range(len(parts) - 1)):
        return True
    suffix = "/".join(parts[-2:])
    return suffix in CONTROL_FILES or parts[-1] in {".claude", ".codex", ".agents"}


def _operands(args: Sequence[str], values: set[str]) -> list[str]:
    operands: list[str] = []
    skip = literal = False
    for arg in args:
        if skip:
            skip = False
        elif literal or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
        elif arg == "--":
            literal = True
        else:
            skip = arg in values
    return operands


def _join(directory: str, name: str) -> str:
    if not directory:
        return name
    stripped = directory.rstrip("/")
    return f"{stripped}/{name}" if stripped else f"/{name}"


def _tree(root: Path) -> Iterator[str]:
    count = 0
    for directory, folders, files in os.walk(root, followlinks=False):
        for name in (*folders, *files):
            count += 1
            if count > _MAX_TREE_ENTRIES:
                raise _Unresolved(str(root))
            yield Path(directory, name).relative_to(root).as_posix()


def _copy_targets(name: str, args: Sequence[str], base: Path) -> Iterator[str]:
    """Destination paths for cp/mv/install/ln/rsync/scp, including directory targets."""

    short_values = _COPY_SHORT_VALUES[name]
    long_values = _COPY_LONG_VALUES[name]
    operands: list[str] = []
    target_directory: str | None = None
    file_target = False
    expect: str | None = None
    literal = False
    for arg in args:
        if expect is not None:
            if expect == "t":
                target_directory = arg
            expect = None
            continue
        if literal or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
            continue
        if arg == "--":
            literal = True
            continue
        if arg.startswith("--"):
            option, separator, value = arg.partition("=")
            matches = long_option(option, long_values | {"--no-target-directory"})
            if name in {"cp", "mv", "ln", "install"} and "--target-directory" in matches:
                if separator:
                    target_directory = value
                else:
                    expect = "t"
            elif "--no-target-directory" in matches and len(matches) == 1:
                file_target = True
            elif matches and not separator:
                expect = ""
            continue
        cluster = arg[1:]
        for position, letter in enumerate(cluster):
            if letter == "T" and name in {"cp", "mv", "ln", "install"}:
                file_target = True
            if letter in short_values:
                rest = cluster[position + 1 :]
                key = "t" if letter == "t" and name in {"cp", "mv", "ln", "install"} else ""
                if rest:
                    if key:
                        target_directory = rest
                else:
                    expect = key
                break
    if target_directory is not None:
        sources, destination = operands, target_directory
        directory_target = True
    elif not operands:
        return
    elif name == "ln" and len(operands) == 1:
        sources, destination = operands, "."
        directory_target = True
    else:
        sources, destination = operands[:-1], operands[-1]
        leaf = destination.rstrip("/").rsplit("/", 1)[-1]
        directory_target = not file_target and (
            len(sources) > 1
            or destination.endswith("/")
            or leaf in {"", ".", ".."}
            or (not unresolved_word(destination) and absolute_path(destination, base).is_dir())
        )
    yield destination
    if name == "mv":
        yield from sources
    if not directory_target:
        return
    trees: list[tuple[Path, str]] = []
    for source in sources:
        stripped = source.rstrip("/")
        leaf = stripped.rsplit("/", 1)[-1]
        contents = leaf in {"", ".", ".."} or (name == "rsync" and source.endswith("/"))
        if not contents:
            yield _join(destination, leaf)
        if name in _TREE_COPIES and not unresolved_word(source):
            prefix = destination if contents else _join(destination, leaf)
            trees.append((absolute_path(source, base), prefix))
    # Directory subtrees last: an oversized tree must not hide a plain target.
    for tree_root, prefix in trees:
        if tree_root.is_dir():
            for relative in _tree(tree_root):
                yield _join(prefix, relative)


def _targets(command: Command, base: Path, root: Path) -> Iterable[str]:
    for operator, target in command.redirects:
        if operator in _OUTPUT:
            yield target
    if not command.argv:
        return
    if (destinations := write_destinations(command, base, root)) is not None:
        # A protected destination is a protected write; unknown files under it need review.
        for path in destinations.paths:
            yield path
            sample = _DIRECTORY_CONTROL_FILES.get(Path(expand_home(path)).name.casefold())
            if destinations.unresolved and sample:
                # Unknown members extracted straight into a control directory can be its
                # control file (for example .git/config).
                yield f"{path}/{sample}"
        if destinations.unresolved:
            raise _Unresolved
        return
    name, args = program(command.argv[0]), command.argv[1:]
    if (files := inplace_files(name, args)) is not None:
        yield from files
    elif name in _COPY_COMMANDS:
        yield from _copy_targets(name, args, base)
    elif name in WRITE_COMMANDS:
        operands = _operands(args, _VALUE_OPTIONS.get(name, set()))
        if name in {"chmod", "chown", "chgrp"} and not any(
            arg.startswith("--reference") for arg in args
        ):
            operands = operands[1:]
        yield from operands
    elif name in {"curl", "wget", "dd"}:
        for index, arg in enumerate(args):
            flag, sep, value = arg.partition("=")
            if (
                flag
                in {"--output", "--output-document", "--output-dir", "--directory-prefix", "of"}
                and sep
            ):
                yield value
            elif arg in {
                "-o",
                "-O",
                "-P",
                "--output",
                "--output-document",
                "--output-dir",
                "--directory-prefix",
            } and index + 1 < len(args):
                yield args[index + 1]
            elif len(arg) > 2 and arg.startswith(("-o", "-O")):
                yield arg[2:]
    elif name == "git" and (git := git_command(command)):
        if git.subcommand in {"rm", "mv", "restore", "checkout"}:
            yield from git.args[1:]
    elif name == "find" and "-delete" in args:
        yield from (arg for arg in args if not arg.startswith("-"))
    elif is_python(name) and (code := python_inline_code(command.argv)):
        yield from _python_targets(code)
    elif name in {"node", "nodejs"} and (code := inline_code(command)):
        yield from re.findall(
            r"""\b(?:writeFile|appendFile|unlink|rename|rm)(?:Sync)?\s*\(\s*['"]([^'"]+)""",
            code,
        )


def _python_targets(code: str) -> Iterable[str]:
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (
            func.id
            if isinstance(func, ast.Name)
            else func.attr
            if isinstance(func, ast.Attribute)
            else ""
        )
        targets: list[ast.expr] = []
        if name == "open" and node.args:
            mode = next((word.value for word in node.keywords if word.arg == "mode"), None)
            mode = mode if mode is not None else node.args[1] if len(node.args) > 1 else None
            if (
                isinstance(mode, ast.Constant)
                and isinstance(mode.value, str)
                and any(char in mode.value for char in "wax+")
            ):
                targets.append(node.args[0])
        if name in {"write_text", "write_bytes", "unlink", "rename", "replace", "touch"} and (
            isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call) and func.value.args
        ):
            targets.append(func.value.args[0])
        elif name in {"unlink", "remove", "rename", "replace", "rmtree"}:
            targets.extend(node.args[: 2 if name in {"rename", "replace"} else 1])
        for target in targets:
            if isinstance(target, ast.Constant) and isinstance(target.value, str):
                yield target.value


def _directory_changes(command: Command) -> list[str]:
    """Directories a command runs in: ``env -C``, ``sudo -D``, and ``git -C`` chains."""

    argv = command.argv
    if not argv:
        return []
    name = program(argv[0])
    if name == "git":
        git = git_command(command)
        directory = ""
        for option, value in git.options if git else ():
            if option == "-C" and value:
                directory = os.path.join(directory, value) if directory else value
        return [directory] if directory else []
    if name not in {"env", "sudo"}:
        return []
    short = "C" if name == "env" else "D"
    values = (
        {"-u", "--unset", "-S", "--split-string", "-C", "--chdir"}
        if name == "env"
        else {
            "-u",
            "--user",
            "-g",
            "--group",
            "-C",
            "--close-from",
            "-p",
            "--prompt",
            "-h",
            "--host",
            "-r",
            "--role",
            "-t",
            "--type",
            "-U",
            "--other-user",
            "-T",
            "--command-timeout",
            "-R",
            "--chroot",
            "-D",
            "--chdir",
        }
    )
    directories: list[str] = []
    index = 1
    while index < len(argv):
        word = argv[index]
        if word == "--" or not word.startswith("-"):
            if name == "env" and "=" in word and word != "--":
                index += 1
                continue
            break
        following = argv[index + 1] if index + 1 < len(argv) else None
        if word == f"-{short}" or (word.startswith("--") and long_option(word, {"--chdir"})):
            option, separator, value = word.partition("=")
            if separator:
                directories.append(value)
            elif following is not None:
                directories.append(following)
                index += 1
        elif word.startswith(f"-{short}") and not word.startswith("--"):
            directories.append(word[2:])
        elif word in values:
            index += 1
        index += 1
    return directories


def _tool_targets(context: EvaluationContext) -> Iterable[str]:
    action = context.proposed_action
    name = context.tool_name or action.type.rsplit(":", 1)[-1]
    if not _WRITE_TOOL.search(name):
        return
    payload = action.input
    if isinstance(payload, Mapping) and str(payload.get("command", "")).lower() == "view":
        # ``str_replace_editor``-style tools multiplex a read-only view command.
        return
    yield from input_paths(payload)
    if isinstance(payload, Mapping):
        # Codex sends ``apply_patch`` text under ``command`` or ``input``.
        for key in ("patch", "patch_text", "input", "diff", "command"):
            patch = payload.get(key)
            if isinstance(patch, str):
                yield from _PATCH_HEADER.findall(patch)


def finding(reason: str, *, review: bool = False) -> DeterministicFinding:
    return DeterministicFinding(
        check="tamper_guard",
        triggered=True,
        severity="medium" if review else "high",
        reason_code=reason,
        blocking=not review,
    )


def _diff_truncated(context: EvaluationContext) -> bool:
    """A proposed diff that exceeded the deterministic bound was cut, hiding paths."""

    text = context.git_diff
    return (
        (context.proposed_diff or context.proposed_action.type == "observation")
        and len(text) >= MAX_DETERMINISTIC_DIFF_CHARS
        and TRUNCATION_MARKER in text
    )


def evaluate(
    context: EvaluationContext, config: ReflexConfig | None = None
) -> list[DeterministicFinding]:
    try:
        cwd, root = roots(context)
        home = Path.home()
        sources = set()
        if config is not None:
            if config._source_path is not None:
                sources.add(config._source_path)
            if config.session.track_secret_taint or config.session.pin_protected_files:
                database = Path(config.session.path).expanduser().absolute()
                sources.add(database)
                sources.update(
                    database.with_name(database.name + suffix)
                    for suffix in ("-wal", "-shm", "-journal")
                )
        sources.update(path.resolve() for path in tuple(sources))
        allowed = {
            absolute_path(path, root)
            for path in (config.local_checks.protected_path_allowlist if config is not None else ())
        }

        def state(name: str, base: Path) -> Literal["write", "unresolved"] | None:
            return _target_state(name, base, allowed, home, sources)

        directories = {cwd}
        unknown_directory = False
        unresolved = False
        for command in inspect(context.proposed_action).commands:
            if command.context != "local":
                continue  # writes on a remote host or in a container are not local files
            for directory in _directory_changes(command):
                if unresolved_word(directory):
                    unknown_directory = True
                    continue
                directories.update(absolute_path(directory, base) for base in tuple(directories))
            if len(directories) > _MAX_DIRECTORIES:
                return [finding("PROTECTED_PATH_UNRESOLVED")]
            for base in tuple(directories):
                # Each directory is judged on its own: one that cannot resolve a target
                # must not hide a protected write that another one can resolve.
                try:
                    for target in _targets(command, base, root):
                        result = state(target, base)
                        if result == "write":
                            return [finding("PROTECTED_PATH_WRITE")]
                        relative = not Path(expand_home(target)).is_absolute()
                        unresolved |= result == "unresolved" or (unknown_directory and relative)
                except _Unresolved:
                    unresolved = True
            if command.argv and program(command.argv[0]) in {"cd", "pushd"}:
                args = [arg for arg in command.argv[1:] if not arg.startswith("-")]
                if args and unresolved_word(args[0]):
                    unknown_directory = True
                elif args:
                    directories.update(absolute_path(args[0], base) for base in tuple(directories))
                    if len(directories) > _MAX_DIRECTORIES:
                        return [finding("PROTECTED_PATH_UNRESOLVED")]
        # Tool inputs and diff headers name literal paths; nothing expands them.
        if any(
            _protected_target(target, cwd, allowed, home, sources)
            for target in _tool_targets(context)
        ):
            return [finding("PROTECTED_PATH_WRITE")]
        if _diff_truncated(context):
            return [finding("PROTECTED_PATH_UNRESOLVED")]
        if any(
            _protected_target(path, root, allowed, home, sources)
            for change in proposed_changes(context)
            for path in change.paths
        ):
            return [finding("PROTECTED_PATH_WRITE")]
    except (OSError, RuntimeError, ValueError):
        return [finding("PROTECTED_PATH_UNRESOLVED")]
    if unresolved:
        return [finding("WRITE_TARGET_UNRESOLVED", review=True)]
    return []


def _target_state(
    name: str, base: Path, allowed: set[Path], home: Path, sources: set[Path]
) -> Literal["write", "unresolved"] | None:
    if unresolved_word(name):
        # A run-time expansion can name anything; a protected remainder (for
        # example ``$DIR/CLAUDE.md``) is still a protected write.
        probe = absolute_path(mask_expansions(name), base)
        return "write" if protected(probe, home) else "unresolved"
    return "write" if _protected_target(name, base, allowed, home, sources) else None


def _protected_target(
    name: str, base: Path, allowed: set[Path], home: Path, sources: set[Path]
) -> bool:
    path = absolute_path(name, base)
    resolved = path.resolve()
    if path in sources or resolved in sources:
        return path not in allowed or path != resolved
    if path in allowed and resolved == path:
        return False
    if protected(path, home) or protected(resolved, home):
        return True
    # Shell glob writes can include a protected basename or a control directory.
    if any(char in path.name for char in "*?["):
        candidates = [
            *(path.parent / value for value in CONTROL_NAMES),
            *(path.parent / value for value in HOME_FILES if path.parent == home),
            *(
                path.parent / filename
                for folder, filename in (value.split("/") for value in CONTROL_FILES)
                if path.parent.name == folder
            ),
        ]
        return any(
            fnmatch.fnmatchcase(str(candidate).casefold(), str(path).casefold())
            for candidate in candidates
        )
    return False
