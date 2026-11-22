"""Protect explicit writes to agent instructions, hooks, and policy inputs."""

from __future__ import annotations

import ast
import fnmatch
import re
from collections.abc import Iterable, Mapping
from pathlib import Path

from ..config import ReflexConfig
from ..models import DeterministicFinding, EvaluationContext
from .common import absolute_path, git_command, roots
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
_WRITE_TOOL = re.compile(
    r"(?:^|[._:])(?:edit|write|replace|append|apply_patch|delete|remove|move|rename|create|update)(?:$|_)",
    re.I,
)


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


def _targets(command: Command) -> Iterable[str]:
    for operator, target in command.redirects:
        if operator in _OUTPUT:
            yield target
    if not command.argv:
        return
    name, args = program(command.argv[0]), command.argv[1:]
    operands = [arg for arg in args if not arg.startswith("-")]
    if name in WRITE_COMMANDS or (
        name in {"sed", "perl", "ruby"}
        and any(
            arg.startswith("--in-place") or re.fullmatch(r"-[A-Za-z]*i[A-Za-z]*", arg or "")
            for arg in args
        )
    ):
        yield from operands
    elif name in {"cp", "install", "ln", "rsync", "scp"} and operands:
        yield operands[-1]
        for index, arg in enumerate(args):
            if arg in {"-t", "--target-directory"} and index + 1 < len(args):
                yield args[index + 1]
            elif arg.startswith("--target-directory="):
                yield arg.split("=", 1)[1]
    elif name in {"curl", "wget", "dd"}:
        for index, arg in enumerate(args):
            flag, sep, value = arg.partition("=")
            if flag in {"--output", "--output-document", "of"} and sep:
                yield value
            elif arg in {"-o", "-O", "--output", "--output-document"} and index + 1 < len(args):
                yield args[index + 1]
            elif len(arg) > 2 and arg.startswith(("-o", "-O")):
                yield arg[2:]
    elif name == "git" and (git := git_command(command)):
        if git.subcommand in {"rm", "mv", "restore", "checkout"}:
            yield from git.args[1:]
    elif name == "find" and "-delete" in args:
        yield from operands
    elif is_python(name) and (code := inline_code(command)):
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


def _tool_targets(context: EvaluationContext) -> Iterable[str]:
    action = context.proposed_action
    if action.command or action.argv:
        return
    name = context.tool_name or action.type.rsplit(":", 1)[-1]
    if not _WRITE_TOOL.search(name):
        return
    yield from input_paths(action.input)
    if isinstance(action.input, Mapping):
        for key in ("patch", "patch_text", "input", "diff"):
            patch = action.input.get(key)
            if isinstance(patch, str):
                yield from _PATCH_HEADER.findall(patch)


def finding(reason: str) -> DeterministicFinding:
    return DeterministicFinding(
        check="tamper_guard", triggered=True, severity="high", reason_code=reason, blocking=True
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
        directories = {cwd}
        for command in inspect(context.proposed_action).commands:
            for base in directories:
                if any(
                    _protected_target(target, base, allowed, home, sources)
                    for target in _targets(command)
                ):
                    return [finding("PROTECTED_PATH_WRITE")]
            if command.argv and program(command.argv[0]) in {"cd", "pushd"}:
                args = [arg for arg in command.argv[1:] if not arg.startswith("-")]
                if args:
                    directories.update(absolute_path(args[0], base) for base in tuple(directories))
                    if len(directories) > 16:
                        return [finding("PROTECTED_PATH_UNRESOLVED")]
        if any(
            _protected_target(target, cwd, allowed, home, sources)
            for target in _tool_targets(context)
        ):
            return [finding("PROTECTED_PATH_WRITE")]
        if any(
            _protected_target(path, root, allowed, home, sources)
            for change in proposed_changes(context)
            for path in change.paths
        ):
            return [finding("PROTECTED_PATH_WRITE")]
    except (OSError, RuntimeError, ValueError):
        return [finding("PROTECTED_PATH_UNRESOLVED")]
    return []


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
