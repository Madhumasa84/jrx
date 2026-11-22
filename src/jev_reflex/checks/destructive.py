"""Deterministic recognition of plainly destructive actions."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import DeterministicFinding, EvaluationContext
from .common import git_command, roots
from .shell import Command, inspect, program

_GENERATED_DIRECTORIES = frozenset(
    {
        "dist",
        "node_modules",
        "coverage-html",
        ".pytest_cache",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".next",
        ".turbo",
    }
)
_SAFE_RM_OPTIONS = frozenset(
    {"--force", "--recursive", "--interactive", "--verbose", "--one-file-system", "--preserve-root"}
)
_INTERPRETER_SIDE_EFFECT_RE = re.compile(
    r"\b(?:os\.(?:system|popen|remove|unlink|rmdir)|"
    r"shutil\.(?:rmtree|move)|(?:pathlib\.)?path\.(?:unlink|rmdir)|"
    r"subprocess\.(?:run|popen|call|check_call|check_output)|"
    r"fs\.(?:rm|rmSync|rmdir|rmdirSync)|"
    r"child_process\.(?:exec|execFile|spawn)|remove-item)\b",
    re.IGNORECASE,
)


def _trigger(reason_code: str) -> DeterministicFinding:
    return DeterministicFinding(
        check="known_destructive",
        triggered=True,
        severity="high",
        reason_code=reason_code,
        blocking=True,
    )


def _rm_options(argv: tuple[str, ...]) -> tuple[list[str], list[str]]:
    options, targets = [], []
    literal = False
    for item in argv[1:]:
        if not literal and item == "--":
            literal = True
        elif not literal and item.startswith("-") and item != "-":
            options.append(item)
        else:
            targets.append(item)
    return options, targets


def _generated_target(target: str, directory: Path, root: Path) -> bool:
    path = Path(target)
    if not path.parts or path.name not in _GENERATED_DIRECTORIES:
        return False
    if path.is_absolute() or {"..", ".git"}.intersection(path.parts):
        return False
    if any(char in target for char in "*?[{}~$"):
        return False
    candidate = directory / path
    if not candidate.is_relative_to(root):
        return False
    # Symlinks make a name-based cleanup exception unsafe.
    return candidate.resolve() == candidate


def _safe_recursive_cleanup(
    context: EvaluationContext, command: Command, options: list[str], targets: list[str]
) -> bool:
    if (
        command.argv[0] not in {"rm", "/bin/rm", "/usr/bin/rm"}
        or command.indirect
        or command.redirects
        or not targets
    ):
        return False
    if any(opt not in _SAFE_RM_OPTIONS and not re.fullmatch(r"-[rRfiIv]+", opt) for opt in options):
        return False
    try:
        directory, root = roots(context)
        return all(_generated_target(target, directory, root) for target in targets)
    except (ValueError, RuntimeError, OSError):
        return False


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    plan = inspect(context.proposed_action)
    for command in plan.commands:
        if not command.argv:
            continue
        name = program(command.argv[0])
        args = command.argv[1:]
        if name == "rm":
            options, targets = _rm_options(command.argv)
            recursive = any(
                opt == "--recursive" or (not opt.startswith("--") and "r" in opt.lower())
                for opt in options
            )
            if recursive and (
                len(plan.commands) != 1
                or not _safe_recursive_cleanup(context, command, options, targets)
            ):
                return [_trigger("RECURSIVE_DELETE")]
        if name.startswith(("python", "node")) and _INTERPRETER_SIDE_EFFECT_RE.search(
            " ".join(args)
        ):
            return [_trigger("INTERPRETER_SIDE_EFFECT")]
        if name == "git":
            git = git_command(command)
            if git and git.subcommand == "reset" and "--hard" in git.flags:
                return [_trigger("GIT_HARD_RESET")]
            if git and git.subcommand == "clean" and git.flags & {"-f", "--force"}:
                return [_trigger("GIT_CLEAN_FORCE")]
        if name in {"psql", "mysql", "sqlite3", "sqlcmd", "duckdb"} and re.search(
            r"\b(?:drop\s+(?:database|table)|truncate\s+table)\b", " ".join(args), re.I
        ):
            return [_trigger("DATABASE_DESTRUCTIVE")]
        if (name, args[:1]) in {("terraform", ("destroy",)), ("kubectl", ("delete",))}:
            return [_trigger("INFRASTRUCTURE_DELETE")]
        if name == "shred" or (name == "docker" and args[:2] == ("system", "prune")):
            return [_trigger("RESOURCE_PRUNE")]
    return [
        DeterministicFinding(
            check="known_destructive", triggered=False, severity="low", reason_code="CLEAR"
        )
    ]
