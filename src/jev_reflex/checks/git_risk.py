"""Deterministic checks for destructive Git and executable configuration."""

from __future__ import annotations

import re

from ..models import DeterministicFinding, EvaluationContext
from .common import GitCommand, git_command
from .shell import inspect, program

_EXECUTION_KEYS = {
    "core.fsmonitor",
    "core.sshcommand",
    "core.hookspath",
    "core.pager",
    "core.editor",
    "sequence.editor",
    "diff.external",
    "credential.helper",
    "core.gitproxy",
}
_EXECUTION_ENV = {
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
}


def executable_key(key: str) -> bool:
    key = key.lower()
    return (
        key in _EXECUTION_KEYS
        or key.startswith(("alias.", "pager.", "include.", "includeif."))
        or bool(
            re.fullmatch(
                r"(?:filter\..*\.(?:process|clean|smudge)|diff\..*\.(?:command|textconv)|merge\..*\.driver)",
                key,
            )
        )
    )


def _configure_execution(git: GitCommand) -> bool:
    for option, argument in git.options:
        key, _, value = argument.partition("=")
        if option in {"-c", "--config-env"} and executable_key(key):
            if option == "-c" and key.lower() == "core.fsmonitor" and value.lower() == "false":
                continue
            return True
    if git.subcommand != "config":
        return False
    args = git.args[1:]
    if set(args) & {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l"}:
        return False
    names = [arg for arg in args if not arg.startswith("-")]
    if names and names[0] in {"get", "list"}:
        return False
    return any(executable_key(arg) for arg in names) and (
        len(names) > 1
        or bool(set(args) & {"--unset", "--unset-all", "--remove-section", "--rename-section"})
    )


def _finding(reason: str, *, review: bool = False) -> DeterministicFinding:
    return DeterministicFinding(
        check="git_risk",
        triggered=True,
        severity="medium" if review else "high",
        reason_code=reason,
        blocking=not review,
    )


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    safe_git = False
    execution_env = False
    amend = False
    for command in inspect(context.proposed_action).commands:
        environment = command.assignments
        if command.argv and program(command.argv[0]) == "env":
            environment += command.argv[1:]
        execution_env |= any(
            item.partition("=")[0] in _EXECUTION_ENV and "=" in item for item in environment
        )
        git = git_command(command)
        if git is None:
            continue
        if execution_env or _configure_execution(git):
            return [_finding("GIT_EXECUTION_CONFIG")]
        flags = git.flags
        name = git.subcommand
        if name == "reset" and "--hard" in flags:
            return [_finding("GIT_HARD_RESET")]
        if name == "clean" and flags & {"-f", "--force"}:
            return [_finding("GIT_CLEAN_FORCE")]
        if name == "push" and (
            flags & {"-f", "--force", "--force-with-lease", "--force-if-includes"}
            or any(arg.startswith("+") for arg in git.args[1:])
        ):
            return [_finding("FORCE_PUSH")]
        if name == "branch" and (
            "-D" in flags or (flags & {"-d", "--delete"} and flags & {"-f", "--force"})
        ):
            return [_finding("BRANCH_DELETE_FORCE")]
        if name in {"filter-repo", "filter-branch"} or (
            name == "rebase" and flags & {"-i", "--interactive"}
        ):
            return [_finding("HISTORY_REWRITE")]
        amend |= name == "commit" and "--amend" in flags
        safe_git |= name in {"status", "diff"}
    if amend:
        return [_finding("COMMIT_AMEND", review=True)]
    return [
        DeterministicFinding(
            check="git_risk",
            triggered=False,
            severity="low",
            reason_code="KNOWN_SAFE_GIT" if safe_git else "CLEAR",
        )
    ]
