"""Shared, shell-free helpers for deterministic checks."""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable

from ..models import EvaluationContext


def action_argv(context: EvaluationContext) -> list[str]:
    """Return action arguments without evaluating shell syntax."""

    action = context.proposed_action
    if action.argv:
        return [str(item) for item in action.argv]
    if not action.command:
        return []
    try:
        return shlex.split(action.command)
    except ValueError:
        # The execution wrapper rejects invalid quoting. Checks still receive a stable
        # token so they never need to invoke a shell to inspect the action.
        return action.command.split()


def command_text(context: EvaluationContext) -> str:
    return " ".join(action_argv(context)).lower()


def first_command(argv: list[str]) -> str:
    for item in argv:
        if not item.startswith("-"):
            return item.lower()
    return ""


def iter_nonflag_args(argv: list[str], *, skip_values_for: Iterable[str] = ()) -> list[str]:
    """Return probable path/target arguments while skipping option values."""

    skip = {name.lower() for name in skip_values_for}
    result: list[str] = []
    previous_flag = ""
    for item in argv:
        lowered = item.lower()
        if previous_flag:
            previous_flag = ""
            continue
        if lowered in skip:
            previous_flag = lowered
            continue
        if item.startswith("-"):
            continue
        result.append(item)
    return result


# Git global options precede the subcommand. Keep their values out of the
# subcommand match, including quoted directory and configuration values.
_GIT_OPTION_VALUE = r"(?:\"[^\"]*\"|'[^']*'|[^\s]+)"
GIT_COMMAND_PREFIX = (
    r"\bgit(?:\s+(?:"
    r"(?:-[cC]|--git-dir|--work-tree|--namespace|--config-env)\s+"
    + _GIT_OPTION_VALUE
    + r"|-[cC][^\s]+"
    r"|--(?:git-dir|work-tree|namespace|config-env)=[^\s]+"
    r"|--(?:no-pager|paginate|bare|no-replace-objects|literal-pathspecs|"
    r"glob-pathspecs|noglob-pathspecs|icase-pathspecs|no-optional-locks|no-lazy-fetch)"
    r"|-[pP]))*\s+"
)


def git_command_text(context: EvaluationContext) -> str:
    """Remove Git global options while their argv boundaries are still available."""
    argv = action_argv(context)
    result: list[str] = []
    value_options = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
    switches = {
        "-p",
        "-P",
        "--paginate",
        "--no-pager",
        "--bare",
        "--no-replace-objects",
        "--literal-pathspecs",
        "--glob-pathspecs",
        "--noglob-pathspecs",
        "--icase-pathspecs",
        "--no-optional-locks",
        "--no-lazy-fetch",
    }
    index = 0
    while index < len(argv):
        token = argv[index]
        index += 1
        if token.replace("\\", "/").rsplit("/", 1)[-1] != "git":
            result.append(token)
            continue
        result.append("git")
        while index < len(argv):
            option = argv[index]
            if option in value_options:
                index += 2
            elif (
                option in switches
                or any(
                    option.startswith(flag + "=") for flag in value_options if flag.startswith("--")
                )
                or (option.startswith(("-C", "-c")) and len(option) > 2)
            ):
                index += 1
            else:
                break
    return " ".join(result)


def git_option_sets(context: EvaluationContext, subcommand: str) -> list[set[str]]:
    """Recognize separate and combined options, stopping at Git's ``--`` marker."""
    options = []
    pattern = GIT_COMMAND_PREFIX + re.escape(subcommand) + r"\b([^\n;&|]*)"
    for match in re.finditer(pattern, git_command_text(context)):
        try:
            arguments = shlex.split(match.group(1))
        except ValueError:
            arguments = match.group(1).split()
        flags: set[str] = set()
        for argument in arguments:
            if argument == "--":
                break
            if argument.startswith("--"):
                flags.add(argument.split("=", 1)[0])
            elif re.fullmatch(r"-[a-zA-Z]+", argument):
                flags.update("-" + letter for letter in argument[1:])
        options.append(flags)
    return options
