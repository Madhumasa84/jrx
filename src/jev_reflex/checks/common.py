"""Shared, shell-free helpers for deterministic checks."""

from __future__ import annotations

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
