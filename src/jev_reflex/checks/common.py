"""Common path and Git argument helpers for deterministic checks."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from ..models import EvaluationContext
from .shell import Command, inspect, program

_GIT_VALUES = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
_GIT_SWITCHES = {
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


def roots(context: EvaluationContext) -> tuple[Path, Path]:
    directory = Path(context.working_directory or context.repository_root or ".").resolve()
    return directory, Path(context.repository_root or directory).resolve()


def command_text(context: EvaluationContext) -> str:
    return " ".join(
        word for command in inspect(context.proposed_action).commands for word in command.argv
    ).lower()


def absolute_path(path: str, base: Path) -> Path:
    return Path(os.path.abspath(base / Path(path).expanduser()))


@dataclass(frozen=True)
class GitCommand:
    options: tuple[tuple[str, str], ...]
    args: tuple[str, ...]

    @property
    def subcommand(self) -> str:
        return self.args[0] if self.args else ""

    @property
    def flags(self) -> set[str]:
        flags: set[str] = set()
        for arg in self.args[1:]:
            if arg == "--":
                break
            if arg.startswith("--"):
                flags.add(arg.split("=", 1)[0])
            elif re.fullmatch(r"-[a-zA-Z]+", arg):
                flags.update("-" + letter for letter in arg[1:])
        return flags


def git_command(command: Command) -> GitCommand | None:
    argv = command.argv
    if not argv or program(argv[0]) != "git":
        return None
    options = []
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg in _GIT_VALUES:
            if index + 1 == len(argv):
                break
            options.append((arg, argv[index + 1]))
            index += 2
        elif arg.partition("=")[0] in _GIT_VALUES and arg.startswith("--"):
            name, _, value = arg.partition("=")
            options.append((name, value))
            index += 1
        elif len(arg) > 2 and arg.startswith(("-c", "-C")):
            options.append((arg[:2], arg[2:]))
            index += 1
        elif arg in _GIT_SWITCHES:
            index += 1
        else:
            break
    return GitCommand(tuple(options), argv[index:])
