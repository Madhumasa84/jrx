"""Common path and Git argument helpers for deterministic checks."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from ..models import EvaluationContext
from .diff import file_changes
from .shell import Command, inspect, program

# Global options that take a value, either as the next word or after ``=``.
# ``-C`` and ``-c`` are only recognized as separate words by Git; attached forms
# are still parsed below because over-matching is the safe direction.
_GIT_VALUES = {
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--super-prefix",
    "--attr-source",
    "--shallow-file",
}
# Global options whose value is only accepted after ``=``.
_GIT_EQUALS_VALUES = {"--exec-path", "--list-cmds"}
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
    "--no-advice",
    "--exec-path",
    "--html-path",
    "--man-path",
    "--info-path",
}
# Git rewrites these legacy flag spellings into the ``help``/``version`` commands.
_GIT_COMMAND_FLAGS = {"-h", "--help", "-v", "--version"}
# Long subcommand options that deterministic rules inspect. Git's parse-options
# accepts any unambiguous prefix of a long option, so each abbreviation is mapped
# to every option it could name (an ambiguous prefix makes Git fail, so the extra
# matches only ever over-approximate).
GIT_LONG_OPTIONS = frozenset(
    {
        "--hard",
        "--force",
        "--force-with-lease",
        "--force-if-includes",
        "--mirror",
        "--delete",
        "--prune",
        "--interactive",
        "--amend",
        "--exec",
        "--upload-pack",
        "--receive-pack",
        "--template",
        "--config",
        "--extcmd",
    }
)
_HOME_VARIABLE = re.compile(r"\$(?:HOME\b|\{HOME\})")
# A remaining parameter expansion, command substitution, or arithmetic expansion.
_UNRESOLVED_EXPANSION = re.compile(r"\$(?:[A-Za-z_{(]|[0-9@*#?$!-])|`")
_EXPANSION_SPAN = re.compile(
    r"\$\{[^}]*\}?|\$\([^)]*\)?|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?$!-]|`[^`]*`?|^~[^/]*"
)


def roots(context: EvaluationContext) -> tuple[Path, Path]:
    directory = Path(context.working_directory or context.repository_root or ".").resolve()
    return directory, Path(context.repository_root or directory).resolve()


def command_text(context: EvaluationContext) -> str:
    return " ".join(
        word for command in inspect(context.proposed_action).commands for word in command.argv
    ).lower()


def expand_home(word: str) -> str:
    """Expand the home-directory forms a shell resolves identically: ``~``, ``$HOME``."""

    if "~" not in word and "$" not in word:
        return word
    home = str(Path.home())
    if word == "~" or word.startswith("~/"):
        word = home + word[1:]
    return _HOME_VARIABLE.sub(lambda _: home, word)


def unresolved_word(word: str) -> bool:
    """Whether a word still holds an expansion the shell resolves at run time.

    ``~``, ``$HOME`` and ``${HOME}`` are expanded first; ``~user`` counts as
    resolved only when the local account database knows that user.
    """

    word = expand_home(word)
    if _UNRESOLVED_EXPANSION.search(word):
        return True
    return word.startswith("~") and os.path.expanduser(word) == word


def mask_expansions(word: str, mask: str = "jrx-unresolved") -> str:
    """Replace each run-time expansion left in a word with a fixed path component."""

    return _EXPANSION_SPAN.sub(lambda _: mask, expand_home(word))


def python_inline_code(argv: Sequence[str]) -> str | None:
    """The ``-c`` program of a CPython command line, including option clusters."""

    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--" or not arg.startswith("-") or arg == "-":
            return None
        if arg in {"-W", "-X", "--check-hash-based-pycs"}:
            index += 2
            continue
        if arg.startswith("--"):
            index += 1
            continue
        cluster = arg[1:]
        for position, letter in enumerate(cluster):
            if letter == "c":
                rest = cluster[position + 1 :]
                if rest:
                    return rest
                return argv[index + 1] if index + 1 < len(argv) else None
            if letter == "m":
                return None
            if letter in {"W", "X"}:
                if position == len(cluster) - 1:
                    index += 1
                break
        index += 1
    return None


def absolute_path(path: str, base: Path) -> Path:
    return Path(os.path.abspath(base / Path(expand_home(path)).expanduser()))


def long_option(word: str, options: Iterable[str]) -> set[str]:
    """Long options that ``word`` names exactly or as a (possibly ambiguous) prefix."""

    name = word.split("=", 1)[0]
    if len(name) < 3 or not name.startswith("--"):
        return set()
    return {option for option in options if option.startswith(name)}


def inplace_files(name: str, args: Sequence[str]) -> list[str] | None:
    """File operands an in-place ``sed``/``perl``/``ruby`` edit rewrites, else ``None``.

    Script arguments (``-e``/``-f`` values, or the first operand when no script
    option is given) are excluded so they are never mistaken for paths.
    """

    if name == "sed":
        # Options taking a value (attached or next word); options whose optional
        # value can only be attached (``-i[SUFFIX]``).
        separate, attached, scripts = "efl", "i", "ef"
        long_script, long_value = {"--expression", "--file"}, {"--line-length"}
    elif name == "perl":
        separate, attached, scripts = "eEI", "il0CdDxMmF", "eE"
        long_script, long_value = set(), set()
    elif name == "ruby":
        separate, attached, scripts = "eIrCEF", "ilx0KTW", "e"
        long_script, long_value = set(), set()
    else:
        return None
    in_place = script_given = literal = False
    expect_value = False
    operands: list[str] = []
    for arg in args:
        if expect_value:
            expect_value = False
            continue
        if literal or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
            continue
        if arg == "--":
            literal = True
            continue
        if arg.startswith("--"):
            option, separator, _ = arg.partition("=")
            if name == "sed" and long_option(option, {"--in-place"}):
                in_place = True
            if long_option(option, long_script):
                script_given = True
                expect_value = not separator
            elif long_option(option, long_value):
                expect_value = not separator
            continue
        cluster = arg[1:]
        for index, letter in enumerate(cluster):
            if letter == "i":
                in_place = True
                break
            if letter in separate:
                script_given |= letter in scripts
                expect_value = index == len(cluster) - 1
                break
            if letter in attached:
                break
    if not in_place:
        return None
    return operands if script_given else operands[1:]


@dataclass(frozen=True)
class GitCommand:
    options: tuple[tuple[str, str], ...]
    args: tuple[str, ...]
    unknown: tuple[str, ...] = ()

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
                flags.update(long_option(arg, GIT_LONG_OPTIONS))
            elif re.fullmatch(r"-[a-zA-Z]+", arg):
                flags.update("-" + letter for letter in arg[1:])
        return flags

    def config(self, key: str) -> str | None:
        """The last ``-c`` value for a configuration key (section and key case-folded)."""

        value = None
        for option, argument in self.options:
            name, separator, setting = argument.partition("=")
            if option == "-c" and name.lower() == key.lower():
                value = setting if separator else "true"
        return value


def git_command(command: Command) -> GitCommand | None:
    argv = command.argv
    if not argv or program(argv[0]) != "git":
        return None
    options = []
    unknown = []
    index = 1
    while index < len(argv):
        arg = argv[index]
        if not arg.startswith("-") or arg == "-" or arg in _GIT_COMMAND_FLAGS:
            break
        name, separator, value = arg.partition("=")
        if arg in _GIT_VALUES:
            if index + 1 == len(argv):
                options.append((arg, ""))
                index += 1
                break
            options.append((arg, argv[index + 1]))
            index += 2
        elif separator and arg.startswith("--") and name in _GIT_VALUES | _GIT_EQUALS_VALUES:
            options.append((name, value))
            index += 1
        elif len(arg) > 2 and arg.startswith(("-c", "-C")):
            options.append((arg[:2], arg[2:]))
            index += 1
        elif arg in _GIT_SWITCHES:
            index += 1
        else:
            # Git rejects unknown global options, but a newer Git may accept one
            # this parser does not know. Keep scanning (assuming a switch) so the
            # subcommand rules still apply, and let callers fail closed on it.
            unknown.append(arg)
            index += 1
    return GitCommand(tuple(options), argv[index:], tuple(unknown))


class WriteDestinations(NamedTuple):
    """Where an archive extraction or ``git apply`` writes.

    ``paths`` are shell words (relative to the command's directory unless absolute) or, for
    ``git apply``, absolute patch targets. ``unresolved`` means the files written under them
    are not established, for example archive members, which this check does not read.
    """

    paths: tuple[str, ...]
    unresolved: bool


_TAR_VALUE_LETTERS = frozenset("fCbKNTXgFHLV")
_UNZIP_READ_ONLY = frozenset("lvtpzcZ")
_GIT_APPLY_READ_ONLY = frozenset({"--check", "--stat", "--numstat", "--summary"})
_MAX_PATCH_BYTES = 8_000_000


def write_destinations(command: Command, base: Path, root: Path) -> WriteDestinations | None:
    """Destinations of ``tar``/``unzip`` extraction or ``git apply``; None for anything else."""
    if not command.argv:
        return None
    name, args = program(command.argv[0]), command.argv[1:]
    if name in {"tar", "gtar", "bsdtar"}:
        return _tar_destinations(args)
    if name == "unzip":
        return _unzip_destinations(args)
    git = git_command(command)
    if git is not None and git.subcommand == "apply":
        return _git_apply_destinations(command, git.args[1:], base, root)
    return None


def _chdir(directory: str, value: str) -> str:
    # Each tar -C is relative to the previous one.
    return value if not directory or os.path.isabs(expand_home(value)) else f"{directory}/{value}"


def _tar_destinations(args: Sequence[str]) -> WriteDestinations | None:
    extracting = unknown_directory = False
    directory = ""
    destinations: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        name, equals, value = arg.partition("=")
        if index == 0 and arg and not arg.startswith("-"):
            # Traditional bundled options ("xzf"); a bundled C takes a later operand.
            extracting = "x" in arg
            unknown_directory = "C" in arg
        elif arg == "--":
            break
        elif name in {"--extract", "--get"}:
            extracting = True
        elif name == "--directory":
            if not equals:
                index += 1
                value = args[index] if index < len(args) else ""
            directory = _chdir(directory, value)
            destinations.append(directory)
        elif arg.startswith("-") and not arg.startswith("--"):
            for position, letter in enumerate(arg[1:], 1):
                if letter == "x":
                    extracting = True
                if letter in _TAR_VALUE_LETTERS:
                    value = arg[position + 1 :]
                    if not value:
                        index += 1
                        value = args[index] if index < len(args) else ""
                    if letter == "C":
                        directory = _chdir(directory, value)
                        destinations.append(directory)
                    break
        index += 1
    if not extracting:
        return None
    paths = tuple(destinations) or (".",)
    return WriteDestinations(paths, True) if not unknown_directory else WriteDestinations((), True)


def _unzip_destinations(args: Sequence[str]) -> WriteDestinations | None:
    destination = "."
    seen_archive = False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "-d" or (arg.startswith("-d") and len(arg) > 2):
            if arg == "-d":
                index += 1
            destination = arg[2:] or (args[index] if index < len(args) else "")
        elif arg.startswith("-") and not seen_archive:
            letters = arg[1:]
            if _UNZIP_READ_ONLY.intersection(letters):
                return None  # list, test, comment or pipe to stdout
            if letters.endswith("P"):
                index += 1  # password value
        elif not arg.startswith("-"):
            seen_archive = True
        index += 1
    return WriteDestinations((destination,), True)


def _read_patch(path: Path) -> str | None:
    try:
        details = path.stat()
        if not stat.S_ISREG(details.st_mode) or details.st_size > _MAX_PATCH_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _git_apply_destinations(
    command: Command, args: Sequence[str], base: Path, root: Path
) -> WriteDestinations | None:
    names = {arg.split("=", 1)[0] for arg in args}
    if names & _GIT_APPLY_READ_ONLY and "--apply" not in names:
        return None
    prefix = ""
    strip = 1
    patches: list[str] = []
    options = True
    index = 0
    while index < len(args):
        arg = args[index]
        if options and arg == "--":
            options = False
        elif options and arg.split("=", 1)[0] == "--directory":
            prefix = arg.partition("=")[2]
            if "=" not in arg:
                index += 1
                prefix = args[index] if index < len(args) else ""
        elif options and re.fullmatch(r"-p\d*", arg):
            if arg == "-p":
                index += 1
                arg = "-p" + (args[index] if index < len(args) else "")
            strip = int(arg[2:]) if arg[2:].isdecimal() else -1
        elif options and arg.startswith("-") and arg != "-":
            pass
        else:
            patches.append(arg)
        index += 1
    if not patches or patches == ["-"]:
        # The patch arrives on stdin; only a redirected file can be read here.
        patches = [target for operator, target in command.redirects if operator == "<"]
        if not patches:
            return WriteDestinations((), True)
    # The diff parser strips git's a/ and b/ prefixes, which matches only -p1.
    unresolved = strip != 1 or unresolved_word(prefix)
    targets: list[str] = []
    for patch in patches:
        text = None if unresolved_word(patch) else _read_patch(absolute_path(patch, base))
        if text is None:
            unresolved = True
            continue
        for change in file_changes(text):
            for path in change.paths:
                # git apply resolves patch paths from the top of the working tree.
                targets.append(str(absolute_path(os.path.join(prefix, path), root)))
    return WriteDestinations(tuple(targets), unresolved)
