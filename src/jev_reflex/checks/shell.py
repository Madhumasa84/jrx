"""Bounded POSIX shell inspection. No expansion, subprocesses, or evaluation."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from ..models import ProposedAction

SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "fish", "ash"})
WRAPPERS = frozenset(
    {
        "busybox",
        "command",
        "doas",
        "env",
        "exec",
        "nice",
        "nohup",
        "setsid",
        "sudo",
        "timeout",
        "toybox",
    }
)
_TOKEN = re.compile(
    r"""(?:'(?:[^']*)'|"(?:\\[\s\S]|[^"\\])*"|\\[\s\S]|[^\s'"\\;&|()<>])+"""
    r"""|&>>|&>|&&|\|\||\|&|<<<|<<-|<<|>>|<>|>&|<&|>\||[\n;&|()<>]|[^ \t\r]"""
)
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SINGLE_OR_DOUBLE_QUOTE = re.compile(r"""'(?:[^']*)'|"(?:\\[\s\S]|[^"\\])*"|\\[\s\S]""")
_SUBSTITUTION = re.compile(r"(?<!\\)(?:\$\((?!\()|`)")
_VARIABLE = re.compile(r"\$(?:[A-Za-z_{@*?!0-9$#-])")
_IFS = re.compile(r"\$(?:\{IFS\}|IFS\b)")
_SEPARATORS = frozenset({";", "&&", "||", "|", "|&", "&", "(", ")", "\n"})
_REDIRECTIONS = frozenset({">", ">>", ">|", "&>", "&>>", "<", "<<<", "<<", "<<-", "<>", ">&", "<&"})
_RESERVED = frozenset(
    {"{", "}", "if", "then", "elif", "else", "fi", "do", "done", "while", "until", "!"}
)
_MAX_DEPTH = 8
_MAX_COMMANDS = 256


def program(word: str) -> str:
    return word.rsplit("/", 1)[-1].lower()


def _unquoted_for_expansion(raw: str) -> str:
    return _SINGLE_OR_DOUBLE_QUOTE.sub(
        lambda match: match[0] if match[0].startswith('"') else "", raw
    )


@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    redirects: tuple[tuple[str, str], ...] = ()
    piped: bool = False
    indirect: bool = False
    assignments: tuple[str, ...] = ()
    process_input: bool = False


@dataclass(frozen=True)
class ShellPlan:
    commands: tuple[Command, ...]
    opaque: bool = False


def _lex(source: str) -> tuple[list[Command], bool]:
    source = source.replace("\\\n", "")
    chunks: list[Command] = []
    words: list[str] = []
    redirects: list[tuple[str, str]] = []
    assignments: list[str] = []
    redirect = ""
    piped = False
    opaque = False
    end = 0
    comment_end = 0
    for match in _TOKEN.finditer(source):
        if match.start() < comment_end:
            continue
        raw = match[0]
        adjacent = end == match.start()
        end = match.end()
        if raw.startswith("#"):
            newline = source.find("\n", end)
            if newline < 0:
                break
            comment_end = newline
            continue
        if raw in _SEPARATORS:
            if raw == "(" and (
                redirect
                or (
                    adjacent
                    and (
                        (words and words[-1].endswith("$"))
                        or (assignments and assignments[-1].endswith("$"))
                    )
                )
            ):
                opaque = True
            if words or redirects or assignments:
                chunks.append(
                    Command(
                        tuple(words),
                        tuple(redirects),
                        piped,
                        assignments=tuple(assignments),
                        process_input=raw == "(" and adjacent and redirect == "<",
                    )
                )
            words, redirects, assignments = [], [], []
            redirect = ""
            piped = raw in {"|", "|&"}
            continue
        if raw in _REDIRECTIONS:
            if redirect or raw in {"<<", "<<-"}:
                opaque = True
            if adjacent and words and words[-1].isdigit():
                words.pop()
            redirect = raw
            continue
        try:
            parts = shlex.split(raw, comments=False)
        except ValueError:
            opaque = True
            continue
        if len(parts) != 1:
            opaque = True
            continue
        word = parts[0]
        expanded = _unquoted_for_expansion(raw)
        if _SUBSTITUTION.search(expanded) or ("$'" in raw and "$" in expanded):
            opaque = True
        if redirect:
            redirects.append((redirect, word))
            opaque |= bool(_VARIABLE.search(expanded))
            redirect = ""
        elif not words and raw in _RESERVED:
            continue
        elif not words and _ASSIGNMENT.match(raw):
            assignments.append(word)
        else:
            if (not words and _VARIABLE.search(expanded)) or _IFS.search(expanded):
                opaque = True
            words.append(word)
    if words or redirects or assignments:
        chunks.append(
            Command(tuple(words), tuple(redirects), piped, assignments=tuple(assignments))
        )
    return chunks, opaque or bool(redirect)


_WRAPPER_PARAMETERS = {
    "env": {"-u", "--unset", "-C", "--chdir"},
    "sudo": {"-u", "--user", "-g", "--group", "-C", "--close-from", "-p", "--prompt"},
    "doas": {"-u", "-C"},
    "exec": {"-a"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-k", "--kill-after", "-s", "--signal"},
    "setsid": set(),
}


def _wrapper_target(argv: tuple[str, ...]) -> tuple[str, ...]:
    name = program(argv[0])
    if name == "command" and any(arg in {"-v", "-V"} for arg in argv[1:]):
        return ()
    index = 1
    while index < len(argv):
        word = argv[index]
        if word == "--":
            index += 1
            break
        if word in _WRAPPER_PARAMETERS.get(name, set()):
            index += 2
        elif word.startswith("-") or _ASSIGNMENT.match(word):
            index += 1
        else:
            break
    return argv[index + (name == "timeout") :]


def shell_script(argv: tuple[str, ...]) -> str | None:
    for index, flag in enumerate(argv[1:-1], 1):
        if flag == "--" or not flag.startswith("-"):
            break
        if not flag.startswith("--") and "c" in flag[1:]:
            return argv[index + 1]
    return None


def xargs_target(argv: tuple[str, ...]) -> tuple[str, ...]:
    index = 1
    value_options = {
        "-a",
        "--arg-file",
        "-d",
        "--delimiter",
        "-E",
        "-I",
        "--replace",
        "-L",
        "--max-lines",
        "-n",
        "--max-args",
        "-P",
        "--max-procs",
        "-s",
        "--max-chars",
    }
    while index < len(argv):
        word = argv[index]
        if word == "--":
            index += 1
            break
        if not word.startswith("-"):
            break
        index += 2 if word in value_options else 1
    return argv[index:]


def inspect(action: ProposedAction) -> ShellPlan:
    """Inspect literal argv or conservative shell segments and known execution wrappers."""
    if action.argv:
        pieces, opaque = [Command(tuple(action.argv))], False
    else:
        pieces, opaque = _lex(action.command or "")
    commands: list[Command] = []

    def visit(piece: Command, depth: int) -> None:
        nonlocal opaque
        if depth > _MAX_DEPTH or len(commands) >= _MAX_COMMANDS:
            opaque = True
            return
        commands.append(piece)
        if not piece.argv:
            return
        name = program(piece.argv[0])
        children: list[Command] = []
        if name in WRAPPERS:
            if name == "env" and any(
                arg.startswith(("-S", "--split-string")) for arg in piece.argv[1:]
            ):
                opaque = True
            target = _wrapper_target(piece.argv)
            if target:
                children = [Command(target, piped=piece.piped)]
        elif name in SHELLS or name == "eval":
            script = " ".join(piece.argv[1:]) if name == "eval" else shell_script(piece.argv)
            if script is not None:
                children, uncertain = _lex(script)
                opaque |= uncertain or name == "eval"
        elif name == "xargs":
            target = xargs_target(piece.argv)
            if target:
                children = [Command(target, piped=True)]
        elif name == "find":
            for index, arg in enumerate(piece.argv[:-1]):
                if arg in {"-exec", "-execdir", "-ok", "-okdir"}:
                    stop = next(
                        (
                            i
                            for i in range(index + 1, len(piece.argv))
                            if piece.argv[i] in {";", "+"}
                        ),
                        len(piece.argv),
                    )
                    children.append(Command(piece.argv[index + 1 : stop]))
        for child in children:
            visit(
                Command(
                    child.argv,
                    child.redirects,
                    child.piped,
                    True,
                    child.assignments,
                    child.process_input,
                ),
                depth + 1,
            )

    for piece in pieces:
        visit(piece, 0)
    return ShellPlan(tuple(commands), opaque)
