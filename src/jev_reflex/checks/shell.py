"""Bounded POSIX shell inspection. No expansion, subprocesses, or evaluation.

The lexer follows bash quoting closely enough to find every command a shell could run:
comments end at the first raw newline, backslash-newline joins lines only outside single
quotes and comments, ``$(...)``/``${...}``/backquotes nest their own quoting, ``$'...'`` and
``$"..."`` are decoded, unquoted brace lists are expanded and literal variable assignments are
propagated. Anything it cannot resolve is marked on the word or makes the plan opaque.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field, replace
from functools import lru_cache
from typing import NamedTuple

from ..models import ProposedAction

SHELLS = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "ash", "yash", "csh", "tcsh"}
)
# Prefix commands whose own arguments are never paths. Repository-boundary checks skip their
# argv because the wrapped command is inspected as its own plan entry.
WRAPPERS = frozenset(
    {
        "builtin",
        "busybox",
        "chrt",
        "command",
        "doas",
        "env",
        "exec",
        "ionice",
        "nice",
        "nohup",
        "setsid",
        "stdbuf",
        "sudo",
        "timeout",
        "toybox",
        "unbuffer",
    }
)
# Prefix commands that also take a path operand (lock file, new root, output file). They are
# unwrapped here but deliberately not exported in WRAPPERS so path checks still see that operand.
_PATH_WRAPPERS = frozenset({"chroot", "flock", "time"})
PREFIX_COMMANDS = WRAPPERS | _PATH_WRAPPERS
STDIN_FILES = frozenset({"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"})
# Interpreters that read a program from stdin when given no script or inline code.
CODE_INTERPRETERS = frozenset(
    {
        "node",
        "nodejs",
        "perl",
        "ruby",
        "php",
        "lua",
        "luajit",
        "tclsh",
        "wish",
        "osascript",
        "pwsh",
        "powershell",
        "irb",
        "r",
        "rscript",
        "julia",
    }
)
# Expansion kinds that leave a word's runtime value unknown.
UNRESOLVED_KINDS = frozenset({"parameter", "command", "arithmetic"})
# Expansion kinds that make a command word (the program to run) unknowable.
_COMMAND_WORD_KINDS = UNRESOLVED_KINDS | {
    "brace",
    "glob",
    "substituted",
    "ifs",
    "numeric_parameter",
}

_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_LEX_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\[[^\]]*\])?(\+?)=")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NAME_START = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_")
_PARAMETER = re.compile(r"([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])(?:(:?[-=+?])(.*))?", re.S)
_INTEGER = re.compile(r"[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+#[0-9A-Za-z@_]+|[0-9]+)")
_SEQUENCE = re.compile(
    r"([+-]?[0-9]+)\.\.([+-]?[0-9]+)(?:\.\.([+-]?[0-9]+))?"
    r"|([A-Za-z])\.\.([A-Za-z])(?:\.\.([+-]?[0-9]+))?"
)
_SEPARATORS = frozenset({";", "&&", "||", "|", "|&", "&", "(", ")", "\n"})
_REDIRECTIONS = frozenset({">", ">>", ">|", "&>", "&>>", "<", "<<<", "<<", "<<-", "<>", ">&", "<&"})
_OPERATORS = ("&>>", "<<<", "<<-", "&>", "&&", "||", "|&", "<<", ">>", "<>", ">&", "<&", ">|")
_META = frozenset(";&|()<>")
# Bash splits words on space and tab only; CR, form feed and Unicode spaces are word text
# (a CR that ends a CRLF line is treated as a blank so CRLF input is not under-inspected).
_BLANKS = frozenset(" \t")
_LITERAL_RUN = re.compile(r"[^ \t\r\n\\'\"`$;&|()<>{},*?\[\]~]+")
_RESERVED = frozenset(
    {"{", "}", "if", "then", "elif", "else", "fi", "do", "done", "while", "until", "!", "esac"}
)
_COMPOUND_OPEN = frozenset({"if", "while", "until", "for", "case", "select"})
_COMPOUND_CLOSE = frozenset({"fi", "done", "esac"})
_DECLARATIONS = frozenset({"export", "declare", "typeset", "local", "readonly"})
_ARITHMETIC_OPERATORS = frozenset({"-eq", "-ne", "-lt", "-le", "-gt", "-ge"})
_NUMERIC_SPECIALS = frozenset({"?", "#", "$", "!"})
_ANSI_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "E": "\x1b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "?": "?",
}
_MAX_DEPTH = 8
_MAX_COMMANDS = 256
_MAX_NESTING = 32
_MAX_BRACE_WORDS = 256
_MAX_BRACES = 64
_MAX_RECOVERIES = 32


def program(word: str) -> str:
    return word.rsplit("/", 1)[-1].lower()


def is_python(name: str) -> bool:
    return bool(re.fullmatch(r"python(?:[23](?:\.\d+)?)?|pypy[23]?", name))


@dataclass(frozen=True)
class Word:
    """One shell word after quote removal and the expansions its value depends on.

    ``text`` keeps the source text of any expansion the lexer could not resolve (for example
    ``$HOME``). ``kinds`` names the expansions involved: ``parameter``, ``command`` and
    ``arithmetic`` leave the runtime value unknown (see ``unresolved``); ``brace``, ``glob``,
    ``tilde``, ``substituted`` (a value taken from a literal assignment or a ``${X:-default}``
    candidate; together with ``parameter`` when the value is only a candidate),
    ``numeric_parameter`` (``$?``, ``$#``, ``$$``, ``$!``), ``vanishable`` (an unquoted
    expansion that may produce no word), ``ifs``, ``ansi_c`` and ``locale`` are informational.
    ``substitutions`` holds the bodies of command substitutions whose output this word carries.
    """

    text: str
    kinds: frozenset[str] = frozenset()
    substitutions: tuple[str, ...] = ()

    @property
    def unresolved(self) -> bool:
        return bool(self.kinds & UNRESOLVED_KINDS)


@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    redirects: tuple[tuple[str, str], ...] = ()
    piped: bool = False
    indirect: bool = False
    assignments: tuple[str, ...] = ()
    process_input: bool = False
    # Per-word metadata aligned with argv/redirects/assignments. Empty when the argv was given
    # verbatim (an exec-style argv has no shell expansions).
    words: tuple[Word, ...] = ()
    redirect_words: tuple[Word, ...] = ()
    assignment_words: tuple[Word, ...] = ()
    # Where the command runs: "local", "remote" (an ssh remote command) or "container" (a
    # docker/podman exec payload). Paths in a non-local command do not name local files.
    context: str = "local"

    def word(self, index: int) -> Word:
        if len(self.words) == len(self.argv):
            return self.words[index]
        return Word(self.argv[index])

    @property
    def unresolved(self) -> tuple[bool, ...]:
        """Per-argv flags: True where the word contains an unresolved expansion."""
        return tuple(self.word(index).unresolved for index in range(len(self.argv)))


@dataclass(frozen=True)
class ShellPlan:
    commands: tuple[Command, ...]
    opaque: bool = False


class _Unterminated(Exception):
    """A quote, substitution or expansion has no terminator (or nests too deeply)."""


class _TooMany(Exception):
    """Brace expansion would produce too many words."""


@dataclass
class _Segment:
    kind: str  # "lit" (one unquoted character), "text" (quoted literal), "param", "cmd", "arith"
    text: str
    quoted: bool = False
    body: str = ""


@dataclass
class _Token:
    op: str
    start: int
    end: int
    raw: str
    segments: list[_Segment] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)


@dataclass
class _Variable:
    value: str | None
    definite: bool
    substitutions: tuple[str, ...] = ()


# --- skipping nested constructs -------------------------------------------------------------


def _line_end_cr(source: str, index: int) -> bool:
    """A carriage return ending a CRLF line counts as a blank (bash would keep it)."""
    return source[index] == "\r" and (index + 1 == len(source) or source[index + 1] == "\n")


def _skip_single(source: str, index: int) -> int:
    end = source.find("'", index)
    if end < 0:
        raise _Unterminated
    return end + 1


def _skip_ansi(source: str, index: int) -> int:
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
        elif char == "'":
            return index + 1
        else:
            index += 1
    raise _Unterminated


def _skip_backtick(source: str, index: int) -> int:
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
        elif char == "`":
            return index + 1
        else:
            index += 1
    raise _Unterminated


def _skip_dollar(source: str, index: int, depth: int) -> int | None:
    """Skip a ``$`` construct at ``index`` that opens nested quoting; None if it does not."""
    following = source[index + 1 : index + 2]
    if following == "'":
        return _skip_ansi(source, index + 2)
    if following in {"(", "{"}:
        if depth > _MAX_NESTING:
            raise _Unterminated
        if following == "(":
            return _skip_command(source, index + 2, depth + 1)
        return _skip_parameter(source, index + 2, depth + 1)
    return None


def _skip_double(source: str, index: int, depth: int) -> int:
    while index < len(source):
        char = source[index]
        if char == '"':
            return index + 1
        if char == "\\":
            index += 2
        elif char == "`":
            index = _skip_backtick(source, index + 1)
        elif char == "$" and source[index + 1 : index + 2] in {"(", "{"}:
            end = _skip_dollar(source, index, depth)
            index = end if end is not None else index + 1
        else:
            index += 1
    raise _Unterminated


def _skip_parameter(source: str, index: int, depth: int) -> int:
    level = 1
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == "'":
            index = _skip_single(source, index + 1)
            continue
        if char == '"':
            index = _skip_double(source, index + 1, depth)
            continue
        if char == "`":
            index = _skip_backtick(source, index + 1)
            continue
        if char == "$" and (end := _skip_dollar(source, index, depth)) is not None:
            index = end
            continue
        if char == "{":
            level += 1
        elif char == "}":
            level -= 1
            if level == 0:
                return index + 1
        index += 1
    raise _Unterminated


def _skip_command(source: str, index: int, depth: int) -> int:
    level = 1
    word_start = True
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            word_start = False
            continue
        if char == "'":
            index = _skip_single(source, index + 1)
            word_start = False
            continue
        if char == '"':
            index = _skip_double(source, index + 1, depth)
            word_start = False
            continue
        if char == "`":
            index = _skip_backtick(source, index + 1)
            word_start = False
            continue
        if char == "$" and (end := _skip_dollar(source, index, depth)) is not None:
            index = end
            word_start = False
            continue
        if char == "#" and word_start:
            newline = source.find("\n", index)
            if newline < 0:
                raise _Unterminated
            index = newline
            continue
        if char == "(":
            level += 1
        elif char == ")":
            level -= 1
            if level == 0:
                return index + 1
        word_start = char in _BLANKS or char == "\n" or char in _META
        index += 1
    raise _Unterminated


def _operand_literal(operand: str) -> str | None:
    """Quote-removed text of a ``${x:-word}`` operand; None when the operand expands anything."""
    out: list[str] = []
    index = 0
    quote = ""
    while index < len(operand):
        char = operand[index]
        if char in "$`" and quote != "'":
            return None
        if char == "\\" and quote != "'" and index + 1 < len(operand):
            out.append(operand[index + 1])
            index += 2
            continue
        if char in "'\"" and quote in {"", char}:
            quote = "" if quote else char
        else:
            out.append(char)
        index += 1
    return None if quote else "".join(out)


def _backtick_body(text: str) -> str:
    return re.sub(r"\\([\\`$])", r"\1", text)


def _ansi_c(text: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\" or index + 1 >= len(text):
            out.append(char)
            index += 1
            continue
        escape = text[index + 1]
        index += 2
        if escape in _ANSI_ESCAPES:
            out.append(_ANSI_ESCAPES[escape])
        elif escape in "01234567":
            match = re.match(r"[0-7]{0,2}", text[index:])
            digits = escape + (match[0] if match else "")
            index += len(digits) - 1
            out.append(chr(int(digits, 8) & 0xFF))
        elif escape in "xuU":
            limit = {"x": 2, "u": 4, "U": 8}[escape]
            match = re.match(rf"[0-9a-fA-F]{{1,{limit}}}", text[index:])
            if not match:
                out.append("\\" + escape)
                continue
            index += len(match[0])
            code = int(match[0], 16)
            out.append(chr(code) if code <= 0x10FFFF else "�")
        elif escape == "c" and index < len(text):
            out.append(chr(ord(text[index]) & 0x1F))
            index += 1
        else:
            out.append("\\" + escape)
    return "".join(out)


def _arithmetic_form(inner: str) -> bool:
    """Whether ``$(inner)`` is ``$((...))``: bash parses that as arithmetic, never a subshell."""
    return inner.startswith("(") and inner.endswith(")")


def _command_like(expression: str) -> bool:
    """Arithmetic text that reads like commands; inspected as both to stay fail-closed."""
    return bool(
        ";" in expression
        or "\n" in expression
        or re.search(r"[A-Za-z0-9_\])]\s+[A-Za-z0-9_$(]", expression)
    )


def _collect_substitutions(text: str, depth: int = 0) -> list[str]:
    """Command-substitution bodies inside an expansion body (quotes are not honoured)."""
    bodies: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        try:
            if char == "\\":
                index += 2
                continue
            if char == "`":
                end = _skip_backtick(text, index + 1)
                bodies.append(_backtick_body(text[index + 1 : end - 1]))
                index = end
                continue
            if char == "$" and text[index + 1 : index + 2] == "(" and depth < _MAX_NESTING:
                end = _skip_command(text, index + 2, depth + 1)
                inner = text[index + 2 : end - 1]
                if not _arithmetic_form(inner) or _command_like(inner[1:-1]):
                    bodies.append(inner)
                if _arithmetic_form(inner):
                    bodies.extend(_collect_substitutions(inner[1:-1], depth + 1))
                index = end
                continue
        except _Unterminated:
            bodies.append(text[index:])
            break
        index += 1
    return bodies


# --- tokenizing ---------------------------------------------------------------------------


def _scan_dollar(
    source: str, index: int, segments: list[_Segment], flags: set[str], quoted: bool
) -> int:
    following = source[index + 1 : index + 2]
    if following == "'" and not quoted:
        end = _skip_ansi(source, index + 2)
        segments.append(_Segment("text", _ansi_c(source[index + 2 : end - 1])))
        flags.add("ansi_c")
        return end
    if following == '"' and not quoted:
        flags.add("locale")
        return _scan_double(source, index + 2, segments, flags)
    if following == "(":
        end = _skip_command(source, index + 2, 1)
        inner = source[index + 2 : end - 1]
        if _arithmetic_form(inner):
            segments.append(_Segment("arith", source[index:end], quoted, inner[1:-1]))
        else:
            segments.append(_Segment("cmd", source[index:end], quoted, inner))
        return end
    if following == "[":
        level, cursor = 0, index + 1
        while cursor < len(source):
            if source[cursor] == "[":
                level += 1
            elif source[cursor] == "]":
                level -= 1
                if level == 0:
                    segments.append(
                        _Segment(
                            "arith", source[index : cursor + 1], quoted, source[index + 2 : cursor]
                        )
                    )
                    return cursor + 1
            cursor += 1
        raise _Unterminated
    if following == "{":
        end = _skip_parameter(source, index + 2, 1)
        segments.append(_Segment("param", source[index:end], quoted, source[index + 2 : end - 1]))
        return end
    if following and following in _NAME_START:
        match = _NAME.match(source, index + 1)
        assert match is not None
        segments.append(_Segment("param", "$" + match[0], quoted, match[0]))
        return match.end()
    if following and following in "0123456789@*#?$!-":
        segments.append(_Segment("param", "$" + following, quoted, following))
        return index + 2
    segments.append(_Segment("text" if quoted else "lit", "$"))
    return index + 1


def _scan_double(source: str, index: int, segments: list[_Segment], flags: set[str]) -> int:
    buffer: list[str] = []
    while index < len(source):
        char = source[index]
        if char == '"':
            segments.append(_Segment("text", "".join(buffer)))
            return index + 1
        if char == "\\" and index + 1 < len(source):
            following = source[index + 1]
            if following == "\n":
                index += 2
            elif following in '$`"\\':
                buffer.append(following)
                index += 2
            else:
                buffer.append(char)
                index += 1
            continue
        if char in "`$":
            if buffer:
                segments.append(_Segment("text", "".join(buffer)))
                buffer = []
            if char == "`":
                end = _skip_backtick(source, index + 1)
                body = _backtick_body(source[index + 1 : end - 1])
                segments.append(_Segment("cmd", source[index:end], True, body))
                index = end
            else:
                index = _scan_dollar(source, index, segments, flags, quoted=True)
            continue
        buffer.append(char)
        index += 1
    raise _Unterminated


class _Broken(Exception):
    def __init__(self, position: int) -> None:
        super().__init__(position)
        self.position = position


def _scan_word(source: str, index: int, segments: list[_Segment], flags: set[str]) -> int:
    while index < len(source):
        char = source[index]
        if char in _BLANKS or char == "\n" or char in _META or _line_end_cr(source, index):
            break
        start, mark = index, len(segments)
        try:
            if char == "\\":
                if source.startswith("\\\n", index):
                    index += 2
                elif index + 1 < len(source):
                    segments.append(_Segment("text", source[index + 1]))
                    index += 2
                else:
                    segments.append(_Segment("text", "\\"))
                    index += 1
            elif char == "'":
                end = _skip_single(source, index + 1)
                segments.append(_Segment("text", source[index + 1 : end - 1]))
                index = end
            elif char == '"':
                index = _scan_double(source, index + 1, segments, flags)
            elif char == "`":
                end = _skip_backtick(source, index + 1)
                body = _backtick_body(source[index + 1 : end - 1])
                segments.append(_Segment("cmd", source[index:end], False, body))
                index = end
            elif char == "$":
                index = _scan_dollar(source, index, segments, flags, quoted=False)
            elif (run := _LITERAL_RUN.match(source, index)) is not None:
                segments.append(_Segment("lit", run[0]))
                index = run.end()
            else:
                # Brace, glob and tilde characters stay single so expansion can find them.
                segments.append(_Segment("lit", char))
                index += 1
        except (_Unterminated, RecursionError):
            del segments[mark:]
            raise _Broken(start) from None
    return index


def _tokenize(source: str) -> tuple[list[_Token], bool]:
    tokens: list[_Token] = []
    broken = False
    recoveries = 0
    index = 0
    while index < len(source):
        char = source[index]
        if char in _BLANKS or _line_end_cr(source, index):
            index += 1
            continue
        if source.startswith("\\\n", index):
            index += 2
            continue
        if char == "#":
            # A comment runs to the first raw newline; backslash-newline does not continue it.
            newline = source.find("\n", index)
            if newline < 0:
                break
            index = newline
            continue
        operator = next((op for op in _OPERATORS if source.startswith(op, index)), None)
        if operator is None and (char == "\n" or char in _META):
            operator = char
        if operator is not None:
            end = index + len(operator)
            tokens.append(_Token(operator, index, end, operator))
            index = end
            continue
        token = _Token("", index, index, "")
        try:
            token.end = _scan_word(source, index, token.segments, token.flags)
        except _Broken as error:
            # Bash would reject the rest of this input. Keep the part before the broken
            # construct, then over-approximate by lexing what follows its opening character.
            broken = True
            recoveries += 1
            if token.segments:
                token.end = error.position
                token.raw = source[index : error.position]
                tokens.append(token)
            if recoveries > _MAX_RECOVERIES:
                break
            index = error.position + 1
            continue
        token.raw = source[index : token.end]
        tokens.append(token)
        index = token.end
    return tokens, broken


# --- brace expansion ----------------------------------------------------------------------


def _is_active(segment: _Segment, char: str) -> bool:
    return segment.kind == "lit" and segment.text == char


def _sequence(text: str) -> list[str] | None:
    match = _SEQUENCE.fullmatch(text)
    if match is None:
        return None
    if match[1] is not None:
        first, last = int(match[1]), int(match[2])
        step = abs(int(match[3] or 1)) or 1
        if abs(last - first) // step + 1 > _MAX_BRACE_WORDS:
            raise _TooMany
        padded = any(
            len(item.lstrip("+-")) > 1 and item.lstrip("+-").startswith("0")
            for item in (match[1], match[2])
        )
        width = max(len(match[1]), len(match[2])) if padded else 0
        direction = 1 if last >= first else -1
        values = range(first, last + direction, step * direction)
        return [f"{value:0{width}d}" for value in values]
    first, last = ord(match[4]), ord(match[5])
    step = abs(int(match[6] or 1)) or 1
    direction = 1 if last >= first else -1
    return [chr(value) for value in range(first, last + direction, step * direction)]


def _brace_expand(segments: list[_Segment], budget: list[int]) -> list[list[_Segment]] | None:
    """Expand the first valid unquoted brace group (bash order); None when there is none."""
    for start, segment in enumerate(segments):
        if not _is_active(segment, "{"):
            continue
        level, end, commas = 0, -1, []
        for cursor in range(start, len(segments)):
            item = segments[cursor]
            if _is_active(item, "{"):
                level += 1
            elif _is_active(item, "}"):
                level -= 1
                if level == 0:
                    end = cursor
                    break
            elif level == 1 and _is_active(item, ","):
                commas.append(cursor)
        if end < 0:
            continue
        if commas:
            bounds = [start, *commas, end]
            parts = [
                segments[left + 1 : right] for left, right in zip(bounds, bounds[1:], strict=False)
            ]
        else:
            inner = segments[start + 1 : end]
            items = (
                _sequence("".join(item.text for item in inner))
                if all(item.kind == "lit" for item in inner)
                else None
            )
            if items is None:
                continue
            parts = [[_Segment("text", item)] for item in items]
        prefix, suffix = segments[:start], segments[end + 1 :]
        tails = _brace_expand(suffix, budget) or [suffix]
        expanded: list[list[_Segment]] = []
        for part in parts:
            for middle in _brace_expand(part, budget) or [part]:
                for tail in tails:
                    budget[0] -= 1
                    if budget[0] < 0:
                        raise _TooMany
                    expanded.append(prefix + middle + tail)
        return expanded
    return None


def _glob(segments: list[_Segment]) -> bool:
    opened = False
    for segment in segments:
        if segment.kind != "lit":
            continue
        if segment.text in {"*", "?"}:
            return True
        if segment.text == "[":
            opened = True
        elif segment.text == "]" and opened:
            return True
    return False


# --- lexing -------------------------------------------------------------------------------


class _Expansion(NamedTuple):
    text: str
    kinds: frozenset[str]
    substitutions: tuple[str, ...]
    splittable: bool


class _Lexer:
    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens = tokens
        self.chunks: list[Command] = []
        self.opaque = False
        self.variables: dict[str, _Variable] = {}
        self.words: list[Word] = []
        self.redirects: list[tuple[str, str]] = []
        self.redirect_words: list[Word] = []
        self.assignment_words: list[Word] = []
        self.redirect = ""
        self.redirect_end = -1
        self.piped = False
        self.list_start = True
        self.parens = 0
        self.braces = 0
        self.compounds = 0
        self.arithmetic_level: int | None = None
        self.time_options = False
        self.skip_word = False

    # Parameter and arithmetic resolution ------------------------------------------------

    def _known(self, name: str) -> _Variable | None:
        variable = self.variables.get(name)
        return variable if variable is not None and variable.value is not None else None

    def _arithmetic_safe(self, text: str) -> bool:
        # $?, $#, $$, $! and ${#name} always expand to integers.
        rest = re.sub(r"\$[?#$!]|\$\{#[A-Za-z_][A-Za-z0-9_]*\}", " 0 ", text)
        rest = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", r"\1", rest)
        rest = re.sub(r"\b(?:0[xX][0-9a-fA-F]+|[0-9]+#[0-9A-Za-z@_]+|[0-9]+)\b", " ", rest)
        if re.search(r"[$`\[\]\"'\\]", rest):
            return False
        for name in _NAME.findall(rest):
            variable = self._known(name)
            if (
                variable is None
                or not variable.definite
                or not _INTEGER.fullmatch((variable.value or "").strip())
            ):
                return False
        return True

    def _parameter(self, segment: _Segment) -> _Expansion:
        raw = segment.text
        if raw.startswith("${"):
            match = _PARAMETER.fullmatch(segment.body)
            if match is None:
                # ${#x}, ${x#pat}, ${x/a/b}, ${!x}, ... : value unknown; nested $(...) still runs.
                found = tuple(_collect_substitutions(segment.body))
                other = {"parameter"} | ({"command"} if found else set())
                if re.match(r"!?#?IFS\b", segment.body):
                    other.add("ifs")
                return _Expansion(raw, frozenset(other), found, False)
            name, operator, operand = match[1], match[2], match[3]
        else:
            name, operator, operand = segment.body, None, None
        kinds: set[str] = set()
        nested = tuple(_collect_substitutions(operand)) if operand else ()
        if nested:
            kinds.add("command")
        if name == "IFS":
            kinds.add("ifs")
        if name in _NUMERIC_SPECIALS and operator is None:
            return _Expansion(raw, frozenset(kinds | {"numeric_parameter"}), (), False)
        variable = self.variables.get(name)
        taint = variable.substitutions if variable is not None else ()
        known = self._known(name)
        literal = _operand_literal(operand) if operand is not None else None

        def resolved(value: str, definite: bool) -> _Expansion:
            extra = {"substituted"} | (set() if definite else {"parameter"})
            return _Expansion(value, frozenset(kinds | extra), taint + nested, not segment.quoted)

        unresolved = _Expansion(raw, frozenset(kinds | {"parameter"}), taint + nested, False)
        if operator is None or operator in {"?", ":?"}:
            return resolved(known.value or "", known.definite) if known else unresolved
        use_value = known is not None and (bool(known.value) or not operator.startswith(":"))
        if operator in {"-", ":-", "=", ":="}:
            if known is not None and use_value:
                return resolved(known.value or "", known.definite)
            if literal is not None:
                return resolved(literal, known is not None and known.definite)
            return unresolved
        # ${x+word} / ${x:+word}
        if literal is None:
            return unresolved
        if known is not None:
            return resolved(literal if use_value else "", known.definite)
        return resolved(literal, False)

    # Word decoding ----------------------------------------------------------------------

    def _decode(self, token: _Token, *, expand: bool, split: bool = True) -> list[Word]:
        """Quote-removed words for a token; ``expand`` brace-expands, ``split`` field-splits."""
        variants = [token.segments]
        expanded = False
        if expand:
            if sum(_is_active(item, "{") for item in token.segments) > _MAX_BRACES:
                self.opaque = True
            else:
                try:
                    result = _brace_expand(token.segments, [_MAX_BRACE_WORDS])
                except _TooMany:
                    self.opaque = True
                    result = None
                if result is not None:
                    variants, expanded = result, True
        words: list[Word] = []
        for segments in variants:
            words.extend(self._build(segments, token.flags, expanded, split))
        return words

    def _build(
        self, segments: list[_Segment], flags: set[str], braced: bool, split: bool
    ) -> list[Word]:
        kinds: set[str] = set(flags)
        if braced:
            kinds.add("brace")
        if _glob(segments):
            kinds.add("glob")
        if segments and _is_active(segments[0], "~"):
            kinds.add("tilde")
        substitutions: list[str] = []
        pieces: list[tuple[str, bool, bool]] = []  # (text, splittable, counts as content)
        # Whether every part is an unquoted unresolved expansion that may produce no word.
        vanishable = bool(segments)
        for segment in segments:
            if segment.kind == "lit":
                pieces.append((segment.text, False, True))
                vanishable = False
            elif segment.kind == "text":
                pieces.append((segment.text, False, True))
                vanishable = False
            elif segment.kind == "param":
                expansion = self._parameter(segment)
                kinds |= expansion.kinds
                substitutions.extend(expansion.substitutions)
                counts = segment.quoted or bool(expansion.text)
                pieces.append((expansion.text, expansion.splittable and split, counts))
                vanishable &= not segment.quoted and "parameter" in expansion.kinds
            elif segment.kind == "cmd":
                kinds.add("command")
                substitutions.append(segment.body)
                pieces.append((segment.text, False, True))
                vanishable &= not segment.quoted
            else:
                vanishable = False
                nested = self._arithmetic_payload(segment.body)
                if _command_like(segment.body):
                    nested.append(f"({segment.body})")
                if nested:
                    kinds.add("command")
                    substitutions.extend(nested)
                if not self._arithmetic_safe(segment.body):
                    kinds.add("arithmetic")
                pieces.append((segment.text, False, True))
        texts: list[str] = []
        current: list[str] = []
        content = False
        for text, splittable, counts in pieces:
            if not splittable or not re.search(r"[ \t\n]", text):
                current.append(text)
                content |= counts and (bool(text) or not splittable)
                continue
            parts = re.split(r"[ \t\n]+", text)
            for position, part in enumerate(parts):
                if position:
                    if content:
                        texts.append("".join(current))
                    current, content = [], False
                current.append(part)
                content |= bool(part)
        if content:
            texts.append("".join(current))
        if vanishable and split:
            kinds.add("vanishable")
        frozen = frozenset(kinds)
        return [Word(text, frozen, tuple(substitutions)) for text in texts]

    # Chunk assembly ---------------------------------------------------------------------

    def run(self) -> tuple[list[Command], bool]:
        for index, token in enumerate(self.tokens):
            if token.op:
                self._operator(token, index)
            else:
                self._word(token, index)
        self._emit(None)
        return self.chunks, self.opaque or bool(self.redirect)

    def _operator(self, token: _Token, index: int) -> None:
        raw = token.op
        if raw in _REDIRECTIONS:
            if self.redirect or raw in {"<<", "<<-"}:
                self.opaque = True
            previous = self.tokens[index - 1] if index else None
            if (
                previous is not None
                and not previous.op
                and previous.end == token.start
                and self.words
                and self.words[-1].text.isdigit()
                and not self.words[-1].kinds
            ):
                self.words.pop()
            self.redirect = raw
            self.redirect_end = token.end
            return
        process_input = False
        if raw == "(":
            if self.redirect:
                self.opaque = True
                process_input = self.redirect == "<" and self.redirect_end == token.start
            following = self.tokens[index + 1] if index + 1 < len(self.tokens) else None
            if (
                not self.words
                and not self.redirect
                and following is not None
                and following.op == "("
                and following.start == token.end
                and self.arithmetic_level is None
            ):
                self.arithmetic_level = self.parens + 2
        self._emit(raw, process_input)
        if raw == "(":
            self.parens += 1
        elif raw == ")":
            self.parens = max(0, self.parens - 1)
            if self.arithmetic_level is not None and self.parens < self.arithmetic_level:
                self.arithmetic_level = None
        self.piped = raw in {"|", "|&"}
        self.list_start = raw in {";", "\n", "(", ")"}

    def _word(self, token: _Token, index: int) -> None:
        if self.redirect:
            # Here-strings and here-document delimiters are neither brace-expanded nor split.
            literal = self.redirect in {"<<<", "<<", "<<-"}
            decoded = self._decode(token, expand=not literal, split=not literal)
            if len(decoded) != 1:
                self.opaque = True
            target = decoded[0] if decoded else Word("", frozenset(token.flags))
            if target.unresolved or target.kinds & {"ansi_c", "ifs", "numeric_parameter"}:
                self.opaque = True
            self.redirects.append((self.redirect, target.text))
            self.redirect_words.append(target)
            self.redirect = ""
            return
        plain = all(segment.kind == "lit" for segment in token.segments)
        if not self.words:
            if self.skip_word:
                self.skip_word = False
                return
            if plain and self._keyword(token, index):
                return
            if _LEX_ASSIGNMENT.match(token.raw):
                values = self._decode(token, expand=False, split=False)
                assignment = values[0] if values else Word(token.raw)
                self._flag(assignment)
                self.assignment_words.append(assignment)
                return
        self.time_options = False
        # Words between [[ and ]] are neither brace-expanded nor split.
        test = bool(self.words) and self.words[0].text == "[[" and not self.words[0].kinds
        decoded = self._decode(token, expand=not test, split=not test)
        command_word = not self.words
        for word in decoded:
            if self.arithmetic_level is not None and self.parens >= self.arithmetic_level:
                word = self._arithmetic_operand(word)
            self._flag(word)
            if command_word and not self.words and word.kinds & _COMMAND_WORD_KINDS:
                self.opaque = True
            self.words.append(word)
        if command_word and len(decoded) > 1:
            self.opaque = True

    def _keyword(self, token: _Token, index: int) -> bool:
        raw = token.raw
        if self.time_options and raw in {"-p", "--"}:
            return True
        if raw in _RESERVED:
            if raw == "{":
                self.braces += 1
            elif raw == "}":
                self.braces = max(0, self.braces - 1)
            elif raw in _COMPOUND_OPEN:
                self.compounds += 1
            elif raw in _COMPOUND_CLOSE:
                self.compounds = max(0, self.compounds - 1)
            return True
        if raw in {"for", "case", "select"}:
            self.compounds += 1
            return False
        if raw == "time":
            self.time_options = True
            return True
        if raw == "function":
            self.skip_word = True
            return True
        if raw == "coproc":
            following = self.tokens[index + 1 : index + 3]
            if (
                len(following) == 2
                and not following[0].op
                and _NAME.fullmatch(following[0].raw)
                and (following[1].op == "(" or following[1].raw == "{")
            ):
                self.skip_word = True
            return True
        return False

    def _flag(self, word: Word) -> None:
        if word.kinds & {"command", "ansi_c", "ifs"}:
            self.opaque = True

    def _arithmetic_payload(self, text: str, depth: int = 0) -> list[str]:
        """Substitutions an arithmetic evaluation of ``text`` would run.

        Arithmetic evaluates variable values recursively, so ``x='a[$(cmd)]'; ((x))``
        runs ``cmd``: known variable values referenced by name are searched too.
        """
        bodies = _collect_substitutions(text)
        if depth < 4:
            for name in dict.fromkeys(_NAME.findall(text)):
                variable = self._known(name)
                if variable is not None and variable.value:
                    bodies.extend(self._arithmetic_payload(variable.value, depth + 1))
        return bodies

    def _arithmetic_operand(self, word: Word) -> Word:
        payload = tuple(self._arithmetic_payload(word.text))
        kinds = set(word.kinds)
        if payload:
            kinds.add("command")
            self.opaque = True
        if word.unresolved or not self._arithmetic_safe(word.text):
            kinds.add("arithmetic")
        if payload or kinds != word.kinds:
            return replace(word, kinds=frozenset(kinds), substitutions=word.substitutions + payload)
        return word

    def _emit(self, separator: str | None, process_input: bool = False) -> None:
        if self.words or self.redirects or self.assignment_words:
            words = self.words
            if words and words[0].text == "[[":
                # [[ a -eq b ]] evaluates both operands as arithmetic expressions.
                operands = {
                    position + offset
                    for position, word in enumerate(words)
                    if word.text in _ARITHMETIC_OPERATORS
                    for offset in (-1, 1)
                }
                words = [
                    self._arithmetic_operand(word) if position in operands else word
                    for position, word in enumerate(words)
                ]
            elif words and words[0].text == "let":
                words = [words[0], *(self._arithmetic_operand(word) for word in words[1:])]
            command = Command(
                tuple(word.text for word in words),
                tuple(self.redirects),
                self.piped,
                assignments=tuple(word.text for word in self.assignment_words),
                process_input=process_input,
                words=tuple(words),
                redirect_words=tuple(self.redirect_words),
                assignment_words=tuple(self.assignment_words),
            )
            self.chunks.append(command)
            self._track(command, separator)
        self.words, self.redirects, self.redirect_words, self.assignment_words = [], [], [], []
        self.redirect = ""
        self.time_options = False

    def _track(self, command: Command, separator: str | None) -> None:
        """Record literal assignments so later ``$NAME`` words can be resolved."""
        definite = (
            self.list_start
            and not command.piped
            and separator not in {"|", "|&", "&"}
            and self.parens == 0
            and self.braces == 0
            and self.compounds == 0
        )
        assignments: list[Word] = []
        if not command.argv:
            assignments = list(command.assignment_words)
        else:
            name = command.argv[0]
            arguments = command.words[1:]
            if name in _DECLARATIONS:
                assignments = [word for word in arguments if _LEX_ASSIGNMENT.match(word.text)]
                if name in {"local", "declare", "typeset"}:
                    # A bare declaration may reset the value (function scope, -i, -a ...).
                    for word in arguments:
                        if "=" not in word.text:
                            self.variables.pop(word.text, None)
            elif name in {"unset", "read", "mapfile", "readarray", "getopts", "for", "select"}:
                for word in arguments:
                    self.variables.pop(word.text, None)
            elif name == "printf" and "-v" in command.argv:
                position = command.argv.index("-v") + 1
                if position < len(command.argv):
                    self.variables.pop(command.argv[position], None)
        for word in assignments:
            match = _LEX_ASSIGNMENT.match(word.text)
            if match is None:
                continue
            name, subscript, append = match[1], match[2], match[3]
            value = word.text[match.end() :]
            previous = self._known(name)
            if subscript or word.unresolved or (append and previous is None):
                self.variables[name] = _Variable(None, False, word.substitutions)
                continue
            if append and previous is not None:
                value = (previous.value or "") + value
                definite = definite and previous.definite
            self.variables[name] = _Variable(value, definite)


def _lex(source: str) -> tuple[list[Command], bool]:
    tokens, broken = _tokenize(source)
    chunks, opaque = _Lexer(tokens).run()
    return chunks, opaque or broken


# --- prefix commands and interpreters -----------------------------------------------------

_WRAPPER_PARAMETERS = {
    "env": {"-u", "--unset", "-C", "--chdir", "-P"},
    "sudo": {
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
        "-D",
        "--chdir",
        "-R",
        "--chroot",
        "-T",
        "--command-timeout",
    },
    "doas": {"-u", "-C"},
    "exec": {"-a"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-k", "--kill-after", "-s", "--signal"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "ionice": {"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"},
    "chrt": {"-T", "--sched-runtime", "-P", "--sched-period", "-D", "--sched-deadline"},
    "flock": {"-w", "--wait", "--timeout", "-E", "--conflict-exit-code", "-c", "--command"},
    "chroot": {"--userspec", "--groups"},
    "time": {"-o", "--output", "-f", "--format"},
}
# Wrappers that take one positional operand (duration, priority, lock file, new root) before
# the wrapped command.
_WRAPPER_OPERAND = frozenset({"timeout", "chrt", "flock", "chroot"})
_SHELL_LONG_VALUES = frozenset(
    {"--rcfile", "--init-file", "--emulate", "--features", "--debug-output", "--profile"}
)


def _wrapper_start(argv: tuple[str, ...]) -> int | None:
    """Index of the wrapped command in a prefix-command argv, or None when there is none."""
    name = program(argv[0])
    if name == "command" and any(arg in {"-v", "-V"} for arg in argv[1:]):
        return None
    parameters = _WRAPPER_PARAMETERS.get(name, set())
    short_values = {item[1] for item in parameters if len(item) == 2}
    index = 1
    while index < len(argv):
        word = argv[index]
        if word == "--":
            index += 1
            break
        if word in parameters:
            index += 2
        elif word.startswith("--") and "=" in word:
            index += 1
        elif word.startswith("-") and len(word) > 1:
            letters = word[1:]
            consumed = 0
            for position, letter in enumerate(letters):
                if letter in short_values:
                    consumed = 0 if letters[position + 1 :] else 1
                    break
            index += 1 + consumed
        elif _ASSIGNMENT.match(word):
            index += 1
        else:
            break
    if name == "chrt" and any(arg in {"-p", "--pid", "-m", "--max"} for arg in argv[1:index]):
        return None
    if name in _WRAPPER_OPERAND:
        index += 1
    return index if index < len(argv) else None


def _flock_script(argv: tuple[str, ...]) -> str | None:
    for index, word in enumerate(argv[1:], 1):
        if word in {"-c", "--command"} and index + 1 < len(argv):
            return argv[index + 1]
        if word.startswith("--command="):
            return word.partition("=")[2]
    return None


class ShellInvocation(NamedTuple):
    scripts: tuple[str, ...]
    command_mode: bool
    reads_stdin: bool


def shell_invocation(argv: tuple[str, ...]) -> ShellInvocation:
    """Parse a shell argv: inline scripts (``-c``, fish ``-C``/``--command``) and stdin use."""
    name = program(argv[0])
    scripts: list[str] = []
    command_mode = stdin_flag = False
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg in {"--", "-"}:
            index += 1
            break
        if arg.startswith("--"):
            key, equals, value = arg.partition("=")
            if key in {"--command", "--init-command"}:
                if equals:
                    scripts.append(value)
                elif index + 1 < len(argv):
                    scripts.append(argv[index + 1])
                index += 1 if equals else 2
                continue
            index += 2 if not equals and key in _SHELL_LONG_VALUES else 1
            continue
        if len(arg) > 1 and arg[0] in "-+":
            consumers: list[str] = []
            for letter in arg[1:]:
                if letter in "oO" or (letter == "C" and name == "fish"):
                    consumers.append(letter)
                elif letter == "c":
                    command_mode = True
                elif letter == "s":
                    stdin_flag = True
            for offset, letter in enumerate(consumers, 1):
                if letter == "C" and index + offset < len(argv):
                    scripts.append(argv[index + offset])
            index += 1 + len(consumers)
            continue
        break
    if command_mode:
        if index < len(argv):
            scripts.insert(0, argv[index])
        return ShellInvocation(tuple(scripts), True, False)
    reads_stdin = stdin_flag or index >= len(argv) or argv[index] in STDIN_FILES
    return ShellInvocation(tuple(scripts), False, reads_stdin)


def shell_script(argv: tuple[str, ...]) -> str | None:
    invocation = shell_invocation(argv)
    return invocation.scripts[0] if invocation.command_mode and invocation.scripts else None


def _value(argv: tuple[str, ...], index: int, rest: str) -> tuple[str | None, int]:
    """Value of a short option: the rest of its group, else the next argument."""
    if rest:
        return rest, 0
    return (argv[index + 1], 1) if index + 1 < len(argv) else (None, 0)


def interpreter_code(argv: tuple[str, ...]) -> tuple[tuple[str, ...], bool]:
    """Inline code given to python/node/perl/ruby (grouped short flags included).

    Returns the code fragments and whether the program is read from stdin instead.
    """
    name = program(argv[0])
    python = is_python(name)
    node = name in {"node", "nodejs"}
    codes: list[str] = []
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            index += 1
            break
        if arg == "-":
            return tuple(codes), not codes
        if not arg.startswith("-"):
            return tuple(codes), False
        consumed = 0
        if arg.startswith("--"):
            key, equals, attached = arg.partition("=")
            if node and key in {"--eval", "--print"}:
                code, consumed = (attached, 0) if equals else _value(argv, index, "")
                if code is not None:
                    codes.append(code)
            elif not equals and (
                (python and key == "--check-hash-based-pycs")
                or (node and key in {"--require", "--import", "--loader", "--conditions"})
                or (node and key in {"--experimental-loader", "--env-file", "--input-type"})
            ):
                consumed = 1
            index += 1 + consumed
            continue
        letters = arg[1:]
        position = 0
        while position < len(letters):
            letter, rest = letters[position], letters[position + 1 :]
            if python and letter in "cmWX":
                value, consumed = _value(argv, index, rest)
                if letter == "c":
                    return ((value,) if value is not None else ()), False
                if letter == "m":
                    return tuple(codes), False
                break
            if node and letter in "ep":
                if rest and set(rest) <= {"e", "p"}:
                    rest = ""
                value, consumed = _value(argv, index, rest)
                if value is not None:
                    codes.append(value)
                break
            if node and letter in "rC":
                consumed = _value(argv, index, rest)[1]
                break
            if name in {"perl", "ruby"} and letter in ("eE" if name == "perl" else "e"):
                value, consumed = _value(argv, index, rest)
                if value is not None:
                    codes.append(value)
                break
            if name == "perl" and letter in "0lC":
                # -l[octal], -0[octal|xHEX] and -C[number|IOESioDALa] take optional values.
                pattern = {
                    "l": r"[0-7]*",
                    "0": r"x[0-9a-fA-F]*|[0-7]*",
                    "C": r"[0-9]*|[IOESioDALa]*",
                }
                match = re.match(pattern[letter], rest)
                position += 1 + (len(match[0]) if match else 0)
                continue
            if name == "perl" and letter in "iIMmxdDF":
                consumed = _value(argv, index, rest)[1] if letter == "I" else 0
                break
            if name == "ruby" and letter in "iIrCEFxKTW0":
                consumed = _value(argv, index, rest)[1] if letter in "IrCE" else 0
                break
            position += 1
        index += 1 + consumed
    if python or node or name in {"perl", "ruby"}:
        return tuple(codes), not codes and index >= len(argv)
    return tuple(codes), index >= len(argv)


def reads_program_from_stdin(argv: tuple[str, ...]) -> bool:
    """Whether a shell or code interpreter would execute its standard input."""
    name = program(argv[0])
    if name in SHELLS:
        return shell_invocation(argv).reads_stdin
    if name in {"source", "."}:
        operands = [arg for arg in argv[1:] if arg != "--"]
        return bool(operands) and operands[0] in STDIN_FILES
    if is_python(name) or name in CODE_INTERPRETERS:
        return interpreter_code(argv)[1]
    return False


def xargs_target(argv: tuple[str, ...]) -> tuple[str, ...]:
    start = _xargs_start(argv)
    return argv[start:]


def _xargs_start(argv: tuple[str, ...]) -> int:
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
    return index


def _slice(
    command: Command, start: int, stop: int | None = None, *, inherit: bool = False
) -> Command:
    aligned = len(command.words) == len(command.argv)
    return Command(
        command.argv[start:stop],
        command.redirects if inherit else (),
        command.piped,
        True,
        (),
        command.process_input if inherit else False,
        command.words[start:stop] if aligned else (),
        command.redirect_words if inherit else (),
    )


class SuInvocation(NamedTuple):
    executes: bool  # starts a shell as another user (not --help/--version)
    script: str | None  # the -c/--command script; None for an interactive shell


_SU_VALUE_LETTERS = frozenset("csgGwu")
_SU_VALUE_LONG = frozenset(
    {
        "--command",
        "--session-command",
        "--shell",
        "--group",
        "--supp-group",
        "--whitelist-environment",
        "--user",
    }
)


def su_invocation(argv: tuple[str, ...]) -> SuInvocation:
    """Parse ``su``/``runuser``, whose util-linux getopt accepts options after the user.

    ``runuser -u USER [--] COMMAND [ARG...]`` runs COMMAND directly, without a shell; that
    argv is returned as the script (quoted, so it lexes back to the same words).
    """
    script = None
    user_mode = False  # runuser -u/--user: the command follows the options
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            index += 1
            break
        name, equals, value = arg.partition("=")
        if arg in {"-h", "--help", "-V", "--version"}:
            return SuInvocation(False, None)
        if name in _SU_VALUE_LONG:
            if not equals:
                index += 1
                value = argv[index] if index < len(argv) else ""
            if name in {"--command", "--session-command"}:
                script = value
            user_mode = user_mode or name == "--user"
        elif arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            for position, letter in enumerate(arg[1:], 1):
                if letter in _SU_VALUE_LETTERS:
                    value = arg[position + 1 :]
                    if not value:
                        index += 1
                        value = argv[index] if index < len(argv) else ""
                    if letter == "c":
                        script = value
                    user_mode = user_mode or letter == "u"
                    break
        elif user_mode:
            break  # the first operand after -u starts the command
        index += 1
    if script is None and user_mode and program(argv[0]) == "runuser" and index < len(argv):
        script = shlex.join(argv[index:])
    return SuInvocation(True, script)


class SshInvocation(NamedTuple):
    connects: bool  # opens a session to ``destination`` (not -V, -G or -Q)
    remote: str | None  # the command line the remote shell runs; None for a login shell
    local: tuple[str, ...]  # -o ProxyCommand/LocalCommand/KnownHostsCommand run here
    files: tuple[str, ...]  # local files named by -i, -F, -E and -S


_SSH_VALUE_LETTERS = frozenset("BbcDEeFIiJLlmOoPpQRSWw")
_SSH_FILE_LETTERS = frozenset("iFES")
_SSH_LOCAL_COMMANDS = frozenset({"proxycommand", "localcommand", "knownhostscommand"})
_SSH_OPTION = re.compile(r"\s*([A-Za-z]+)\s*(?:=\s*|\s+)(.*)", re.S)


def ssh_invocation(argv: tuple[str, ...]) -> SshInvocation:
    """Parse OpenSSH's options, destination and remote command (joined as ssh joins them)."""
    connects = True
    remote_option = None
    local: list[str] = []
    files: list[str] = []
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            index += 1
            break
        if not arg.startswith("-") or arg == "-":
            break
        for position, letter in enumerate(arg[1:], 1):
            if letter in {"V", "G"}:
                connects = False
            if letter in _SSH_VALUE_LETTERS:
                value = arg[position + 1 :]
                if not value:
                    index += 1
                    value = argv[index] if index < len(argv) else ""
                if letter == "Q":
                    connects = False
                elif letter in _SSH_FILE_LETTERS:
                    files.append(value)
                elif letter == "o" and (match := _SSH_OPTION.match(value)):
                    key = match[1].lower()
                    if key in _SSH_LOCAL_COMMANDS:
                        local.append(match[2])
                    elif key == "remotecommand":
                        remote_option = match[2]
                break
        index += 1
    destination = argv[index] if index < len(argv) else None
    remote = " ".join(argv[index + 1 :]) or remote_option if destination else None
    return SshInvocation(connects and destination is not None, remote, tuple(local), tuple(files))


class ContainerExec(NamedTuple):
    start: int  # argv index of the command run inside the container
    files: tuple[str, ...]  # local files named by --env-file


_CONTAINER_GLOBAL_VALUES = frozenset(
    {"-H", "--host", "--config", "-c", "--context", "-l", "--log-level", "--url", "--connection"}
)
_EXEC_VALUE_LONG = frozenset(
    {"--env", "--env-file", "--user", "--workdir", "--detach-keys", "--preserve-fds"}
)
_EXEC_VALUE_LETTERS = frozenset("euw")


def container_exec(argv: tuple[str, ...]) -> ContainerExec | None:
    """Parse ``docker``/``podman`` ``exec`` (or ``container exec``); None for other commands."""
    index = 1
    while index < len(argv) and argv[index].startswith("-"):
        index += 2 if argv[index] in _CONTAINER_GLOBAL_VALUES else 1
    if argv[index : index + 2] == ("container", "exec"):
        index += 2
    elif argv[index : index + 1] == ("exec",):
        index += 1
    else:
        return None
    files: list[str] = []
    while index < len(argv) and argv[index].startswith("-"):
        arg = argv[index]
        if arg == "--":
            index += 1
            break
        name, equals, value = arg.partition("=")
        if name in _EXEC_VALUE_LONG:
            if not equals:
                index += 1
                value = argv[index] if index < len(argv) else ""
            if name == "--env-file":
                files.append(value)
        elif not arg.startswith("--"):
            for position, letter in enumerate(arg[1:], 1):
                if letter in _EXEC_VALUE_LETTERS:
                    if not arg[position + 1 :]:
                        index += 1
                    break
        index += 1
    # The container name comes next; the command after it runs in exec form.
    if index + 1 >= len(argv):
        return None
    return ContainerExec(index + 1, tuple(files))


def _here_strings(command: Command) -> list[str]:
    return [target for operator, target in command.redirects if operator == "<<<"]


# --- inspection -----------------------------------------------------------------------------


def inspect(action: ProposedAction) -> ShellPlan:
    """Inspect literal argv or conservative shell segments and known execution wrappers."""
    return _plan(action.command or "", tuple(action.argv))


@lru_cache(maxsize=64)
def _plan(source: str, argv: tuple[str, ...]) -> ShellPlan:
    if argv:
        pieces, opaque = [Command(argv)], False
    else:
        pieces, opaque = _lex(source)
    commands: list[Command] = []
    pending: list[tuple[str, int, str]] = []
    seen: set[str] = set()

    def lex_children(script: str) -> list[Command]:
        nonlocal opaque
        children, uncertain = _lex(script)
        opaque |= uncertain
        return children

    def visit(piece: Command, depth: int) -> None:
        nonlocal opaque
        if depth > _MAX_DEPTH or len(commands) >= _MAX_COMMANDS:
            opaque = True
            return
        commands.append(piece)
        for word in (*piece.words, *piece.redirect_words, *piece.assignment_words):
            for body in word.substitutions:
                if body not in seen:
                    seen.add(body)
                    pending.append((body, depth + 1, piece.context))
        if not piece.argv:
            return
        argv = piece.argv
        name = program(argv[0])
        children: list[Command] = []
        if len(argv) > 1 and "vanishable" in piece.word(0).kinds:
            # An unquoted unresolved command word may expand to nothing ("$(true) rm -rf x"),
            # making the next word the program: inspect that reading too.
            children.append(_slice(piece, 1, inherit=True))
        if name in WRAPPERS or name in _PATH_WRAPPERS:
            if name == "env" and any(arg.startswith(("-S", "--split-string")) for arg in argv[1:]):
                opaque = True
            script = _flock_script(argv) if name == "flock" else None
            if script is not None:
                children.extend(lex_children(script))
            elif (start := _wrapper_start(argv)) is not None:
                child = _slice(piece, start, inherit=True)
                if child.word(0).kinds & _COMMAND_WORD_KINDS:
                    opaque = True
                children.append(child)
        elif name in SHELLS or name in {"eval", "source", "."}:
            scripts: list[str] = []
            if name == "eval":
                arguments = list(argv[1:])
                if arguments[:1] == ["--"]:
                    arguments = arguments[1:]
                scripts.append(" ".join(arguments))
                opaque = True
            elif name in SHELLS:
                invocation = shell_invocation(argv)
                scripts.extend(invocation.scripts)
                if invocation.command_mode or invocation.reads_stdin:
                    scripts.extend(_here_strings(piece))
            elif reads_program_from_stdin(argv):
                scripts.extend(_here_strings(piece))
            for script in scripts:
                children.extend(lex_children(script))
        elif name == "xargs":
            start = _xargs_start(argv)
            if start < len(argv):
                child = replace(_slice(piece, start), piped=True)
                if child.word(0).kinds & _COMMAND_WORD_KINDS:
                    opaque = True
                children.append(child)
        elif name == "find":
            for index, arg in enumerate(argv[:-1]):
                if arg in {"-exec", "-execdir", "-ok", "-okdir"}:
                    stop = next(
                        (i for i in range(index + 1, len(argv)) if argv[i] in {";", "+"}),
                        len(argv),
                    )
                    children.append(replace(_slice(piece, index + 1, stop), piped=False))
        elif name in {"su", "runuser"}:
            su = su_invocation(argv)
            if su.script is not None:
                children.extend(lex_children(su.script))
            elif su.executes:
                # An interactive shell runs input the plan cannot see.
                opaque = True
        elif name == "ssh":
            ssh = ssh_invocation(argv)
            for script in ssh.local:
                children.extend(lex_children(script))
            if ssh.remote is not None:
                children.extend(
                    replace(child, context="remote") for child in lex_children(ssh.remote)
                )
        elif name in {"docker", "podman"}:
            exec_form = container_exec(argv)
            if exec_form is not None:
                child = replace(_slice(piece, exec_form.start), context="container")
                if child.word(0).kinds & _COMMAND_WORD_KINDS:
                    opaque = True
                children.append(child)
            elif "exec" in argv[1:]:
                opaque = True  # an exec the parser could not place
        elif (here := _here_strings(piece)) and (is_python(name) or name in CODE_INTERPRETERS):
            if reads_program_from_stdin(argv):
                flag = "-c" if is_python(name) else "-e"
                if is_python(name) or name in {"node", "nodejs", "perl", "ruby"}:
                    for code in here:
                        children.append(
                            Command(
                                (argv[0], flag, code), words=(piece.word(0), Word(flag), Word(code))
                            )
                        )
                else:
                    opaque = True
        for child in children:
            # A payload keeps its parent's context unless it names a new one (ssh, exec).
            where = child.context if child.context != "local" else piece.context
            visit(replace(child, indirect=True, context=where), depth + 1)

    for piece in pieces:
        visit(piece, 0)
    position = 0
    while position < len(pending):
        body, depth, where = pending[position]
        position += 1
        for piece in lex_children(body):
            visit(replace(piece, indirect=True, context=where), depth)
    return ShellPlan(tuple(commands), opaque)
