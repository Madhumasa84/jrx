"""Deterministic recognition of plainly destructive actions."""

from __future__ import annotations

import re
import shlex

from ..models import DeterministicFinding, EvaluationContext
from .common import action_argv, command_text


def _clear() -> DeterministicFinding:
    return DeterministicFinding(
        check="known_destructive",
        triggered=False,
        severity="low",
        reason_code="CLEAR",
    )


def _trigger(reason_code: str) -> DeterministicFinding:
    return DeterministicFinding(
        check="known_destructive",
        triggered=True,
        severity="high",
        reason_code=reason_code,
        blocking=True,
    )


def _program_name(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _rm_is_recursive_force(argv: list[str]) -> bool:
    if not argv or _program_name(argv[0]) != "rm":
        return False
    for item in argv[1:]:
        if item == "--":
            break
        if not item.startswith("-") or item == "-":
            break
        if item.startswith("--"):
            if item.split("=", 1)[0].lower() == "--recursive":
                return True
        elif "r" in item[1:].lower():
            return True
    return False


_SHELL_PROGRAMS = {"sh", "bash", "dash", "zsh", "ksh", "fish"}
_WRAPPER_PROGRAMS = {
    "command",
    "doas",
    "env",
    "exec",
    "nice",
    "nohup",
    "setsid",
    "sudo",
    "timeout",
    "xargs",
}
_EVAL_PROGRAMS = {"eval"}
_SHELL_OPERATORS = {";", "&&", "||", "|", "&"}
_INTERPRETER_SIDE_EFFECT_RE = re.compile(
    r"\b(?:os\.(?:system|popen|remove|unlink|rmdir)|"
    r"shutil\.(?:rmtree|move)|(?:pathlib\.)?path\.(?:unlink|rmdir)|"
    r"subprocess\.(?:run|popen|call|check_call|check_output)|"
    r"fs\.(?:rm|rmSync|rmdir|rmdirSync)|"
    r"child_process\.(?:exec|execFile|spawn)|remove-item)\b",
    re.IGNORECASE,
)


def _shell_tokens(value: str) -> list[str]:
    try:
        lexer = shlex.shlex(value, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return value.split()


def _is_shell_command_flag(value: str) -> bool:
    return value == "-c" or (value.startswith("-") and not value.startswith("--") and "c" in value)


def _contains_recursive_rm(argv: list[str], depth: int = 0) -> bool:
    """Recognize recursive rm through common command wrappers without executing it."""

    if not argv or depth > 4:
        return False

    segments: list[list[str]] = [[]]
    for token in argv:
        if token in _SHELL_OPERATORS:
            if segments[-1]:
                segments.append([])
        else:
            segments[-1].append(token)

    for segment in segments:
        if not segment:
            continue
        program = _program_name(segment[0])
        if program == "rm" and _rm_is_recursive_force(segment):
            return True
        if program in _SHELL_PROGRAMS:
            for index, token in enumerate(segment[1:], start=1):
                if _is_shell_command_flag(token) and index + 1 < len(segment):
                    if _contains_recursive_rm(_shell_tokens(segment[index + 1]), depth + 1):
                        return True
            continue
        if program in _EVAL_PROGRAMS:
            if any(
                _contains_recursive_rm(_shell_tokens(value), depth + 1) for value in segment[1:]
            ):
                return True
            continue
        if program in _WRAPPER_PROGRAMS:
            for index, token in enumerate(segment[1:], start=1):
                token_program = _program_name(token)
                if token_program == "rm" and _rm_is_recursive_force(segment[index:]):
                    return True
                if token_program in _SHELL_PROGRAMS | _WRAPPER_PROGRAMS:
                    if _contains_recursive_rm(segment[index:], depth + 1):
                        return True
    return False


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    """Detect actions whose destructive nature is explicit from argv."""

    argv = action_argv(context)
    text = command_text(context)
    command_argv = (
        _shell_tokens(context.proposed_action.command)
        if context.proposed_action.command is not None and not context.proposed_action.argv
        else argv
    )
    if _contains_recursive_rm(command_argv):
        return [_trigger("RECURSIVE_DELETE")]
    if _INTERPRETER_SIDE_EFFECT_RE.search(text):
        return [_trigger("INTERPRETER_SIDE_EFFECT")]
    if re.search(r"\bgit\s+reset\s+[^\n]*--hard\b", text):
        return [_trigger("GIT_HARD_RESET")]
    if re.search(r"\bgit\s+clean\s+[^\n]*-[a-z]*f[a-z]*\b", text):
        return [_trigger("GIT_CLEAN_FORCE")]
    if re.search(r"\b(?:drop\s+(?:database|table)|truncate\s+table)\b", text):
        return [_trigger("DATABASE_DESTRUCTIVE")]
    if re.search(r"\bterraform\s+destroy\b|\bkubectl\s+delete\b", text):
        return [_trigger("INFRASTRUCTURE_DELETE")]
    if re.search(r"\bdocker\s+system\s+prune\b|\bshred\b", text):
        return [_trigger("RESOURCE_PRUNE")]
    return [_clear()]
