"""Deterministic recognition of plainly destructive actions."""

from __future__ import annotations

import re

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


def _rm_is_recursive_force(argv: list[str]) -> bool:
    if not argv or argv[0].lower() != "rm":
        return False
    flags = "".join(item[1:] for item in argv[1:] if item.startswith("-") and item != "--")
    return "r" in flags.lower()


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    """Detect actions whose destructive nature is explicit from argv."""

    argv = action_argv(context)
    text = command_text(context)
    if _rm_is_recursive_force(argv):
        return [_trigger("RECURSIVE_DELETE")]
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
