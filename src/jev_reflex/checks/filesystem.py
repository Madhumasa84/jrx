"""Deterministic filesystem, database, and migration hazard checks."""

from __future__ import annotations

import re

from ..models import DeterministicFinding, EvaluationContext
from .common import command_text

_FORMAT_RE = re.compile(
    r"\b(?:mkfs(?:\.[a-z0-9]+)?|wipefs|fdisk|parted)\b|"
    r"\bdiskutil\s+erase(?:disk|volume)\b|\bdd\b[^\n]*\bof=/dev/",
    re.IGNORECASE,
)
_DROP_RE = re.compile(r"\b(?:drop\s+(?:database|table)|delete\s+from\s+\w+)\b", re.IGNORECASE)
_IRREVERSIBLE_MIGRATION_RE = re.compile(
    r"\b(?:alembic|django-admin|rails|prisma|migrate|migration)\b[^\n]*"
    r"(?:--force|--irreversible|irreversible|destroy|reset|downgrade)",
    re.IGNORECASE,
)
_PERSISTENCE_RE = re.compile(
    r"\b(?:alembic|migrate|migration|schema|database|db|terraform|kubectl|docker)\b",
    re.IGNORECASE,
)


def _finding(
    *,
    triggered: bool,
    severity: str,
    reason_code: str,
    blocking: bool = False,
) -> DeterministicFinding:
    return DeterministicFinding(
        check="filesystem",
        triggered=triggered,
        severity=severity,  # type: ignore[arg-type]
        reason_code=reason_code,
        blocking=blocking,
    )


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    text = command_text(context)
    if _FORMAT_RE.search(text):
        return [
            _finding(
                triggered=True, severity="high", reason_code="FILESYSTEM_FORMAT", blocking=True
            )
        ]
    if _DROP_RE.search(text):
        return [
            _finding(
                triggered=True, severity="high", reason_code="PERSISTENT_DELETE", blocking=True
            )
        ]
    if _IRREVERSIBLE_MIGRATION_RE.search(text):
        return [
            _finding(
                triggered=True, severity="high", reason_code="IRREVERSIBLE_MIGRATION", blocking=True
            )
        ]
    if _PERSISTENCE_RE.search(text):
        return [_finding(triggered=True, severity="medium", reason_code="PERSISTENCE_ACTION")]
    return [_finding(triggered=False, severity="low", reason_code="CLEAR")]
