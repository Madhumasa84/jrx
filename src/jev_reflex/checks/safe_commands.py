"""Small allow-list of commands whose ordinary form is low impact."""

from __future__ import annotations

import re

from ..models import DeterministicFinding, EvaluationContext
from .common import command_text

_SAFE_COMMAND_RE = re.compile(
    r"^(?:pytest(?:\s|$)|python(?:3)?\s+-m\s+compileall(?:\s|$)|"
    r"ruff\s+(?:check|format)(?:\s|$)|git\s+(?:status|diff)(?:\s|$))",
    re.IGNORECASE,
)


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    if _SAFE_COMMAND_RE.search(command_text(context)):
        return [
            DeterministicFinding(
                check="safe_command",
                triggered=False,
                severity="low",
                reason_code="KNOWN_SAFE_COMMAND",
            )
        ]
    return [
        DeterministicFinding(
            check="safe_command",
            triggered=False,
            severity="low",
            reason_code="NOT_ALLOWLISTED",
        )
    ]
