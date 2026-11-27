"""Small allow-list of commands whose ordinary form is low impact."""

from __future__ import annotations

import re

from ..models import DeterministicFinding, EvaluationContext
from .shell import inspect

_SAFE_COMMAND_RE = re.compile(
    r"^(?:pytest(?:\s|$)|python(?:3)?\s+-m\s+compileall(?:\s|$)|"
    r"ruff\s+(?:check|format)(?:\s|$)|git\s+(?:status|diff)(?:\s|$))",
    re.IGNORECASE,
)


def _known_safe(context: EvaluationContext) -> bool:
    # Every command the shell could run must be an allow-listed literal command: a safe
    # prefix followed by "; rm ...", an opaque plan or an unresolved word is not known safe.
    plan = inspect(context.proposed_action)
    commands = [command for command in plan.commands if command.argv]
    return (
        bool(commands)
        and not plan.opaque
        and all(
            not any(command.unresolved)
            and _SAFE_COMMAND_RE.search(" ".join(command.argv).lower()) is not None
            for command in commands
        )
    )


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    if _known_safe(context):
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
