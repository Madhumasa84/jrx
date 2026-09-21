"""Deterministic checks for known dangerous Git operations."""

from __future__ import annotations

import re

from ..models import DeterministicFinding, EvaluationContext
from .common import action_argv, command_text


def _finding(
    *,
    triggered: bool,
    severity: str,
    reason_code: str,
    blocking: bool = False,
) -> DeterministicFinding:
    return DeterministicFinding(
        check="git_risk",
        triggered=triggered,
        severity=severity,  # type: ignore[arg-type]
        reason_code=reason_code,
        blocking=blocking,
    )


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    text = command_text(context)
    raw_argv = action_argv(context)
    raw_text = " ".join(raw_argv)
    if re.search(r"\bgit\s+push\b[^\n]*(?:--force(?:-with-lease)?|\s-f(?:\s|$))", text):
        return [_finding(triggered=True, severity="high", reason_code="FORCE_PUSH", blocking=True)]
    if re.search(r"\bgit\s+branch\b[^\n]*\s-D(?:\s|$)", raw_text) or re.search(
        r"\bgit\s+branch\b[^\n]*(?:--delete|-d)\b[^\n]*(?:--force|-f)\b", text
    ):
        return [
            _finding(
                triggered=True, severity="high", reason_code="BRANCH_DELETE_FORCE", blocking=True
            )
        ]
    if re.search(r"\bgit\s+(?:filter-repo|filter-branch|rebase\s+-i)\b", text):
        return [
            _finding(triggered=True, severity="high", reason_code="HISTORY_REWRITE", blocking=True)
        ]
    if re.search(r"\bgit\s+commit\b[^\n]*--amend\b", text):
        return [_finding(triggered=True, severity="medium", reason_code="COMMIT_AMEND")]
    if re.search(r"\bgit\s+(?:status|diff)\b", text):
        return [_finding(triggered=False, severity="low", reason_code="KNOWN_SAFE_GIT")]
    return [_finding(triggered=False, severity="low", reason_code="CLEAR")]
