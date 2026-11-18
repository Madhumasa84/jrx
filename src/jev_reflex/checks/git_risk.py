"""Deterministic checks for known dangerous Git operations."""

from __future__ import annotations

import re

from ..models import DeterministicFinding, EvaluationContext
from .common import GIT_COMMAND_PREFIX, git_command_text, git_option_sets


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
    raw_text = git_command_text(context)
    text = raw_text.lower()
    for subcommand, options, reason in (
        ("reset", {"--hard"}, "GIT_HARD_RESET"),
        ("clean", {"-f", "--force"}, "GIT_CLEAN_FORCE"),
    ):
        if any(flags & options for flags in git_option_sets(context, subcommand)):
            return [_finding(triggered=True, severity="high", reason_code=reason, blocking=True)]
    if any(
        flags & {"-f", "--force", "--force-with-lease", "--force-if-includes"}
        for flags in git_option_sets(context, "push")
    ) or re.search(GIT_COMMAND_PREFIX + r"push\b[^\n;&|]*\s\+\S+", text):
        return [_finding(triggered=True, severity="high", reason_code="FORCE_PUSH", blocking=True)]
    if any(
        "-D" in flags or (flags & {"-d", "--delete"} and flags & {"-f", "--force"})
        for flags in git_option_sets(context, "branch")
    ):
        return [
            _finding(
                triggered=True, severity="high", reason_code="BRANCH_DELETE_FORCE", blocking=True
            )
        ]
    if re.search(GIT_COMMAND_PREFIX + r"(?:filter-repo|filter-branch)\b", text) or any(
        flags & {"-i", "--interactive"} for flags in git_option_sets(context, "rebase")
    ):
        return [
            _finding(triggered=True, severity="high", reason_code="HISTORY_REWRITE", blocking=True)
        ]
    if any("--amend" in flags for flags in git_option_sets(context, "commit")):
        return [_finding(triggered=True, severity="medium", reason_code="COMMIT_AMEND")]
    if re.search(GIT_COMMAND_PREFIX + r"(?:status|diff)\b", text):
        return [_finding(triggered=False, severity="low", reason_code="KNOWN_SAFE_GIT")]
    return [_finding(triggered=False, severity="low", reason_code="CLEAR")]
