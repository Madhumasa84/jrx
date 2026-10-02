"""Deterministic checks for known dangerous Git operations."""

from __future__ import annotations

import re
import shlex

from ..models import DeterministicFinding, EvaluationContext
from .common import action_argv, command_text


def git_operations(argv: list[str], depth: int = 0) -> list[list[str]]:
    """Find Git subcommands after global options, preserving case-sensitive flags."""
    operations: list[list[str]] = []
    if depth < 4:
        for token in argv:
            if any(char.isspace() for char in token):
                try:
                    nested = shlex.split(token)
                except ValueError:
                    continue
                operations.extend(git_operations(nested, depth + 1))
    for start, token in enumerate(argv):
        if token.rsplit("/", 1)[-1] != "git":
            continue
        index = start + 1
        while index < len(argv):
            option = argv[index]
            if option in {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--config-env"}:
                index += 2
            elif option.startswith("-"):
                index += 1
            else:
                operations.append(argv[index:])
                break
    return operations


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
    # Parse the Git invocation rather than requiring the program and subcommand
    # to be adjacent. The legacy text checks also cover shell snippets.
    for operation in git_operations(raw_argv):
        subcommand, *flags = operation
        reason = None
        if subcommand == "reset" and "--hard" in flags:
            reason = "GIT_HARD_RESET"
        elif subcommand == "push" and any(
            flag == "-f" or flag.split("=", 1)[0] in {"--force", "--force-with-lease"}
            for flag in flags
        ):
            reason = "FORCE_PUSH"
        elif subcommand == "branch":
            short = "".join(
                flag[1:] for flag in flags if flag.startswith("-") and not flag.startswith("--")
            )
            if "D" in short or (
                ("d" in short or "--delete" in flags) and ("f" in short or "--force" in flags)
            ):
                reason = "BRANCH_DELETE_FORCE"
        elif subcommand == "clean" and any(
            flag.startswith("-") and not flag.startswith("--") and "f" in flag[1:] for flag in flags
        ):
            reason = "GIT_CLEAN_FORCE"
        elif subcommand in {"filter-repo", "filter-branch"}:
            reason = "HISTORY_REWRITE"
        if reason:
            return [_finding(triggered=True, severity="high", reason_code=reason, blocking=True)]
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
