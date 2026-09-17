"""Deterministic secret exposure checks with reason codes only."""

from __future__ import annotations

import re

from ..models import DeterministicFinding, EvaluationContext
from ..redaction import redact_text

_ENV_SECRET_REFERENCE_RE = re.compile(
    r"(?i)(?:\$\{?)(?:[a-z0-9_]*(?:token|secret|password|passwd|api[_-]?key|private[_-]?key)|"
    r"aws_access_key_id|aws_secret_access_key)(?:\}?)"
)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)
_AUTH_HEADER_RE = re.compile(r"(?i)\b(?:authorization|proxy-authorization)\s*[:=]")
_KNOWN_TOKEN_RE = re.compile(r"(?i)\b(?:gh[pousr]_|github_pat_|sk-|xox[baprs]-|npm_|AKIA|ASIA|eyJ)")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?ix)\b(?:password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|"
    r"[a-z][a-z0-9_]*(?:_token|_secret|_key|_password|_passwd|_credential)s?)\b\s*(?:=|:)"
)


def _clear() -> DeterministicFinding:
    return DeterministicFinding(
        check="secret_pattern",
        triggered=False,
        severity="low",
        reason_code="CLEAR",
    )


def _trigger(reason_code: str) -> DeterministicFinding:
    return DeterministicFinding(
        check="secret_pattern",
        triggered=True,
        severity="high",
        reason_code=reason_code,
        blocking=True,
    )


def _context_text(context: EvaluationContext) -> str:
    action = context.proposed_action.display()
    action_input = (
        "" if context.proposed_action.input is None else str(context.proposed_action.input)
    )
    return "\n".join(
        (
            context.user_task,
            action,
            action_input,
            " ".join(context.changed_files),
            context.git_diff,
            context.test_results,
            context.recent_context,
            context.external_content,
        )
    )


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    text = _context_text(context)
    if _PRIVATE_KEY_RE.search(text):
        return [_trigger("PRIVATE_KEY_BLOCK")]
    if _AUTH_HEADER_RE.search(text):
        return [_trigger("AUTHORIZATION_HEADER")]
    if _KNOWN_TOKEN_RE.search(text):
        return [_trigger("KNOWN_TOKEN_PATTERN")]
    if _ENV_SECRET_REFERENCE_RE.search(text):
        return [_trigger("SECRET_ENV_REFERENCE")]
    if _SECRET_ASSIGNMENT_RE.search(text):
        return [_trigger("SECRET_ASSIGNMENT")]

    # Keep the redaction implementation and deterministic check aligned for future
    # pattern additions without exposing the matched content.
    if redact_text(text) != text:
        return [_trigger("SECRET_PATTERN")]
    return [_clear()]
