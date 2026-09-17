"""Deterministic secret redaction performed before logging or model transmission."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED_SECRET = "<REDACTED_SECRET>"

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_AUTH_HEADER_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>\b(?:authorization|proxy-authorization)\s*[:=]\s*)"
    r"(?:"
    r"(?P<quote>[\"'])[^\"'\r\n]*?(?P=quote)"
    r"|"
    r"(?P<unquoted>(?:[^\s,;\"']+\s+)?[^\s,;\"']+)"
    r")"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_KNOWN_TOKEN_RE = re.compile(
    r"(?i)\b(?:"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9][A-Za-z0-9_-]{15,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"npm_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
    r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")\b"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>\b(?:"
    r"password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|"
    r"authorization|aws_access_key_id|aws_secret_access_key|"
    r"[a-z][a-z0-9_]*(?:_token|_secret|_key|_password|_passwd|_credential)s?"
    r")\b\s*(?:=|:)\s*)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}\"']*)"
)
_URL_SECRET_RE = re.compile(r"(?i)([?&](?:token|secret|api[_-]?key|password|access_token)=)[^&\s]+")
_SECRET_FLAG_RE = re.compile(
    r"(?i)(--?(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?token|"
    r"private[_-]?key|authorization))(?:=|\s+)(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}]*)"
)


def _redact_assignment(match: re.Match[str]) -> str:
    value = match.group("value")
    if not value:
        return match.group("prefix")
    # A shell reference such as $TOKEN names a variable but does not contain its value.
    if value.startswith("$") and len(value) > 1:
        return match.group("prefix") + value
    if value.startswith('"') and value.endswith('"'):
        return match.group("prefix") + f'"{REDACTED_SECRET}"'
    if value.startswith("'") and value.endswith("'"):
        return match.group("prefix") + f"'{REDACTED_SECRET}'"
    return match.group("prefix") + REDACTED_SECRET


def _redact_flag(match: re.Match[str]) -> str:
    value = match.group(2)
    if value.startswith("$") and len(value) > 1:
        return f"{match.group(1)} {value}"
    if value.startswith('"') and value.endswith('"'):
        return f'{match.group(1)} "{REDACTED_SECRET}"'
    if value.startswith("'") and value.endswith("'"):
        return f"{match.group(1)} '{REDACTED_SECRET}'"
    return f"{match.group(1)} {REDACTED_SECRET}"


def _redact_auth_header(match: re.Match[str]) -> str:
    quote = match.group("quote")
    if quote:
        return f"{match.group('prefix')}{quote}{REDACTED_SECRET}{quote}"
    return f"{match.group('prefix')}{REDACTED_SECRET}"


def redact_text(value: str | None) -> str:
    """Redact obvious credentials without attempting to persist the original value."""

    if not value:
        return "" if value is None else value
    redacted = _PRIVATE_KEY_RE.sub(REDACTED_SECRET, str(value))
    redacted = _AUTH_HEADER_RE.sub(_redact_auth_header, redacted)
    redacted = _BEARER_RE.sub(REDACTED_SECRET, redacted)
    redacted = _KNOWN_TOKEN_RE.sub(REDACTED_SECRET, redacted)
    redacted = _SECRET_ASSIGNMENT_RE.sub(_redact_assignment, redacted)
    redacted = _SECRET_FLAG_RE.sub(_redact_flag, redacted)
    redacted = _URL_SECRET_RE.sub(rf"\1{REDACTED_SECRET}", redacted)
    return redacted


def _looks_secret_key(key: str) -> bool:
    normalized = key.upper().replace("-", "_")
    return any(
        marker in normalized
        for marker in (
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "PASSWD",
            "PRIVATE_KEY",
            "PRIVATEKEY",
            "API_KEY",
            "APIKEY",
            "CREDENTIAL",
            "AUTHORIZATION",
        )
    ) or bool(re.search(r"(?:^|_)(?:KEY|AUTH)$", normalized))


def redact_obj(value: Any, *, key: str | None = None) -> Any:
    """Recursively redact strings and values under secret-looking object keys."""

    if isinstance(value, str):
        if key and _looks_secret_key(key) and value and not value.startswith("$"):
            return REDACTED_SECRET
        return redact_text(value)
    if isinstance(value, Mapping):
        return {str(k): redact_obj(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_obj(item) for item in value]
    return value


def redact_argv(argv: Sequence[str]) -> list[str]:
    """Redact values passed as a separate argument after a secret-looking flag."""

    result: list[str] = []
    awaiting_secret = False
    for item in argv:
        text = str(item)
        if awaiting_secret:
            result.append(REDACTED_SECRET if not text.startswith("$") else text)
            awaiting_secret = False
            continue
        if re.fullmatch(
            r"(?i)--?(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?token|private[_-]?key|authorization)",
            text,
        ):
            result.append(text)
            awaiting_secret = True
            continue
        result.append(redact_text(text))
    return result
