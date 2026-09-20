"""Deterministic secret redaction performed before logging or model transmission."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import warnings
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
_SECRET_FLAG_RE = re.compile(
    r"(?ix)(?P<flag>(?<!\S)--?"
    r"(?:[a-z0-9]+[_-])*(?:password|passwd|passphrase|secret|token|api[_-]?key|"
    r"access[_-]?token|private[_-]?key|authorization)(?:[_-][a-z0-9]+)*"
    r")(?:=|\s+)(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}]*)"
)
_USERPASS_FLAG_RE = re.compile(
    r"(?ix)(?P<flag>(?<!\S)--?user(?:name)?|-u)(?:=|\s+)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}]*)"
)
_USERPASS_ATTACHED_RE = re.compile(r"(?i)(?P<flag>(?<!\S)-u)(?P<value>[^\s,;}]+)")
_URL_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|secret|api[_-]?key|password|access[_-]?token|"
    r"client[_-]?secret|private[_-]?key|auth|key)=)[^&\s]+"
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
    value = match.group("value")
    if value.startswith("$") and len(value) > 1:
        return f"{match.group('flag')} {value}"
    if value.startswith('"') and value.endswith('"'):
        return f'{match.group("flag")} "{REDACTED_SECRET}"'
    if value.startswith("'") and value.endswith("'"):
        return f"{match.group('flag')} '{REDACTED_SECRET}'"
    return f"{match.group('flag')} {REDACTED_SECRET}"


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
    redacted = _USERPASS_FLAG_RE.sub(_redact_flag, redacted)
    redacted = _USERPASS_ATTACHED_RE.sub(_redact_flag, redacted)
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
            r"(?i)--?(?:[a-z0-9]+[_-])*(?:password|passwd|passphrase|secret|token|api[_-]?key|"
            r"access[_-]?token|private[_-]?key|authorization)(?:[_-][a-z0-9]+)*",
            text,
        ) or re.fullmatch(r"(?i)--?user(?:name)?|-u", text):
            result.append(text)
            awaiting_secret = True
            continue
        result.append(redact_text(text))
    return result


# Gitleaks integration
_GITLEAKS_AVAILABLE = None
_GITLEAKS_WARNING_SHOWN = False


def _check_gitleaks_available() -> bool:
    """Check if gitleaks is available on PATH."""
    global _GITLEAKS_AVAILABLE, _GITLEAKS_WARNING_SHOWN

    if _GITLEAKS_AVAILABLE is not None:
        return _GITLEAKS_AVAILABLE

    _GITLEAKS_AVAILABLE = shutil.which("gitleaks") is not None

    if not _GITLEAKS_AVAILABLE and not _GITLEAKS_WARNING_SHOWN:
        _GITLEAKS_WARNING_SHOWN = True
        warnings.warn(
            "gitleaks not found, falling back to regex-only redaction — see docs/security.md",
            UserWarning,
            stacklevel=2,
        )

    return _GITLEAKS_AVAILABLE


class GitleaksRedactor:
    """Redactor that uses gitleaks to detect secrets."""

    def __init__(self, timeout: float = 10.0) -> None:
        """Initialize the gitleaks redactor.

        Args:
            timeout: Maximum time in seconds to wait for gitleaks scan.
        """
        self.timeout = timeout
        self._available = _check_gitleaks_available()

    def redact(self, text: str) -> tuple[str, bool]:
        """Redact secrets in text using gitleaks.

        Args:
            text: The text to redact.

        Returns:
            (redacted_text, failed) where failed is True if gitleaks failed.
        """
        if not self._available:
            return redact_text(text), False

        try:
            # Run gitleaks detect on stdin
            result = subprocess.run(
                ["gitleaks", "detect", "--no-git", "--report-format", "json", "--source", "-"],
                input=text,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if result.returncode != 0:
                # Gitleaks failed - fail toward more redaction
                return REDACTED_SECRET, True

            # Parse JSON output
            try:
                findings = json.loads(result.stdout)
            except json.JSONDecodeError:
                # Invalid JSON - fail toward more redaction
                return REDACTED_SECRET, True

            if not isinstance(findings, list):
                return REDACTED_SECRET, True

            # Apply redactions based on findings
            redacted = text
            offset = 0

            # Sort findings by start position to apply in order
            findings.sort(key=lambda f: f.get("startLine", 0) * 1000 + f.get("startColumn", 0))

            for finding in findings:
                start_line = finding.get("startLine", 0)
                start_column = finding.get("startColumn", 0)
                end_line = finding.get("endLine", 0)
                end_column = finding.get("endColumn", 0)

                # Convert line/column to character offsets
                lines = redacted.split("\n")
                if start_line >= len(lines) or end_line >= len(lines):
                    continue

                # Calculate start position
                start_pos = sum(len(line) + 1 for line in lines[:start_line]) + start_column
                # Calculate end position
                end_pos = sum(len(line) + 1 for line in lines[:end_line]) + end_column

                if start_pos >= len(redacted) or end_pos > len(redacted):
                    continue

                # Redact the span
                redacted = redacted[:start_pos] + REDACTED_SECRET + redacted[end_pos:]
                offset += len(REDACTED_SECRET) - (end_pos - start_pos)

            return redacted, False

        except subprocess.TimeoutExpired:
            # Timeout - fail toward more redaction
            return REDACTED_SECRET, True
        except Exception:
            # Any other error - fail toward more redaction
            return REDACTED_SECRET, True


_gitleaks_redactor: GitleaksRedactor | None = None


def _get_gitleaks_redactor() -> GitleaksRedactor:
    """Get or create the singleton gitleaks redactor."""
    global _gitleaks_redactor
    if _gitleaks_redactor is None:
        _gitleaks_redactor = GitleaksRedactor()
    return _gitleaks_redactor


def redact_text_with_gitleaks(value: str | None) -> tuple[str, bool]:
    """Redact text using both gitleaks and regex patterns.

    Args:
        value: The text to redact.

    Returns:
        (redacted_text, gitleaks_failed) where gitleaks_failed is True if gitleaks failed.
    """
    if not value:
        return "" if value is None else value, False

    # First apply regex redaction (always runs)
    regex_redacted = redact_text(value)

    # Then apply gitleaks if available
    gitleaks_redactor = _get_gitleaks_redactor()
    if gitleaks_redactor._available:
        gitleaks_redacted, failed = gitleaks_redactor.redact(regex_redacted)
        return gitleaks_redacted, failed

    return regex_redacted, False
