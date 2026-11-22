"""Credential evidence for local detection and session output tracking."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from pathlib import Path

from ..models import DeterministicFinding, EvaluationContext
from ..redaction import (
    _BEARER_RE,
    _KNOWN_TOKEN_RE,
    _SECRET_ASSIGNMENT_RE,
    _SECRET_FLAG_RE,
    _USERPASS_ATTACHED_RE,
    _USERPASS_FLAG_RE,
    REDACTED_SECRET,
    looks_secret_key,
)
from .common import absolute_path, roots
from .shell import inspect, program

_ENV_REFERENCE = re.compile(
    r"(?i)\$\{?(?:[a-z0-9_]*(?:token|secret|password|passwd|api[_-]?key|private[_-]?key)"
    r"|aws_access_key_id|aws_secret_access_key)\b"
)
_PRIVATE_HEADER = re.compile(
    r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----"
    r"|-----BEGIN PGP PRIVATE KEY BLOCK-----",
    re.I,
)
_AUTH_VALUE = re.compile(
    r"""(?i)\b(?:authorization|proxy-authorization)\s*[:=]\s*["']?"""
    r"""(?:(?:basic|bearer|token)\s+)?(?P<value>[A-Za-z0-9._~+/=-]+)"""
)
_URL_VALUE = re.compile(
    r"(?i)[?&](?:token|secret|api[_-]?key|password|access[_-]?token|"
    r"client[_-]?secret|private[_-]?key|auth|key)=(?P<value>[^&\s\"']+)"
)
_PLACEHOLDER = re.compile(
    r"<[^<>]*>|\{\{[^{}]*\}\}|(?:replace|change)[-_]?me|"
    r"(?:unused|sample|example|placeholder|dummy|test)[-_](?:value|example|placeholder)|"
    r"sk[-_]test[-_]placeholder",
    re.I,
)


def concrete_credential_value(value: str) -> bool:
    return bool(
        value
        and not value.startswith("$")
        and value != REDACTED_SECRET
        and value != "AKIAIOSFODNN7EXAMPLE"
        and not _PLACEHOLDER.fullmatch(value)
    )


def sensitive_credential_path(path: Path, home: Path) -> bool:
    name = path.name.casefold()
    return (
        name == ".env"
        or (name.startswith(".env.") and name != ".env.example")
        or path.suffix.casefold() in {".pem", ".key"}
        or path.is_relative_to(home / ".ssh")
        and path != home / ".ssh"
        or path in {home / ".aws/credentials", home / ".kube/config"}
    )


def _direct_disclosure(context: EvaluationContext) -> bool:
    from .repo_boundary import input_paths

    direct = (
        arg
        for command in inspect(context.proposed_action).commands
        if command.argv and program(command.argv[0]) in {"cat", "head", "tail", "bat"}
        for arg in command.argv[1:]
        if not arg.startswith("-")
    )
    payload = context.proposed_action.input
    paths = list(direct)
    if isinstance(payload, Mapping) and any(
        payload.get(key) is True for key in ("attach_values", "include_values", "return_plaintext")
    ):
        paths += input_paths(payload) + [
            item for key, item in structured_text(payload) if key in {"include", "files"}
        ]
    if not paths:
        return False
    try:
        cwd, _ = roots(context)
        home = Path.home()
        return any(sensitive_credential_path(absolute_path(path, cwd), home) for path in paths)
    except (OSError, RuntimeError, ValueError):
        return False


def credential_values(text: str) -> Iterator[tuple[str, str]]:
    """Yield credential values with concrete evidence. Never match prefix-only labels."""
    for match in _KNOWN_TOKEN_RE.finditer(text):
        if concrete_credential_value(match[0]):
            yield "KNOWN_TOKEN_PATTERN", match[0]
    for match in _BEARER_RE.finditer(text):
        value = match[0].split(maxsplit=1)[1]
        if concrete_credential_value(value):
            yield "AUTHORIZATION_HEADER", value
    for match in _AUTH_VALUE.finditer(text):
        value = match["value"]
        if concrete_credential_value(value) and value.lower() not in {"bearer", "basic", "token"}:
            yield "AUTHORIZATION_HEADER", value
    for regex, reason in (
        (_SECRET_ASSIGNMENT_RE, "SECRET_ASSIGNMENT"),
        (_SECRET_FLAG_RE, "SECRET_PATTERN"),
        (_URL_VALUE, "SECRET_PATTERN"),
    ):
        for match in regex.finditer(text):
            if reason == "SECRET_ASSIGNMENT" and match["prefix"].lower().strip().startswith(
                ("authorization", "proxy-authorization")
            ):
                continue
            value = match["value"].strip("'\"")
            if concrete_credential_value(value):
                yield reason, value
    for regex in (_USERPASS_FLAG_RE, _USERPASS_ATTACHED_RE):
        for match in regex.finditer(text):
            _, separator, value = match["value"].strip("'\"").partition(":")
            if separator and concrete_credential_value(value):
                yield "SECRET_PATTERN", value


def structured_text(value: object, *, key: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield key, value
    elif isinstance(value, Mapping):
        for name, item in value.items():
            yield from structured_text(item, key=str(name))
    elif isinstance(value, list | tuple):
        for item in value:
            yield from structured_text(item, key=key)


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    action = context.proposed_action
    reason = ""
    if _ENV_REFERENCE.search(action.display()):
        reason = "SECRET_ENV_REFERENCE"
    else:
        sources = (
            ("", action.display()),
            ("", context.user_task),
            ("", context.git_diff),
            ("", context.test_results),
            ("", context.recent_context),
            ("", context.external_content),
            *structured_text(action.input),
        )
        for key, text in sources:
            if _PRIVATE_HEADER.search(text):
                reason = "PRIVATE_KEY_BLOCK"
            elif (found := next(credential_values(text), None)) is not None:
                reason = found[0]
            elif key and looks_secret_key(key) and concrete_credential_value(text):
                reason = "SECRET_ASSIGNMENT"
            if reason:
                break
    if not reason and _direct_disclosure(context):
        return [
            DeterministicFinding(
                check="secret_pattern",
                triggered=True,
                severity="medium",
                reason_code="CREDENTIAL_FILE_DISCLOSURE",
            )
        ]
    return [
        DeterministicFinding(
            check="secret_pattern",
            triggered=bool(reason),
            severity="high" if reason else "low",
            reason_code=reason or "CLEAR",
            blocking=bool(reason),
        )
    ]
