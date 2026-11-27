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
from .common import absolute_path, inplace_files, roots
from .shell import Command, inspect, program

_ENV_REFERENCE = re.compile(
    r"(?i)\$\{?(?:[a-z0-9_]*(?:token|secret|password|passwd|api[_-]?key|private[_-]?key)"
    r"|aws_access_key_id|aws_secret_access_key)\b"
)
# A variable name that ``$NAME`` would flag through ``_ENV_REFERENCE``.
_SECRET_NAME = re.compile(
    r"(?i)[a-z0-9_]*(?:token|secret|password|passwd|api_?key|private_?key)"
    r"|aws_access_key_id|aws_secret_access_key"
)
# Programs that print file contents (all operands are files).
_READERS = frozenset(
    {
        "cat",
        "tac",
        "nl",
        "head",
        "tail",
        "bat",
        "batcat",
        "less",
        "more",
        "most",
        "view",
        "base64",
        "base32",
        "basenc",
        "xxd",
        "od",
        "hexdump",
        "hd",
        "strings",
        "rev",
        "fold",
        "column",
        "paste",
        "cut",
        "sort",
        "uniq",
        "diff",
        "cmp",
        "comm",
        "iconv",
        "expand",
        "fmt",
        "pr",
    }
)
# Programs whose first operand is a pattern or program unless an option supplies it.
_PATTERN_READERS = {
    "grep": {"-e", "--regexp", "-f", "--file"},
    "egrep": {"-e", "--regexp", "-f", "--file"},
    "fgrep": {"-e", "--regexp", "-f", "--file"},
    "rg": {"-e", "--regexp", "-f", "--file"},
    "ag": set(),
    "awk": {"-f", "--file"},
    "gawk": {"-f", "--file"},
    "mawk": {"-f"},
    "nawk": {"-f"},
    "sed": {"-e", "--expression", "-f", "--file"},
    "jq": {"-f", "--from-file"},
    "yq": set(),
}
_DECLARATIONS = {"declare", "typeset", "readonly", "local", "export"}
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


def _read_paths(command: Command) -> list[str]:
    """Files whose contents a command prints: reader operands and input redirects."""

    paths = [target for operator, target in command.redirects if operator in {"<", "<>"}]
    if not command.argv:
        return paths
    name, args = program(command.argv[0]), command.argv[1:]
    if name in _READERS or name in _PATTERN_READERS:
        if name == "sed" and inplace_files(name, args) is not None:
            return paths
        operands = [arg for arg in args if not arg.startswith("-") or arg == "-"]
        supplied = _PATTERN_READERS.get(name)
        if supplied is not None and not any(
            arg.split("=", 1)[0] in supplied
            or (len(arg) > 2 and arg[0] == "-" and arg[1] in "ef" and name != "jq")
            for arg in args
        ):
            operands = operands[1:]
        paths += operands
    return paths


def _direct_disclosure(context: EvaluationContext) -> bool:
    from .repo_boundary import input_paths

    direct = (
        path
        for command in inspect(context.proposed_action).commands
        for path in _read_paths(command)
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


def _environment_disclosure(context: EvaluationContext) -> str:
    """``printenv SECRET`` prints a secret; ``env``/``export -p`` print every variable."""

    dump = False
    for command in inspect(context.proposed_action).commands:
        if not command.argv:
            continue
        name, args = program(command.argv[0]), command.argv[1:]
        options = [arg for arg in args if arg.startswith(("-", "+")) and arg != "--"]
        names = [arg.split("=", 1)[0] for arg in args if not arg.startswith(("-", "+"))]
        if name == "printenv":
            if any(_SECRET_NAME.fullmatch(item) for item in names):
                return "SECRET_ENV_REFERENCE"
            dump |= not names
        elif name in _DECLARATIONS:
            printing = any("p" in option[1:] for option in options if not option.startswith("--"))
            if printing and any(_SECRET_NAME.fullmatch(item) for item in names):
                return "SECRET_ENV_REFERENCE"
            # ``declare``/``typeset`` alone list every variable; ``export``,
            # ``readonly`` and ``local`` list them with no operand or with ``-p``.
            listing = (
                printing
                or not options
                or (name in {"declare", "typeset"} and not {"-f", "-F"} & set(options))
            )
            dump |= not names and listing
        elif name == "env":
            index = 0
            while index < len(args):
                word = args[index]
                if word in {"-u", "--unset", "-C", "--chdir"}:
                    index += 2
                elif word.startswith("-") or "=" in word:
                    index += 1
                else:
                    break
            dump |= index >= len(args) and not any(
                word.startswith(("-S", "--split-string")) for word in args
            )
        elif name == "set" and not args:
            dump = True
    return "ENVIRONMENT_DISCLOSURE" if dump else ""


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
    environment = "" if reason else _environment_disclosure(context)
    if environment == "SECRET_ENV_REFERENCE":
        reason = environment
    if not reason and (environment or _direct_disclosure(context)):
        return [
            DeterministicFinding(
                check="secret_pattern",
                triggered=True,
                severity="medium",
                reason_code=environment or "CREDENTIAL_FILE_DISCLOSURE",
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
