"""Deterministic secret redaction performed before logging or model transmission.

Redaction runs on agent-controlled text before a policy decision is made, so every
scan in this module must stay linear in the size of its input. Patterns avoid
ambiguous nested quantifiers, use possessive quantifiers where a match cannot need
to give characters back, and restrict where a match may start so that no region of
the input is rescanned once per candidate start position.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import warnings
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

REDACTED_SECRET = "<REDACTED_SECRET>"

# ---------------------------------------------------------------------------
# Patterns shared with checks/secrets.py. Keep their group names and matching
# behaviour stable; only their worst-case running time may change.
# ---------------------------------------------------------------------------

_BEARER_RE = re.compile(r"(?i)\bbearer\s++[A-Za-z0-9._~+/=-]+")
_KNOWN_TOKEN_RE = re.compile(
    r"(?i)\b(?:"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9][A-Za-z0-9_-]{15,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"npm_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
    # A JWT starts a base64url run; starting inside one would rescan the run once
    # per "eyJ" occurrence (quadratic on "eyJ-eyJ-...").
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{20,}+\.[A-Za-z0-9_-]{10,}+\.[A-Za-z0-9_-]{10,}"
    r")\b"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>\b(?:"
    r"password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|"
    r"authorization|aws_access_key_id|aws_secret_access_key|"
    r"[a-z][a-z0-9_]*(?:_token|_secret|_key|_password|_passwd|_credential)s?"
    r")\b\s*(?:=|:)\s*)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}\"']+(?=[\s,;}\"']|$))"
    r"(?!\s*=)"
)
# The flag must contain a credential word as whole dash/underscore components.
# The lookahead checks that while the token itself is consumed possessively, so a
# long flag such as "--token-token-...-token!" is scanned once instead of once per
# credential word it contains.
_SECRET_FLAG_RE = re.compile(
    r"(?i)(?<!\S)"
    r"(?=--?(?:[a-z0-9]+[_-])*"
    r"(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?token|"
    r"private[_-]?key|authorization)(?![a-z0-9]))"
    r"(?P<flag>--?[a-z0-9]++(?:[_-][a-z0-9]++)*+)"
    r"(?:=|\s+)(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}]*)"
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

# ---------------------------------------------------------------------------
# Redaction scanners
# ---------------------------------------------------------------------------

_PEM_BEGIN_RE = re.compile(r"-----BEGIN [A-Z0-9 ]{0,64}PRIVATE KEY(?: BLOCK)?-----", re.I)
_PEM_END_RE = re.compile(r"-----END [A-Z0-9 ]{0,64}PRIVATE KEY(?: BLOCK)?-----", re.I)

# A key starts where no identifier character precedes it. "-" may precede a key
# (X-Api-Key, -Dspring.datasource.password) but is not part of the matched key, so
# the compound name is recovered by a bounded backward scan instead of by letting
# every "-" start a fresh, overlapping match.
_KEY_VALUE_RE = re.compile(
    r"(?<![A-Za-z0-9_.])"
    r"(?P<key>[A-Za-z0-9_][A-Za-z0-9_.]*+)"
    r"(?P<close>\\?[\"'])?+"
    r"\s*+(?:=>|:=|!==?|={1,3}|:(?!:))\s*+"
)
# Every credential name ends in a component containing one of these words.
_CREDENTIAL_HINT_RE = re.compile(r"(?i)pass|pwd|secret|token|key|auth|credential|cookie")
_COMPOUND_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_MAX_KEY_CONTEXT = 256

_QUOTED_VALUE = (
    r"(?P<dq>\"(?P<dqi>(?:[^\"\\\r\n]|\\[^\r\n])*+)(?P<dqc>\"|\\?(?=[\r\n])|\\?\Z))"
    r"|(?P<sq>'(?P<sqi>[^'\r\n]*+)(?P<sqc>'|(?=[\r\n])|\Z))"
    r"|(?P<eq>\\\"(?P<eqi>(?:[^\"\\\r\n]|\\[^\"\r\n])*+)(?P<eqc>\\?\"|\\?(?=[\r\n])|\\?\Z))"
)
# Assignment values stop at structural delimiters. A comma only ends the value when
# a delimiter or the end follows it, so "password=abc,REST" is redacted whole.
_ASSIGNMENT_VALUE_RE = re.compile(
    _QUOTED_VALUE + r"|(?P<bare>(?:[^\s,;}\"'\\]|\\[^\r\n]|,(?=[^\s,;}\"']))++)"
)
# Command-line values are shell words; embedded quotes belong to the word.
_FLAG_VALUE_RE = re.compile(_QUOTED_VALUE + r"|(?P<bare>(?:[^\s,;}\\]|\\[^\r\n]|,(?=[^\s,;}]))++)")
_LABEL_FOLLOWS_RE = re.compile(r"\s*+=")
_AUTH_SECOND_TOKEN_RE = re.compile(r"[ \t]++(?:[^\s,;}\"'\\]|\\[^\r\n]|,(?=[^\s,;}\"']))++")
_AUTH_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9._+-]{0,63}")
_SHELL_VARIABLE_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})")

_FLAG_TOKEN_RE = re.compile(r"--?[A-Za-z0-9][A-Za-z0-9_-]*+")
_FLAG_RE = re.compile(r"(?<!\S)(?P<flag>--?[A-Za-z0-9][A-Za-z0-9_-]*+)(?P<sep>=|\s++)")
_FLAG_SECRET_WORD_RE = re.compile(
    r"-(?:password|passwd|passphrase|secret|token|api-?key|access-?token|private-?key|"
    r"authorization|cookie)-"
)
_USER_FLAG_RE = re.compile(r"(?i)(?<!\S)(?:--user(?:name)?(?:=|\s++)|-u(?:=|\s*+))")

_URL_USERINFO_RE = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*+://[^\s/?#@:\"'<>\\]*+:")
# Userinfo ends where the authority ends; RFC 3986 parsers split on the last "@".
_URL_AUTHORITY_END_RE = re.compile(r"[\s\"'<>/?#\\]")

_PASSWORD_COMMAND_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])(?:[A-Za-z0-9_.-]*+/)*+"
    r"(?P<cmd>mysql(?:dump|admin|import|show|check|pump|binlog|slap|sh)?|"
    r"mariadb(?:-?(?:dump|admin|import|show|check|slap))?|sshpass|redis-cli|"
    r"(?:docker|podman|nerdctl|buildah|skopeo|oras)[ \t]++login)"
    r"(?![A-Za-z0-9_.-])"
)
_COMMAND_SEGMENT_END_RE = re.compile(r"[\r\n;|&]")
_ATTACHED_P_RE = re.compile(
    r"(?<!\S)-p(?P<attached>\"(?:[^\"\\\r\n]|\\[^\r\n])*+\"?|'[^'\r\n]*+'?|[^\s\"']\S*+)"
)
_OPTION_VALUE = (
    r"(?:(?P<attached>[^\s\"']\S*+|\"[^\"\r\n]*+\"?|'[^'\r\n]*+'?)"
    r"|[ \t]++(?P<separate>\"[^\"\r\n]*+\"?|'[^'\r\n]*+'?|[^\s\"']\S*+))"
)
_OPTION_P_RE = re.compile(r"(?<!\S)-p" + _OPTION_VALUE)
_OPTION_A_RE = re.compile(r"(?<!\S)-a" + _OPTION_VALUE)
_PASSWORD_COMMANDS = frozenset(
    {"mysql", "mysqldump", "mysqladmin", "mysqlimport", "mysqlshow", "mysqlcheck"}
    | {"mysqlpump", "mysqlbinlog", "mysqlslap", "mysqlsh", "mariadb"}
    | {f"mariadb{sep}{tool}" for sep in ("", "-") for tool in ("dump", "admin", "import")}
    | {f"mariadb{sep}{tool}" for sep in ("", "-") for tool in ("show", "check", "slap")}
)
_LOGIN_TOOLS = frozenset({"docker", "podman", "nerdctl", "buildah", "skopeo", "oras"})

_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_KEY_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_CREDENTIAL_WORDS = frozenset(
    {
        "PASSWORD",
        "PASSWORDS",
        "PASSWD",
        "PASSPHRASE",
        "PWD",
        "SECRET",
        "SECRETS",
        "TOKEN",
        "TOKENS",
        "CREDENTIAL",
        "CREDENTIALS",
        "AUTHORIZATION",
        "AUTH",
        "APIKEY",
        "APIKEYS",
        "PRIVATEKEY",
        "COOKIE",
        "COOKIES",
    }
)
_CREDENTIAL_SUFFIXES = ("PASSWORD", "PASSWD", "PASSPHRASE", "SECRET", "TOKEN")
# PWD and OLDPWD name the shell's working directories, not a database password.
_NOT_CREDENTIAL_KEYS = frozenset({"PWD", "OLDPWD"})


def _key_parts(key: str) -> list[str]:
    spaced = _CAMEL_BOUNDARY_RE.sub("_", key[-_MAX_KEY_CONTEXT:])
    return [part for part in _KEY_SPLIT_RE.split(spaced.upper()) if part]


def names_credential(key: str) -> bool:
    """Whether a key, variable or header name designates a credential value.

    The credential word must end the name (``db_password``, ``accessKey``,
    ``X-Api-Key``, ``PGPASSWORD``), so identifiers such as ``password_reset`` or
    ``secretName`` are not treated as assignments of a secret.
    """

    if key in _NOT_CREDENTIAL_KEYS:
        return False
    parts = _key_parts(key)
    if not parts:
        return False
    last = parts[-1]
    if last in _CREDENTIAL_WORDS or last.endswith(_CREDENTIAL_SUFFIXES):
        return True
    if last == "KEY" and len(parts) > 1:
        return True
    return parts[-3:] == ["ACCESS", "KEY", "ID"]


def _is_shell_variable(value: str) -> bool:
    return _SHELL_VARIABLE_RE.fullmatch(value) is not None


def _redacted_value(match: re.Match[str]) -> str | None:
    """Return the replacement for a parsed value, or None to keep it."""

    if match.group("dq") is not None:
        if _is_shell_variable(match.group("dqi")):
            return None
        return '"' + REDACTED_SECRET + ('"' if match.group("dqc") == '"' else "")
    if match.group("sq") is not None:
        if _is_shell_variable(match.group("sqi")):
            return None
        return "'" + REDACTED_SECRET + ("'" if match.group("sqc") == "'" else "")
    if match.group("eq") is not None:
        if _is_shell_variable(match.group("eqi")):
            return None
        closing = match.group("eqc")
        return '\\"' + REDACTED_SECRET + (closing if closing.endswith('"') else "")
    if _is_shell_variable(match.group("bare")):
        return None
    return REDACTED_SECRET


def _redact_private_keys(text: str) -> str:
    if "-----" not in text:
        return text
    pieces: list[str] = []
    position = 0
    while begin := _PEM_BEGIN_RE.search(text, position):
        pieces.append(text[position : begin.start()])
        pieces.append(REDACTED_SECRET)
        end = _PEM_END_RE.search(text, begin.end())
        if end is None:
            # A truncated key block still exposes key material: drop the rest.
            position = len(text)
            break
        position = end.end()
    pieces.append(text[position:])
    return "".join(pieces)


def _compound_key(text: str, start: int, end: int) -> str:
    """Extend a key backwards over "-" joined segments (X-Api-Key), bounded."""

    floor = max(0, start - _MAX_KEY_CONTEXT)
    while start > floor and text[start - 1] in _COMPOUND_CHARS:
        start -= 1
    return text[start:end]


def _redact_key_values(text: str) -> str:
    pieces: list[str] = []
    emitted = 0
    position = 0
    while match := _KEY_VALUE_RE.search(text, position):
        position = match.end()
        if _CREDENTIAL_HINT_RE.search(match.group("key")) is None:
            continue
        key = _compound_key(text, match.start("key"), match.end("key"))
        if not names_credential(key):
            continue
        value = _ASSIGNMENT_VALUE_RE.match(text, position)
        if value is None:
            continue
        value_end = value.end()
        if value.group("bare") is not None:
            if _LABEL_FOLLOWS_RE.match(text, value_end):
                # "secret: api_key = ..." labels the assignment that follows.
                continue
            if _key_parts(key)[-1] == "AUTHORIZATION" and _AUTH_SCHEME_RE.fullmatch(
                value.group("bare")
            ):
                credential = _AUTH_SECOND_TOKEN_RE.match(text, value_end)
                if credential is not None:
                    value_end = credential.end()
                pieces.append(text[emitted : value.start()])
                pieces.append(REDACTED_SECRET)
                emitted = position = value_end
                continue
        replacement = _redacted_value(value)
        position = value_end
        if replacement is None:
            continue
        pieces.append(text[emitted : value.start()])
        pieces.append(replacement)
        emitted = value_end
    pieces.append(text[emitted:])
    return "".join(pieces)


def _secret_flag(flag: str) -> bool:
    name = flag.lstrip("-").lower().replace("_", "-")
    if name == "pass":
        return True
    if name.endswith("-stdin"):
        return False
    return _FLAG_SECRET_WORD_RE.search(f"-{name}-") is not None


def _redact_flags(text: str) -> str:
    if "-" not in text:
        return text
    pieces: list[str] = []
    emitted = 0
    position = 0
    while match := _FLAG_RE.search(text, position):
        position = match.end()
        if not _secret_flag(match.group("flag")):
            continue
        value = _FLAG_VALUE_RE.match(text, position)
        if value is None:
            continue
        position = value.end()
        replacement = _redacted_value(value)
        if replacement is None:
            continue
        pieces.append(text[emitted : value.start()])
        pieces.append(replacement)
        emitted = value.end()
    pieces.append(text[emitted:])
    return "".join(pieces)


def _redact_user_flags(text: str) -> str:
    """Redact ``user:password`` values of -u/--user; a bare user name is kept."""

    if "-" not in text:
        return text
    pieces: list[str] = []
    emitted = 0
    position = 0
    while match := _USER_FLAG_RE.search(text, position):
        position = match.end()
        value = _FLAG_VALUE_RE.match(text, position)
        if value is None or ":" not in value.group(0):
            # Keep scanning inside a skipped value ("-u -u user:pass").
            continue
        position = value.end()
        replacement = _redacted_value(value)
        if replacement is None:
            continue
        pieces.append(text[emitted : value.start()])
        pieces.append(replacement)
        emitted = value.end()
    pieces.append(text[emitted:])
    return "".join(pieces)


def _redact_url_userinfo(text: str) -> str:
    if "://" not in text:
        return text
    pieces: list[str] = []
    emitted = 0
    position = 0
    while match := _URL_USERINFO_RE.search(text, position):
        start = match.end()
        boundary = _URL_AUTHORITY_END_RE.search(text, start)
        end = boundary.start() if boundary else len(text)
        at = text.rfind("@", start, end)
        if at < 0:
            position = end
            continue
        if at > start:
            pieces.append(text[emitted:start])
            pieces.append(REDACTED_SECRET)
            emitted = at
        position = at + 1
    pieces.append(text[emitted:])
    return "".join(pieces)


def _redact_command_passwords(text: str) -> str:
    """Redact passwords passed to well-known clients as short options.

    ``mysql -pSECRET`` attaches the password (a separate ``-p db`` prompts and names
    a database). ``sshpass``, registry ``login`` commands and ``redis-cli`` take the
    password as the value of their first ``-p``/``-a`` option.
    """

    if not any(name in text for name in ("mysql", "mariadb", "sshpass", "login", "redis-cli")):
        return text
    pieces: list[str] = []
    emitted = 0
    position = 0
    while command := _PASSWORD_COMMAND_RE.search(text, position):
        boundary = _COMMAND_SEGMENT_END_RE.search(text, command.end())
        end = boundary.start() if boundary else len(text)
        name = command.group("cmd")
        position = end
        if name.startswith(("mysql", "mariadb")):
            spans = [
                found.span("attached")
                for found in _ATTACHED_P_RE.finditer(text, command.end(), end)
            ]
        else:
            pattern = _OPTION_A_RE if name == "redis-cli" else _OPTION_P_RE
            option = pattern.search(text, command.end(), end)
            spans = []
            if option is not None:
                group = "attached" if option.group("attached") is not None else "separate"
                spans = [option.span(group)]
        for start, stop in spans:
            if _is_shell_variable(text[start:stop].strip("\"'")):
                continue
            pieces.append(text[emitted:start])
            pieces.append(REDACTED_SECRET)
            emitted = stop
    pieces.append(text[emitted:])
    return "".join(pieces)


def redact_text(value: str | None) -> str:
    """Redact obvious credentials without attempting to persist the original value."""

    if not value:
        return "" if value is None else value
    redacted = _redact_private_keys(str(value))
    redacted = _redact_key_values(redacted)
    redacted = _BEARER_RE.sub(REDACTED_SECRET, redacted)
    redacted = _KNOWN_TOKEN_RE.sub(REDACTED_SECRET, redacted)
    redacted = _redact_url_userinfo(redacted)
    redacted = _redact_flags(redacted)
    redacted = _redact_user_flags(redacted)
    redacted = _redact_command_passwords(redacted)
    redacted = _URL_SECRET_RE.sub(rf"\1{REDACTED_SECRET}", redacted)
    return redacted


def looks_secret_key(key: str) -> bool:
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


def _redaction_key_level(key: str) -> int:
    """0: ordinary key; 1: secret-looking key; 2: key that names a credential."""

    if names_credential(key):
        return 2
    camel = _CAMEL_BOUNDARY_RE.sub("_", key[-_MAX_KEY_CONTEXT:])
    return 1 if looks_secret_key(key) or looks_secret_key(camel) else 0


def redact_obj(value: Any, *, key: str | None = None, _level: int = 0) -> Any:
    """Recursively redact strings and values under secret-looking object keys.

    Everything below a secret-looking key is treated as secret, including list
    items, nested objects and bytes. Numbers are dropped below keys that name a
    credential (``password``), but kept below names that merely mention one
    (``secret_exposure`` scores). Object keys are redacted like any other text.
    The input is never mutated.
    """

    level = max(_level, _redaction_key_level(key) if key is not None else 0)
    if isinstance(value, bytes | bytearray | memoryview):
        if level and len(value):
            return REDACTED_SECRET
        return redact_text(bytes(value).decode("utf-8", errors="replace"))
    if isinstance(value, str):
        if level and value and not _is_shell_variable(value):
            return REDACTED_SECRET
        return redact_text(value)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for item_key, item in value.items():
            name = str(item_key)
            safe_name = redact_text(name)
            if safe_name != name and safe_name in result:
                suffix = 2
                while f"{safe_name}#{suffix}" in result:
                    suffix += 1
                safe_name = f"{safe_name}#{suffix}"
            result[safe_name] = redact_obj(item, key=name, _level=level)
        return result
    if isinstance(value, list | tuple | set | frozenset):
        return [redact_obj(item, _level=level) for item in value]
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return REDACTED_SECRET if level >= 2 else value
    return REDACTED_SECRET if level else value


def redact_argv(argv: Sequence[str]) -> list[str]:
    """Redact credentials in an argument vector, including values passed separately."""

    result: list[str] = []
    awaiting: str | None = None
    command: str | None = None
    command_option_used = False
    previous = ""
    for item in argv:
        text = str(item)
        if awaiting is not None:
            pending, awaiting = awaiting, None
            if pending == "user" and ":" not in text:
                result.append(redact_text(text))
            else:
                result.append(text if _is_shell_variable(text) else REDACTED_SECRET)
            previous = text
            continue
        base = os.path.basename(text)
        if base in _PASSWORD_COMMANDS:
            command, command_option_used = "mysql", False
        elif base == "sshpass":
            command, command_option_used = "sshpass", False
        elif base == "redis-cli":
            command, command_option_used = "redis", False
        elif text == "login" and os.path.basename(previous) in _LOGIN_TOOLS:
            command, command_option_used = "login", False
        previous = text
        if command == "mysql" and text.startswith("-p") and len(text) > 2:
            value = text[2:]
            result.append(text if _is_shell_variable(value) else "-p" + REDACTED_SECRET)
            continue
        option = "-a" if command == "redis" else "-p"
        if command in {"sshpass", "login", "redis"} and not command_option_used:
            if text == option:
                command_option_used = True
                awaiting = "secret"
                result.append(text)
                continue
            if text.startswith(option) and len(text) > 2:
                command_option_used = True
                value = text[2:]
                result.append(text if _is_shell_variable(value) else option + REDACTED_SECRET)
                continue
        if _FLAG_TOKEN_RE.fullmatch(text) and _secret_flag(text):
            result.append(text)
            awaiting = "secret"
            continue
        if text.lower() in {"-u", "--user", "--username"}:
            result.append(text)
            awaiting = "user"
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
            # Gitleaks scans files, not stdin. Keep the input in a private
            # temporary directory and remove it before returning.
            with tempfile.TemporaryDirectory(prefix="jrx-redact-") as directory:
                source = Path(directory) / "input.txt"
                descriptor = os.open(source, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(text)
                env = {
                    key: value
                    for key, value in os.environ.items()
                    if key not in {"GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"}
                }
                result = subprocess.run(
                    [
                        "gitleaks",
                        "dir",
                        "--no-banner",
                        "--log-level",
                        "error",
                        "--exit-code",
                        "0",
                        "--report-format",
                        "json",
                        "--report-path",
                        "-",
                        str(source),
                    ],
                    cwd=directory,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
            if result.returncode != 0:
                return REDACTED_SECRET, True
            findings = json.loads(result.stdout)
            if not isinstance(findings, list):
                return REDACTED_SECRET, True
            redacted = text
            for finding in findings:
                if not isinstance(finding, dict):
                    return REDACTED_SECRET, True
                secret = finding.get("Secret", finding.get("secret"))
                if not isinstance(secret, str) or not secret or secret not in text:
                    return REDACTED_SECRET, True
                redacted = redacted.replace(secret, REDACTED_SECRET)
            return redacted, False
        except (OSError, subprocess.TimeoutExpired, UnicodeError, ValueError):
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
