"""Untrusted executable pipelines and package sources."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from ..config import LocalChecksConfig, ReflexConfig
from ..models import DeterministicFinding, EvaluationContext
from .diff import proposed_changes
from .execution import is_python
from .shell import SHELLS, Command, inspect, program

_DOWNLOAD = {"curl", "wget"}
_URL = re.compile(r"""\b(?:git\+)?(?:https?|ssh|ftp|file)://[^\s"'<>),]+""", re.I)
_PACKAGE_FLAGS = {
    "-i",
    "--index",
    "--default-index",
    "--index-url",
    "--extra-index-url",
    "--registry",
}
_INTERPRETERS = SHELLS | {"node", "nodejs", "perl", "ruby"}


def _interpreter(name: str) -> bool:
    return name in _INTERPRETERS or is_python(name)


def _package_install(command: Command) -> tuple[str, ...]:
    name, args = program(command.argv[0]), command.argv[1:]
    if is_python(name) and args[:2] == ("-m", "pip"):
        name, args = "pip", args[2:]
    elif name == "uv" and args[:1] == ("pip",):
        name, args = "pip", args[1:]
    if name in {"pipx", "uv", "npm", "pnpm", "yarn", "bun"} or re.fullmatch(
        r"pip(?:[23](?:\.\d+)?)?", name
    ):
        operation = next((arg for arg in args if not arg.startswith("-")), "")
        if operation in {"install", "add", "i", "ci", "sync"}:
            return args
    return ()


def _trusted(url: str, hosts: set[str]) -> bool:
    try:
        parsed = urlsplit(url.removeprefix("git+"))
        return (
            parsed.scheme == "https"
            and parsed.hostname in hosts
            and parsed.port in {None, 443}
            and parsed.username is None
            and parsed.password is None
            and not url.startswith("git+")
        )
    except ValueError:
        return False


def _untrusted_index(args: tuple[str, ...], hosts: set[str]) -> bool:
    for index, arg in enumerate(args):
        flag, separator, value = arg.partition("=")
        if flag in _PACKAGE_FLAGS and not _trusted(
            value if separator else args[index + 1] if index + 1 < len(args) else "", hosts
        ):
            return True
    return False


def _manifest_risk(context: EvaluationContext, hosts: set[str]) -> bool:
    for change in proposed_changes(context):
        content = "\n".join(change.added)
        for path in change.paths:
            name = PurePosixPath(path).name.lower()
            manifest = name in {
                "pyproject.toml",
                "cargo.toml",
                "package.json",
                "setup.cfg",
                "pip.conf",
            } or (name.startswith("requirements") and name.endswith((".txt", ".in")))
            if manifest and any(not _trusted(match[0], hosts) for match in _URL.finditer(content)):
                return True
            if path.startswith((".github/actions/", ".github/workflows/")) and name.endswith(
                (".yml", ".yaml")
            ):
                for match in re.finditer(
                    r"""^\s*-?\s*uses:\s*['"]?([\w./-]+)@([\w/.-]+)""", content, re.M
                ):
                    if not match[1].startswith("./") and not re.fullmatch(
                        r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", match[2]
                    ):
                        return True
            if name == "dockerfile" or name.startswith("dockerfile."):
                for match in re.finditer(
                    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", content, re.M | re.I
                ):
                    image = match[1]
                    registry, _, _ = image.partition("/")
                    if (
                        "/" in image
                        and ("." in registry or ":" in registry)
                        and "@sha256:" not in image
                    ):
                        return True
    return False


def evaluate(
    context: EvaluationContext, config: ReflexConfig | None = None
) -> list[DeterministicFinding]:
    local = config.local_checks if config is not None else LocalChecksConfig()
    hosts = {host.lower() for host in local.trusted_package_hosts}
    remote = encoded = process_input = False
    review = False
    for command in inspect(context.proposed_action).commands:
        if not command.argv:
            continue
        name, args = program(command.argv[0]), command.argv[1:]
        if (command.piped and _interpreter(name) and (remote or encoded)) or (
            process_input and name in _DOWNLOAD
        ):
            return [_finding("UNTRUSTED_PIPE_TO_INTERPRETER", blocking=True)]
        if not command.piped:
            remote = encoded = False
        remote |= name in _DOWNLOAD
        encoded |= (
            name in {"base64", "basenc"}
            and bool(set(args) & {"-d", "-D", "--decode"})
            or name == "xxd"
            and bool(set(args) & {"-r", "-revert"})
            or name == "printf"
            and any(re.search(r"\\(?:x[0-9a-fA-F]{2}|[0-7]{2,3})", arg) for arg in args)
        )
        process_input = command.process_input and _interpreter(name)
        if install := _package_install(command):
            review |= _untrusted_index(install, hosts) or any(
                not _trusted(match[0], hosts) for arg in install for match in _URL.finditer(arg)
            )
    if review or _manifest_risk(context, hosts):
        return [_finding("UNTRUSTED_PACKAGE_SOURCE", blocking=False)]
    return []


def _finding(reason: str, *, blocking: bool) -> DeterministicFinding:
    return DeterministicFinding(
        check="supply_chain",
        triggered=True,
        severity="high" if blocking else "medium",
        reason_code=reason,
        blocking=blocking,
    )
