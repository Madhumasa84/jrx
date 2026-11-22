"""Recognize dynamic shell execution and concrete delegated execution sinks."""

from __future__ import annotations

import ast
import re
import sys
from collections.abc import Mapping

from ..models import DeterministicFinding, EvaluationContext
from .common import git_command
from .diff import proposed_changes
from .shell import SHELLS, Command, inspect, program, xargs_target

_HTTP_LIBRARIES = {"http", "urllib", "requests", "httpx", "aiohttp", "socket", "ftplib", "smtplib"}
_PROCESS_LIBRARIES = {"subprocess", "runpy", "importlib", "ctypes", "multiprocessing"}
_LOADER_ENV = {
    "BASH_ENV",
    "ENV",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "NODE_OPTIONS",
    "PYTHONPATH",
}
_JS_DYNAMIC = re.compile(
    r"\b(?:eval|Function|require|import|fetch)\s*\(|"
    r"\b(?:child_process|XMLHttpRequest|WebSocket|https?|net|vm)\b|"
    r"\b[A-Za-z_$][\w$]*\[\s*\["
)
_JS_NETWORK = re.compile(
    r"\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(|"
    r"""(?:require\s*\(|from\s+|import\s*\()\s*['"](?:node:)?(?:https?|net|tls|undici|axios)\b"""
)
_NETWORK_PROGRAMS = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "scp",
    "ssh",
    "sftp",
    "socat",
    "ftp",
}


def is_python(name: str) -> bool:
    return bool(re.fullmatch(r"python(?:[23](?:\.\d+)?)?|pypy[23]?", name))


def inline_code(command: Command) -> str | None:
    name = program(command.argv[0])
    flags = {"-c"} if is_python(name) else {"-e", "--eval", "-p", "--print"}
    for index, arg in enumerate(command.argv[1:], 1):
        if arg == "--" or not arg.startswith("-"):
            break
        if arg in flags and index + 1 < len(command.argv):
            return command.argv[index + 1]
        flag, separator, value = arg.partition("=")
        if separator and flag in flags:
            return value
        if is_python(name) and arg.startswith("-c") and len(arg) > 2:
            return arg[2:]
        if name in {"perl", "ruby", "node", "nodejs"} and re.match(r"^-[ep].+", arg):
            return arg[2:]
    return None


def _python_evidence(code: str) -> tuple[bool, bool]:
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return True, False
    imports: set[str] = set()
    dynamic = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add((node.module or "").split(".", 1)[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                dynamic |= node.func.id in {
                    "eval",
                    "exec",
                    "compile",
                    "__import__",
                    "getattr",
                    "setattr",
                }
            elif isinstance(node.func, ast.Attribute):
                dynamic |= node.func.attr in {"system", "popen", "execv", "execve", "spawnv"}
    network = bool(imports & _HTTP_LIBRARIES)
    return dynamic or network or bool(
        imports & _PROCESS_LIBRARIES or imports - sys.stdlib_module_names
    ), network


def egress(command: Command) -> bool:
    if not command.argv:
        return False
    name, args = program(command.argv[0]), command.argv[1:]
    if name in _NETWORK_PROGRAMS or (name == "gh" and args[:1] in {("gist",), ("api",)}):
        return True
    if name == "rsync":
        return any(re.search(r"^(?:[^/\s]+@)?[^/:\s]+:", arg) for arg in args)
    if (git := git_command(command)) and git.subcommand in {
        "push",
        "fetch",
        "pull",
        "clone",
        "ls-remote",
    }:
        return True
    if (is_python(name) or name in {"node", "nodejs"}) and (code := inline_code(command)):
        return _python_evidence(code)[1] if is_python(name) else bool(_JS_NETWORK.search(code))
    return False


def _command_risk(command: Command) -> str | None:
    name, args = program(command.argv[0]), command.argv[1:]
    if name in {"sudo", "doas"} and args and "-l" not in args:
        return "PRIVILEGED_EXECUTION"
    environment = (*command.assignments, *(args if name == "env" else ()))
    if any(item.partition("=")[0] in _LOADER_ENV and "=" in item for item in environment):
        return "EXECUTABLE_ENVIRONMENT"
    if name in SHELLS and command.piped:
        return "PIPE_TO_INTERPRETER"
    if name == "find" and set(args) & {"-exec", "-execdir", "-ok", "-okdir"}:
        return "DELEGATED_EXECUTION"
    if name == "tar" and any(
        arg.startswith("--checkpoint-action=exec")
        or arg == "exec"
        or arg.startswith("exec=")
        or arg.startswith(("--use-compress-program", "--to-command"))
        for arg in args
    ):
        return "DELEGATED_EXECUTION"
    if name == "xargs":
        target = xargs_target(command.argv)
        if target and program(target[0]) in SHELLS | {"eval", "exec"}:
            return "DELEGATED_EXECUTION"
    if name in {"rg", "ripgrep"} and any(
        arg == "--pre" or arg.startswith("--pre=") for arg in args
    ):
        return "DELEGATED_EXECUTION"
    if name in {"make", "gmake"} and any(arg.startswith(("--eval", "-E")) for arg in args):
        return "DELEGATED_EXECUTION"
    if name == "awk" and any(re.search(r"\bsystem\s*\(", arg) for arg in args):
        return "INLINE_EXECUTION"
    if is_python(name) or name in {"node", "nodejs", "perl", "ruby"}:
        if (code := inline_code(command)) is not None:
            if is_python(name) and _python_evidence(code)[0]:
                return "INLINE_EXECUTION"
            if name in {"node", "nodejs"} and _JS_DYNAMIC.search(code):
                return "INLINE_EXECUTION"
            if name in {"perl", "ruby"} and re.search(
                r"\b(?:system|exec|eval|spawn|open)\b|`", code
            ):
                return "INLINE_EXECUTION"
    return None


def _tool_execution(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    explicit = (
        value.get("execute") is True
        or value.get("evaluate") is True
        or value.get("effect") == "execute"
    )
    return (
        explicit
        and bool(
            value.keys()
            & {"expression", "expression_parts", "code", "cell", "payload", "snippet", "script"}
        )
    ) or isinstance(value.get("runtime_hook"), Mapping)


def _build_execution(context: EvaluationContext) -> bool:
    for change in proposed_changes(context):
        content = "\n".join(change.added)
        for path in change.paths:
            name = path.rsplit("/", 1)[-1].lower()
            if name in {"makefile", "gnumakefile"} and re.search(r"\$[({]\s*shell\b", content):
                return True
            if name == "package.json" and re.search(
                r'"(?:preinstall|postinstall|install|prepare|pretest|posttest)"\s*:', content
            ):
                return True
            if name == "pyproject.toml":
                for match in re.finditer(r'^\s*build-backend\s*=\s*["\']([^"\']+)', content, re.M):
                    if match[1] not in {
                        "setuptools.build_meta",
                        "hatchling.build",
                        "flit_core.buildapi",
                        "poetry.core.masonry.api",
                    }:
                        return True
    return False


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    plan = inspect(context.proposed_action)
    reason = next(
        (risk for command in plan.commands if command.argv and (risk := _command_risk(command))),
        None,
    )
    if reason is None and plan.opaque:
        reason = "OPAQUE_SHELL_EXECUTION"
    if reason is None and (
        _tool_execution(context.proposed_action.input) or _build_execution(context)
    ):
        reason = "DECLARED_EXECUTION_HOOK"
    if reason is None:
        return []
    return [
        DeterministicFinding(
            check="execution_risk", triggered=True, severity="medium", reason_code=reason
        )
    ]
