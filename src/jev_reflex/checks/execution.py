"""Recognize dynamic shell execution and concrete delegated execution sinks."""

from __future__ import annotations

import ast
import re
import sys
from collections.abc import Mapping, Sequence

from ..models import DeterministicFinding, EvaluationContext
from .common import git_command
from .diff import proposed_changes
from .shell import (
    CODE_INTERPRETERS,
    PREFIX_COMMANDS,
    SHELLS,
    Command,
    ShellPlan,
    container_exec,
    inspect,
    interpreter_code,
    is_python,
    program,
    reads_program_from_stdin,
    ssh_invocation,
    su_invocation,
    xargs_target,
)

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
# Builtins and utilities whose behaviour an unresolved argument cannot widen beyond output.
_EXPANSION_SAFE = frozenset(
    {
        "echo",
        "printf",
        "test",
        "[",
        "[[",
        "true",
        "false",
        ":",
        "export",
        "local",
        "declare",
        "typeset",
        "readonly",
        "unset",
        "shift",
        "set",
        "return",
        "exit",
        "read",
        "sleep",
        "seq",
        "basename",
        "dirname",
        "pwd",
        "type",
        "which",
        "hash",
        "wait",
        "expr",
        "let",
    }
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


def inline_code(command: Command) -> str | None:
    """Inline program text given to python/node/perl/ruby, grouped short flags included."""
    codes, _ = interpreter_code(command.argv)
    return "\n".join(codes) if codes else None


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
    # Remote hosts and containers are outside what the local checks can observe, so a
    # command run there needs review even when its own text looks harmless.
    if command.context == "remote" or (name == "ssh" and ssh_invocation(command.argv).connects):
        return "REMOTE_EXECUTION"
    if command.context == "container" or (
        name in {"docker", "podman"} and container_exec(command.argv) is not None
    ):
        return "CONTAINER_EXECUTION"
    if (name in {"sudo", "doas"} and args and "-l" not in args) or (
        name in {"su", "runuser"} and su_invocation(command.argv).executes
    ):
        return "PRIVILEGED_EXECUTION"
    environment = (*command.assignments, *(args if name == "env" else ()))
    if any(item.partition("=")[0] in _LOADER_ENV and "=" in item for item in environment):
        return "EXECUTABLE_ENVIRONMENT"
    if command.piped and (
        name in SHELLS
        or (
            (is_python(name) or name in CODE_INTERPRETERS or name in {"source", "."})
            and reads_program_from_stdin(command.argv)
        )
    ):
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


def _unresolved_expansion(plan: ShellPlan) -> bool:
    """Arguments whose runtime value the lexer could not resolve.

    Arithmetic contexts (``$((x))``, ``((x))``, ``let``, ``[[ x -eq 1 ]]``) evaluate variable
    text as code, so any operand that is not a known integer counts. Other unresolved
    parameter expansions count when they reach a command whose options or operands change
    what it does; output-only builtins such as ``echo``/``printf`` are exempt, and prefix
    commands are judged through the command they wrap.
    """
    for command in plan.commands:
        words = [command.word(index) for index in range(len(command.argv))]
        if any("arithmetic" in word.kinds for word in (*words, *command.assignment_words)):
            return True
        if not command.argv:
            continue
        name = program(command.argv[0])
        if name in _EXPANSION_SAFE or name in PREFIX_COMMANDS:
            continue
        message_values = _git_message_values(command.argv) if name == "git" else set()
        if any(
            "parameter" in word.kinds
            and (index not in message_values or word.kinds & {"vanishable", "ifs"})
            for index, word in enumerate(words[1:], start=1)
        ):
            return True
    return False


def _git_message_values(argv: Sequence[str]) -> set[int]:
    """Indices of git ``-m``/``--message`` values: commit text, never options or paths.

    Only the flag's own value is exempt; a word the shell can split or drop (an unquoted
    expansion) is still judged by the caller because its pieces could become new options.
    """
    values = set()
    for index, arg in enumerate(argv):
        if arg in {"-m", "--message"} and index + 1 < len(argv):
            values.add(index + 1)
        elif arg.startswith("--message=") or (arg.startswith("-m") and len(arg) > 2):
            values.add(index)
    return values


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    plan = inspect(context.proposed_action)
    reason = next(
        (risk for command in plan.commands if command.argv and (risk := _command_risk(command))),
        None,
    )
    if reason is None and plan.opaque:
        reason = "OPAQUE_SHELL_EXECUTION"
    if reason is None and _unresolved_expansion(plan):
        reason = "UNRESOLVED_EXPANSION"
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
