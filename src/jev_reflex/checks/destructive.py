"""Deterministic recognition of plainly destructive actions."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ..models import DeterministicFinding, EvaluationContext
from .common import git_command, long_option, python_inline_code, roots
from .shell import Command, inspect, program, xargs_target

_GENERATED_DIRECTORIES = frozenset(
    {
        "dist",
        "node_modules",
        "coverage-html",
        ".pytest_cache",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".next",
        ".turbo",
    }
)
_SAFE_RM_OPTIONS = frozenset(
    {"--force", "--recursive", "--interactive", "--verbose", "--one-file-system", "--preserve-root"}
)
_RM_LONG_OPTIONS = frozenset(
    {
        *_SAFE_RM_OPTIONS,
        "--dir",
        "--no-preserve-root",
        "--help",
        "--version",
    }
)
_INTERPRETER_SIDE_EFFECT_RE = re.compile(
    r"\b(?:os\.(?:system|popen|remove|unlink|rmdir|removedirs)|"
    r"shutil\.(?:rmtree|move)|(?:pathlib\.)?path\.(?:unlink|rmdir)|"
    r"subprocess\.(?:run|popen|call|check_call|check_output)|"
    r"fs\.(?:rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync)|"
    r"child_process\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)|"
    r"""child_process['"]\s*\)\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)|"""
    r"""(?:fs|fs/promises)['"]\s*\)\s*\.\s*(?:rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync)|"""
    r"(?:execSync|execFileSync|spawnSync)\s*\(|"
    r"remove-item)\b",
    re.IGNORECASE,
)
# Python callables with a filesystem or process side effect, by qualified name.
_PY_SIDE_EFFECTS = frozenset(
    {
        *(
            f"os.{name}"
            for name in (
                "system",
                "popen",
                "remove",
                "unlink",
                "rmdir",
                "removedirs",
                "rename",
                "renames",
                "replace",
                "truncate",
                "startfile",
                "posix_spawn",
                "posix_spawnp",
                *(f"exec{suffix}" for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
                *(f"spawn{suffix}" for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
            )
        ),
        "shutil.rmtree",
        "shutil.move",
        "pty.spawn",
        "commands.getoutput",
        "commands.getstatusoutput",
    }
)
_PY_SIDE_EFFECT_MODULES = ("subprocess.",)
# Method names whose call is a side effect whatever object they are reached through.
_PY_SIDE_EFFECT_ATTRIBUTES = frozenset(
    {
        "system",
        "popen",
        "rmtree",
        "unlink",
        "rmdir",
        "removedirs",
        "check_call",
        "check_output",
        "Popen",
        "getoutput",
        "getstatusoutput",
        "posix_spawn",
        "posix_spawnp",
        *(f"exec{suffix}" for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
        *(f"spawn{suffix}" for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
    }
)
# ``find`` tests that narrow which entries an action applies to.
_FIND_FILTERS = frozenset(
    {
        "-name",
        "-iname",
        "-path",
        "-ipath",
        "-wholename",
        "-iwholename",
        "-regex",
        "-iregex",
        "-lname",
        "-ilname",
        "-newer",
        "-anewer",
        "-cnewer",
        "-mtime",
        "-mmin",
        "-atime",
        "-amin",
        "-ctime",
        "-cmin",
        "-used",
        "-size",
        "-user",
        "-group",
        "-uid",
        "-gid",
        "-nouser",
        "-nogroup",
        "-perm",
        "-links",
        "-inum",
        "-samefile",
        "-empty",
        "-fstype",
        "-context",
    }
)
_FIND_ALTERNATIVES = frozenset({"!", "-not", "-o", "-or", ","})
_FIND_EXEC = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_DELETE_PROGRAMS = frozenset({"rm", "unlink", "rmdir", "shred"})


def _trigger(reason_code: str) -> DeterministicFinding:
    return DeterministicFinding(
        check="known_destructive",
        triggered=True,
        severity="high",
        reason_code=reason_code,
        blocking=True,
    )


def _rm_options(argv: tuple[str, ...]) -> tuple[list[str], list[str]]:
    options, targets = [], []
    literal = False
    for item in argv[1:]:
        if not literal and item == "--":
            literal = True
        elif not literal and item.startswith("-") and item != "-":
            options.append(item)
        else:
            targets.append(item)
    return options, targets


def _rm_option(option: str) -> str:
    """Expand an unambiguous abbreviation of a GNU ``rm`` long option."""

    matches = long_option(option, _RM_LONG_OPTIONS)
    return matches.pop() if len(matches) == 1 else option


def _generated_target(target: str, directory: Path, root: Path) -> bool:
    path = Path(target)
    if not path.parts or path.name not in _GENERATED_DIRECTORIES:
        return False
    if path.is_absolute() or {"..", ".git"}.intersection(path.parts):
        return False
    if any(char in target for char in "*?[{}~$"):
        return False
    candidate = directory / path
    if not candidate.is_relative_to(root):
        return False
    # Symlinks make a name-based cleanup exception unsafe.
    return candidate.resolve() == candidate


def _safe_recursive_cleanup(
    context: EvaluationContext, command: Command, options: list[str], targets: list[str]
) -> bool:
    if (
        command.argv[0] not in {"rm", "/bin/rm", "/usr/bin/rm"}
        or command.indirect
        or command.redirects
        or not targets
    ):
        return False
    if any(
        _rm_option(opt) not in _SAFE_RM_OPTIONS and not re.fullmatch(r"-[rRfiIv]+", opt)
        for opt in options
    ):
        return False
    try:
        directory, root = roots(context)
        return all(_generated_target(target, directory, root) for target in targets)
    except (ValueError, RuntimeError, OSError):
        return False


def _find_delete(argv: tuple[str, ...]) -> bool:
    """An unfiltered ``find`` deletion: every entry under the start points is removed."""

    deletes = "-delete" in argv
    for index, arg in enumerate(argv[:-1]):
        if arg in _FIND_EXEC and program(argv[index + 1]) in _DELETE_PROGRAMS:
            deletes = True
    if not deletes:
        return False
    if _FIND_ALTERNATIVES.intersection(argv):
        # Negation or alternation can invert any narrowing test.
        return True
    return not _FIND_FILTERS.intersection(argv)


def _find_feeds_delete(commands: tuple[Command, ...], find: Command) -> bool:
    """``find ... | xargs rm``: the next pipeline stage deletes every name ``find`` prints.

    The same narrowing rules as ``find -delete`` apply, so ``find . -name '*.pyc' | xargs
    rm`` stays a scoped cleanup while ``find . | xargs rm`` removes everything found.
    """
    position = next(index for index, command in enumerate(commands) if command is find)
    # The next command at find's own level; find's -exec payloads are nested below it.
    consumer = next(
        (command for command in commands[position + 1 :] if command.indirect == find.indirect),
        None,
    )
    if consumer is None or not consumer.piped or not consumer.argv:
        return False
    if program(consumer.argv[0]) != "xargs":
        return False
    target = xargs_target(consumer.argv)
    if not target or program(target[0]) not in _DELETE_PROGRAMS:
        return False
    return _find_delete((*find.argv, "-delete"))


def _python_side_effect(code: str) -> bool | None:
    """Resolve imported names in Python code; ``None`` when the code does not parse."""

    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    aliases: dict[str, str] = {}
    star_modules: list[str] = []
    nodes = list(ast.walk(tree))
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    head = alias.name.split(".", 1)[0]
                    aliases[head] = head
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name == "*":
                    star_modules.append(node.module)
                else:
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def qualified(expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Name):
            if expr.id in aliases:
                return aliases[expr.id]
            for module in star_modules:
                candidate = f"{module}.{expr.id}"
                if candidate in _PY_SIDE_EFFECTS or candidate.startswith(_PY_SIDE_EFFECT_MODULES):
                    return candidate
            return expr.id
        if isinstance(expr, ast.Attribute):
            base = qualified(expr.value)
            return f"{base}.{expr.attr}" if base else None
        if isinstance(expr, ast.Call) and expr.args:
            function = qualified(expr.func)
            first = expr.args[0]
            if (
                function in {"__import__", "importlib.import_module"}
                and isinstance(first, ast.Constant)
                and isinstance(first.value, str)
            ):
                return first.value
            if function == "getattr" and len(expr.args) > 1:
                name = expr.args[1]
                base = qualified(first)
                if base and isinstance(name, ast.Constant) and isinstance(name.value, str):
                    return f"{base}.{name.value}"
        return None

    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        name = qualified(node.func)
        if name and (name in _PY_SIDE_EFFECTS or name.startswith(_PY_SIDE_EFFECT_MODULES)):
            return True
        if name and name.rsplit(".", 1)[-1] in _PY_SIDE_EFFECT_ATTRIBUTES and "." in name:
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in _PY_SIDE_EFFECT_ATTRIBUTES:
            return True
    return False


def _interpreter_side_effect(name: str, argv: tuple[str, ...]) -> bool:
    if not name.startswith(("python", "pypy", "node")):
        return False
    if name.startswith(("python", "pypy")) and (code := python_inline_code(argv)) is not None:
        if _python_side_effect(code):
            return True
    # Text evidence also covers unparsable code, node, and script arguments.
    return bool(_INTERPRETER_SIDE_EFFECT_RE.search(" ".join(argv[1:])))


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    plan = inspect(context.proposed_action)
    for command in plan.commands:
        if not command.argv:
            continue
        name = program(command.argv[0])
        args = command.argv[1:]
        if name == "rm":
            options, targets = _rm_options(command.argv)
            recursive = any(
                long_option(opt, {"--recursive"})
                or (not opt.startswith("--") and "r" in opt.lower())
                for opt in options
            )
            if recursive and (
                len(plan.commands) != 1
                or not _safe_recursive_cleanup(context, command, options, targets)
            ):
                return [_trigger("RECURSIVE_DELETE")]
        if name == "find" and (
            _find_delete(command.argv) or _find_feeds_delete(plan.commands, command)
        ):
            return [_trigger("RECURSIVE_DELETE")]
        if _interpreter_side_effect(name, command.argv):
            return [_trigger("INTERPRETER_SIDE_EFFECT")]
        if name == "git":
            git = git_command(command)
            if git and git.subcommand == "reset" and "--hard" in git.flags:
                return [_trigger("GIT_HARD_RESET")]
            if git and git.subcommand == "clean":
                require = git.config("clean.requireForce")
                if git.flags & {"-f", "--force"} or (
                    require is not None and require.lower() in {"false", "no", "off", "0"}
                ):
                    return [_trigger("GIT_CLEAN_FORCE")]
        if name in {"psql", "mysql", "sqlite3", "sqlcmd", "duckdb"} and re.search(
            r"\b(?:drop\s+(?:database|table)|truncate\s+table)\b", " ".join(args), re.I
        ):
            return [_trigger("DATABASE_DESTRUCTIVE")]
        if (name, args[:1]) in {("terraform", ("destroy",)), ("kubectl", ("delete",))}:
            return [_trigger("INFRASTRUCTURE_DELETE")]
        if name == "shred" or (name == "docker" and args[:2] == ("system", "prune")):
            return [_trigger("RESOURCE_PRUNE")]
    return [
        DeterministicFinding(
            check="known_destructive", triggered=False, severity="low", reason_code="CLEAR"
        )
    ]
