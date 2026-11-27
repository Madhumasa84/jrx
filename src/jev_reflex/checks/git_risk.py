"""Deterministic checks for destructive Git and executable configuration."""

from __future__ import annotations

import re
import shlex

from ..models import DeterministicFinding, EvaluationContext
from .common import GitCommand, git_command, long_option
from .shell import inspect, program

_EXECUTION_KEYS = {
    "core.fsmonitor",
    "core.sshcommand",
    "core.hookspath",
    "core.pager",
    "core.editor",
    "core.askpass",
    "core.gitproxy",
    "core.alternaterefscommand",
    "sequence.editor",
    "diff.external",
    "interactive.difffilter",
    "uploadpack.packobjectshook",
}
# Section and key names are case-insensitive; subsections are case-sensitive but
# unconstrained here, so matching the case-folded key is exact for these forms.
_EXECUTION_KEY_PATTERN = re.compile(
    r"(?:credential(?:\..*)?\.helper"
    r"|gpg(?:\..*)?\.(?:program|defaultkeycommand)"
    r"|remote\..*\.(?:uploadpack|receivepack|vcs)"
    r"|protocol(?:\..*)?\.allow"
    r"|filter\..*\.(?:process|clean|smudge)"
    r"|diff\..*\.(?:command|textconv)"
    r"|merge\..*\.driver"
    r"|(?:difftool|mergetool|browser|man)\..*\.(?:cmd|path)"
    r"|(?:hook|trailer)\..*\.(?:command|cmd)"
    r"|tar\..*\.command"
    r"|submodule\..*\.update"
    r"|sendemail(?:\..*)?\.(?:smtpserver|sendmailcmd|tocmd|cccmd|headercmd))"
)
_EXECUTION_PREFIXES = ("alias.", "pager.", "include.", "includeif.")
# Program-valued settings where a no-op pager/editor value runs nothing new.
_PROGRAM_KEYS = {"core.pager", "core.editor", "sequence.editor"}
_PROGRAM_ENV = {"GIT_PAGER", "PAGER", "GIT_EDITOR", "EDITOR", "VISUAL", "GIT_SEQUENCE_EDITOR"}
# No-op pager/editor values agents use to keep Git non-interactive.
_BENIGN_PROGRAMS = {"cat", "true", "false", ":"}
_EXECUTION_ENV = {
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_EXTERNAL_DIFF",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_EXEC_PATH",
    "GIT_PROXY_COMMAND",
    "GIT_TEMPLATE_DIR",
    *_PROGRAM_ENV,
}
_DECLARATIONS = {"export", "declare", "typeset", "readonly", "local"}
# Subcommands that contact a remote helper program a transport option can replace.
_TRANSPORTS = {"fetch", "pull", "clone", "ls-remote", "push", "archive", "remote", "submodule"}
_TRANSPORT_OPTIONS = {"--upload-pack", "--receive-pack", "--exec"}
_FALSE = {"false", "no", "off", "0"}


def _benign_program(value: str) -> bool:
    try:
        words = shlex.split(value)
    except ValueError:
        return False
    if not words:
        return True
    name = words[0]
    if name.startswith(("/bin/", "/usr/bin/")):
        name = name.rsplit("/", 1)[1]
    # Only a bare name or a system path (``./x/cat`` is an arbitrary program) with
    # plain flags: Git runs the value through ``sh -c``.
    return name in _BENIGN_PROGRAMS and all(
        re.fullmatch(r"-[A-Za-z0-9-]+", word) for word in words[1:]
    )


def executable_key(key: str, value: str | None = None) -> bool:
    key = key.lower()
    if (
        value is not None
        and (key in _PROGRAM_KEYS or key.startswith("pager."))
        and _benign_program(value)
    ):
        return False
    return (
        key in _EXECUTION_KEYS
        or key.startswith(_EXECUTION_PREFIXES)
        or bool(_EXECUTION_KEY_PATTERN.fullmatch(key))
    )


def _executable_setting(setting: str) -> bool:
    key, separator, value = setting.partition("=")
    return executable_key(key, value if separator else None)


def _execution_assignment(item: str) -> bool:
    name, separator, value = item.partition("=")
    if not separator:
        return False
    if name in _PROGRAM_ENV:
        return not _benign_program(value)
    return name in _EXECUTION_ENV or name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))


def _configure_execution(git: GitCommand) -> bool:
    for option, argument in git.options:
        if option in {"--exec-path", "--config-env"}:
            # An alternate exec path replaces every Git helper program, and a
            # value read from the environment cannot be reviewed here.
            return True
        key, _, value = argument.partition("=")
        if option == "-c" and _executable_setting(argument):
            if key.lower() == "core.fsmonitor" and value.lower() == "false":
                continue
            return True
    if git.subcommand != "config":
        return False
    args = git.args[1:]
    if set(args) & {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l"}:
        return False
    names = [arg for arg in args if not arg.startswith("-")]
    if names and names[0] in {"get", "list"}:
        return False
    return any(executable_key(arg) for arg in names) and (
        len(names) > 1
        or bool(set(args) & {"--unset", "--unset-all", "--remove-section", "--rename-section"})
    )


def _transport_execution(git: GitCommand) -> bool:
    """Options that make clone/fetch/push run an agent-chosen program or hook."""

    name = git.subcommand
    expect_config = False
    for arg in git.args[1:]:
        if expect_config:
            expect_config = False
            if _executable_setting(arg):
                return True
            continue
        if arg == "--":
            break
        if arg.startswith("--"):
            options = long_option(arg, _TRANSPORT_OPTIONS | {"--template", "--config"})
            if name in _TRANSPORTS and options & _TRANSPORT_OPTIONS:
                return True
            if name in {"clone", "init"} and "--template" in options:
                return True
            if name == "clone" and "--config" in options:
                _, separator, setting = arg.partition("=")
                if not separator:
                    expect_config = True
                elif _executable_setting(setting):
                    return True
            continue
        if not arg.startswith("-") or name not in {"clone", "ls-remote"}:
            continue
        for index, letter in enumerate(arg[1:]):
            if letter == "u":
                return True
            if letter == "c" and name == "clone":
                setting = arg[index + 2 :]
                if not setting:
                    expect_config = True
                elif _executable_setting(setting):
                    return True
                break
            if letter in {"o", "b", "j"}:
                break
    return False


def _delegated_execution(git: GitCommand) -> bool:
    """Subcommands that run a command line the agent supplies."""

    name, flags, args = git.subcommand, git.flags, git.args[1:]
    if name == "rebase" and flags & {"-x", "--exec"}:
        return True
    if name == "difftool" and flags & {"-x", "--extcmd"}:
        return True
    return (name, args[:1]) in {("submodule", ("foreach",)), ("bisect", ("run",))}


def _remote_ref_delete(git: GitCommand) -> bool:
    flags = git.flags
    if flags & {"-d", "--delete", "--mirror", "--prune"}:
        return True
    refspecs = [arg for arg in git.args[1:] if not arg.startswith("-")]
    return any(spec.lstrip("+").startswith(":") and len(spec.lstrip("+")) > 1 for spec in refspecs)


def _clean_without_force(git: GitCommand) -> bool:
    value = git.config("clean.requireForce")
    return value is not None and value.lower() in _FALSE


def _finding(reason: str, *, review: bool = False) -> DeterministicFinding:
    return DeterministicFinding(
        check="git_risk",
        triggered=True,
        severity="medium" if review else "high",
        reason_code=reason,
        blocking=not review,
    )


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    safe_git = False
    execution_env = False
    amend = False
    review = ""
    for command in inspect(context.proposed_action).commands:
        environment = command.assignments
        name = program(command.argv[0]) if command.argv else ""
        if name == "env" or name in _DECLARATIONS:
            environment += command.argv[1:]
        execution_env |= any(_execution_assignment(item) for item in environment)
        git = git_command(command)
        if git is None:
            continue
        if execution_env or _configure_execution(git) or _transport_execution(git):
            return [_finding("GIT_EXECUTION_CONFIG")]
        flags = git.flags
        name = git.subcommand
        if name == "reset" and "--hard" in flags:
            return [_finding("GIT_HARD_RESET")]
        if name == "clean" and (flags & {"-f", "--force"} or _clean_without_force(git)):
            return [_finding("GIT_CLEAN_FORCE")]
        if name == "push" and (
            flags & {"-f", "--force", "--force-with-lease", "--force-if-includes"}
            or any(arg.startswith("+") for arg in git.args[1:])
        ):
            return [_finding("FORCE_PUSH")]
        if name == "push" and _remote_ref_delete(git):
            return [_finding("REMOTE_REF_DELETE")]
        if name == "branch" and (
            "-D" in flags or (flags & {"-d", "--delete"} and flags & {"-f", "--force"})
        ):
            return [_finding("BRANCH_DELETE_FORCE")]
        if name in {"filter-repo", "filter-branch"} or (
            name == "rebase" and flags & {"-i", "--interactive"}
        ):
            return [_finding("HISTORY_REWRITE")]
        if not review and _delegated_execution(git):
            review = "GIT_DELEGATED_EXECUTION"
        if not review and git.unknown:
            review = "GIT_UNKNOWN_OPTION"
        amend |= name == "commit" and "--amend" in flags
        safe_git |= name in {"status", "diff"}
    if review:
        return [_finding(review, review=True)]
    if amend:
        return [_finding("COMMIT_AMEND", review=True)]
    return [
        DeterministicFinding(
            check="git_risk",
            triggered=False,
            severity="low",
            reason_code="KNOWN_SAFE_GIT" if safe_git else "CLEAR",
        )
    ]
