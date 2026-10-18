from pathlib import Path

import pytest

from jev_reflex.checks import run_deterministic_checks
from jev_reflex.models import EvaluationContext, ProposedAction


def _context(tmp_path: Path, command: str) -> EvaluationContext:
    root = tmp_path.resolve()
    return EvaluationContext(
        repository="demo",
        repository_root=str(root),
        working_directory=str(root),
        proposed_action=ProposedAction(command=command),
    )


def _triggered(context: EvaluationContext, check: str) -> bool:
    return any(
        finding.check == check and finding.triggered
        for finding in run_deterministic_checks(context)
    )


def test_known_safe_command_has_no_blocking_finding(tmp_path: Path) -> None:
    findings = run_deterministic_checks(_context(tmp_path, "pytest tests/"))
    assert not any(finding.triggered and finding.blocking for finding in findings)
    assert any(finding.reason_code == "KNOWN_SAFE_COMMAND" for finding in findings)


def test_recursive_delete_is_a_deterministic_hard_finding(tmp_path: Path) -> None:
    findings = run_deterministic_checks(_context(tmp_path, "rm -rf ./cache"))
    destructive = next(finding for finding in findings if finding.check == "known_destructive")
    assert destructive.triggered is True
    assert destructive.reason_code == "RECURSIVE_DELETE"
    assert destructive.blocking is True


@pytest.mark.parametrize(
    "command",
    [
        "git branch -f -d topic",
        "git branch --force --delete topic",
        "git branch -df topic",
        "git branch -fd topic",
        "git branch -rD origin/topic",
        "git -C 'directory with spaces' branch -df topic",
        "bash -c 'git branch -df topic'",
    ],
)
def test_force_branch_deletion_flag_forms_are_blocked(tmp_path, command):
    finding = next(
        f for f in run_deterministic_checks(_context(tmp_path, command)) if f.check == "git_risk"
    )
    assert finding.blocking and finding.reason_code == "BRANCH_DELETE_FORCE"


@pytest.mark.parametrize(
    "command", ["git clean --force", "git clean -ffdx", "git -C . clean --force -d"]
)
def test_force_clean_flag_forms_are_blocked(tmp_path, command):
    finding = next(
        f
        for f in run_deterministic_checks(_context(tmp_path, command))
        if f.check == "known_destructive"
    )
    assert finding.blocking and finding.reason_code == "GIT_CLEAN_FORCE"


@pytest.mark.parametrize(
    "command", ["git branch -d topic", "git branch -d -- -f", "git clean -- -f", "git clean -n"]
)
def test_git_option_end_marker_and_safe_flags(tmp_path, command):
    findings = run_deterministic_checks(_context(tmp_path, command))
    assert not any(
        f.triggered and f.blocking for f in findings if f.check in {"git_risk", "known_destructive"}
    )


@pytest.mark.parametrize(
    "command,reason",
    [
        ("git push -vf origin main", "FORCE_PUSH"),
        ("git push -fv origin main", "FORCE_PUSH"),
        ("git push --force-with-lease=main origin main", "FORCE_PUSH"),
        ("git rebase --interactive HEAD~2", "HISTORY_REWRITE"),
        ("git rebase --autosquash -i HEAD~2", "HISTORY_REWRITE"),
        ("git rebase -iv HEAD~2", "HISTORY_REWRITE"),
    ],
)
def test_git_risky_combined_and_long_flags(tmp_path, command, reason):
    finding = next(
        f for f in run_deterministic_checks(_context(tmp_path, command)) if f.check == "git_risk"
    )
    assert finding.blocking and finding.reason_code == reason


@pytest.mark.parametrize(
    "command",
    ["git push -- -f", "git rebase -- -i", "git reset -- --hard", "git commit -- --amend"],
)
def test_git_risky_flag_names_after_marker_are_arguments(tmp_path, command):
    findings = run_deterministic_checks(_context(tmp_path, command))
    assert not any(f.triggered for f in findings if f.check in {"git_risk", "known_destructive"})


@pytest.mark.parametrize(
    "command",
    [
        "sudo rm -rf ./cache",
        "env FOO=1 rm -rf ./cache",
        "bash -c 'rm -rf ./cache'",
        "eval 'rm -rf ./cache'",
        "xargs rm -rf ./cache",
        "/bin/rm --recursive ./cache",
        "echo ready; rm -rf ./cache",
    ],
)
def test_wrapped_recursive_delete_is_a_deterministic_hard_finding(
    tmp_path: Path, command: str
) -> None:
    findings = run_deterministic_checks(_context(tmp_path, command))
    destructive = next(finding for finding in findings if finding.check == "known_destructive")
    assert destructive.triggered is True
    assert destructive.reason_code == "RECURSIVE_DELETE"
    assert destructive.blocking is True


@pytest.mark.parametrize(
    "command",
    [
        "python -c \"import shutil; shutil.rmtree('./cache')\"",
        "python -c \"import os; os.system('rm -rf ./cache')\"",
    ],
)
def test_interpreter_side_effects_are_deterministic_hard_findings(
    tmp_path: Path, command: str
) -> None:
    findings = run_deterministic_checks(_context(tmp_path, command))
    destructive = next(finding for finding in findings if finding.check == "known_destructive")
    assert destructive.triggered is True
    assert destructive.reason_code == "INTERPRETER_SIDE_EFFECT"
    assert destructive.blocking is True


def test_repository_escape_is_canonicalized_and_blocked(tmp_path: Path) -> None:
    findings = run_deterministic_checks(_context(tmp_path, "cat ../../outside/result.txt"))
    boundary = next(finding for finding in findings if finding.check == "repo_boundary")
    assert boundary.triggered is True
    assert boundary.reason_code == "TARGET_OUTSIDE_REPO"
    assert boundary.blocking is True


@pytest.mark.parametrize(
    "command",
    [
        "git -C../outside status",
        "pytest --rootdir=/outside tests/",
        "cat //outside/result.txt",
        "curl file:///outside/result.txt",
        "python -c \"open('../outside/result.txt', 'w').write('x')\"",
        "python -c \"open('/outside/result.txt', 'w').write('x')\"",
    ],
)
def test_path_forms_that_bypass_a_shell_are_blocked(tmp_path: Path, command: str) -> None:
    boundary = next(
        finding
        for finding in run_deterministic_checks(_context(tmp_path, command))
        if finding.check == "repo_boundary"
    )
    assert boundary.triggered is True
    assert boundary.reason_code == "TARGET_OUTSIDE_REPO"
    assert boundary.blocking is True


def test_repository_symlink_loop_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "a").symlink_to(tmp_path / "b")
    (tmp_path / "b").symlink_to(tmp_path / "a")
    boundary = next(
        finding
        for finding in run_deterministic_checks(_context(tmp_path, "cat a/file"))
        if finding.check == "repo_boundary"
    )
    assert boundary.triggered is True
    assert boundary.reason_code == "TARGET_OUTSIDE_REPO"
    assert boundary.blocking is True


def test_secret_environment_reference_is_detected_without_value(tmp_path: Path) -> None:
    context = _context(tmp_path, "echo $API_KEY")
    assert _triggered(context, "secret_pattern")


def test_safe_python_flag_is_not_mistaken_for_a_path(tmp_path: Path) -> None:
    findings = run_deterministic_checks(_context(tmp_path, "python -c \"print('hello')\""))
    boundary = next(finding for finding in findings if finding.check == "repo_boundary")
    assert boundary.triggered is False


def test_tool_file_path_is_checked_for_repository_escape(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    context = EvaluationContext(
        repository_root=str(root),
        working_directory=str(root),
        proposed_action=ProposedAction(
            type="tool_call",
            input={"file_path": str(root.parent / "outside.txt")},
        ),
    )
    boundary = next(
        finding for finding in run_deterministic_checks(context) if finding.check == "repo_boundary"
    )
    assert boundary.triggered is True
    assert boundary.reason_code == "TARGET_OUTSIDE_REPO"


def test_tool_input_secret_is_detected_without_returning_the_value(tmp_path: Path) -> None:
    context = _context(tmp_path, "write-file")
    context.proposed_action = ProposedAction(
        type="tool_call",
        input={"content": "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz123456"},
    )
    secret = next(
        finding
        for finding in run_deterministic_checks(context)
        if finding.check == "secret_pattern"
    )
    assert secret.triggered is True
    assert secret.reason_code in {"AUTHORIZATION_HEADER", "KNOWN_TOKEN_PATTERN"}


@pytest.mark.parametrize(
    "tool_input",
    [
        {"operations": [{"file_path": "../outside.txt"}]},
        [{"options": {"path": "../outside.txt"}}],
        {"operations": [[{"destination": "../outside.txt"}]]},
        {"path": {"options": [{"file_path": "../outside.txt"}]}},
    ],
)
def test_nested_tool_input_paths_cannot_escape_repository(tmp_path: Path, tool_input) -> None:
    context = _context(tmp_path, "")
    context.proposed_action = ProposedAction(type="tool_call", input=tool_input)
    assert _triggered(context, "repo_boundary")


def test_nested_tool_input_checks_only_path_fields(tmp_path: Path) -> None:
    context = _context(tmp_path, "")
    context.proposed_action = ProposedAction(
        type="tool_call",
        input={"operations": [{"path": "src/file.py", "content": "../example.txt"}]},
    )
    assert not _triggered(context, "repo_boundary")


@pytest.mark.parametrize(
    "command,reason",
    [
        ("rm ./cache -rf", "RECURSIVE_DELETE"),
        ("rm ./cache --recursive", "RECURSIVE_DELETE"),
        ("git -C . reset --hard", "GIT_HARD_RESET"),
        ("git -c advice.statusHints=false clean -fd", "GIT_CLEAN_FORCE"),
        ("git --no-pager -C. push --force", "FORCE_PUSH"),
        ("git --git-dir=.git push origin +main", "FORCE_PUSH"),
        ("git push origin +main:main", "FORCE_PUSH"),
    ],
)
def test_destructive_option_forms_are_blocked(tmp_path, command, reason):
    findings = run_deterministic_checks(_context(tmp_path, command))
    assert any(f.triggered and f.blocking and f.reason_code == reason for f in findings)


@pytest.mark.parametrize("command", ["rm -- -rf", "git -C . status", "git push origin main"])
def test_non_destructive_option_forms_remain_clear(tmp_path, command):
    findings = run_deterministic_checks(_context(tmp_path, command))
    assert not any(f.triggered and f.blocking for f in findings)


@pytest.mark.parametrize("use_argv", [False, True])
@pytest.mark.parametrize(
    "args",
    [
        ["git", "-C", "space dir", "reset", "--hard"],
        ["git", "-Cspace dir", "push", "--force"],
        ["git", "--work-tree=space dir", "push", "origin", "+main"],
    ],
)
def test_git_global_options_preserve_argument_boundaries(tmp_path, use_argv, args):
    import shlex

    context = _context(tmp_path, shlex.join(args))
    if use_argv:
        context.proposed_action = ProposedAction(argv=args)
    assert any(
        f.triggered and f.blocking and f.check in {"git_risk", "known_destructive"}
        for f in run_deterministic_checks(context)
    )
