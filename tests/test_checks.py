from pathlib import Path

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


def test_repository_escape_is_canonicalized_and_blocked(tmp_path: Path) -> None:
    findings = run_deterministic_checks(_context(tmp_path, "cat ../../outside/result.txt"))
    boundary = next(finding for finding in findings if finding.check == "repo_boundary")
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
