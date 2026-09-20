"""Tests for the golden fixture policy regression runner."""

from pathlib import Path

import yaml
from typer.testing import CliRunner

from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig, ThresholdConfig, load_config
from jev_reflex.golden_runner import (
    DEFAULT_FIXTURES_DIR,
    FixtureCase,
    load_fixtures,
    run_fixtures,
)

runner = CliRunner()


def test_default_policy_all_pass() -> None:
    """Verify that all golden fixtures pass on the default policy (reflex.example.yaml)."""
    config = load_config(Path("reflex.example.yaml"))
    report = run_fixtures(config=config)
    assert report.all_passed, f"Fixtures failed: {report.summary_table()}"
    assert report.failed == 0
    assert report.total >= 15
    assert report.passed == report.total


def test_runner_reports_failure_on_deliberately_wrong_expectation(tmp_path: Path) -> None:
    """Verify that the runner correctly reports a failure when expected_decision is wrong."""
    bad_fixture = {
        "name": "deliberate-failure-case",
        "category": "destructive",
        "description": "Destructive command that should HOLD, but fixture claims ALLOW",
        "context": {
            "command": "rm -rf /cache",
            "task": "Clean cache files",
        },
        "expected_decision": "ALLOW",  # Deliberately wrong: actual will be HOLD
    }
    fixture_file = tmp_path / "bad_fixture.yaml"
    with fixture_file.open("w", encoding="utf-8") as f:
        yaml.safe_dump(bad_fixture, f)

    report = run_fixtures(fixtures_dir=tmp_path)
    assert not report.all_passed
    assert report.failed == 1
    assert report.passed == 0
    assert len(report.failures) == 1

    failure = report.failures[0]
    assert failure.name == "deliberate-failure-case"
    assert failure.expected == "ALLOW"
    assert failure.actual == "HOLD"
    assert not failure.passed
    assert "expected ALLOW != actual HOLD" in failure.diff_summary()
    assert "FAIL" in report.summary_table()


def test_runner_boundary_threshold_detection(tmp_path: Path) -> None:
    """Verify that boundary cases with mocked signals detect threshold crossings."""
    # Test case right at review threshold 0.70 expects REVIEW
    boundary_fixture = {
        "name": "boundary-test-case",
        "category": "boundary",
        "description": "Signal at review threshold",
        "context": {
            "command": "cat info.txt",
            "task": "Read file",
        },
        "mocked_jev_signals": {
            "security_sensitive": 0.70,
        },
        "expected_decision": "ALLOW",  # Wrong! At 0.70, it must be REVIEW
    }
    fixture_file = tmp_path / "boundary.yaml"
    with fixture_file.open("w", encoding="utf-8") as f:
        yaml.safe_dump(boundary_fixture, f)

    report = run_fixtures(fixtures_dir=tmp_path)
    assert not report.all_passed
    assert report.failures[0].expected == "ALLOW"
    assert report.failures[0].actual == "REVIEW"


def test_cli_policy_test_command() -> None:
    """Verify `jrx policy test --config reflex.example.yaml` passes via CLI."""
    result = runner.invoke(app, ["policy", "test", "--config", "reflex.example.yaml"])
    assert result.exit_code == 0, result.stdout
    assert "PASS" in result.stdout
    assert "Total: 24" in result.stdout or "Total:" in result.stdout


def test_cli_policy_test_json() -> None:
    """Verify `jrx policy test --json` produces valid JSON with all_passed=True."""
    import json

    result = runner.invoke(app, ["policy", "test", "--config", "reflex.example.yaml", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)
    assert body["all_passed"] is True
    assert body["failed"] == 0
    assert body["total"] >= 15
    assert len(body["results"]) == body["total"]


def test_cli_policy_test_fails_on_wrong_expectation(tmp_path: Path) -> None:
    """Verify CLI exits with code 1 when a fixture fails."""
    bad_fixture = {
        "name": "cli-failure-case",
        "category": "test",
        "description": "Should fail",
        "context": {
            "command": "rm -rf /data",
            "task": "Delete",
        },
        "expected_decision": "ALLOW",
    }
    with (tmp_path / "bad.yaml").open("w", encoding="utf-8") as f:
        yaml.safe_dump(bad_fixture, f)

    result = runner.invoke(app, ["policy", "test", "--fixtures", str(tmp_path)])
    assert result.exit_code == 1, result.stdout
    assert "FAIL" in result.stdout
    assert "expected ALLOW != actual HOLD" in result.stdout


def test_policy_change_catches_regression() -> None:
    """Verify that a policy change that raises review threshold flips a boundary fixture."""
    # Stricter review threshold (0.75 instead of 0.70)
    # The fixture boundary-security-threshold has security_sensitive=0.70
    # Under default (review=0.70), 0.70 -> REVIEW
    # Under altered (review=0.75), 0.70 < 0.75 -> ALLOW, which will fail!
    altered_config = ReflexConfig(thresholds=ThresholdConfig(review=0.75, strong=0.90))
    report = run_fixtures(config=altered_config)
    assert not report.all_passed
    assert report.failed >= 1
    # Check that the boundary case was among failures
    failed_names = {f.name for f in report.failures}
    assert "boundary-security-threshold" in failed_names


def test_fixture_loading() -> None:
    """Verify load_fixtures loads all files in DEFAULT_FIXTURES_DIR."""
    cases = load_fixtures(DEFAULT_FIXTURES_DIR)
    assert len(cases) >= 15
    for case in cases:
        assert isinstance(case, FixtureCase)
        assert case.name
        assert case.category
        assert case.expected_decision in ("ALLOW", "REVIEW", "HOLD")
        assert case.context.proposed_action.command or case.context.proposed_action.display()
