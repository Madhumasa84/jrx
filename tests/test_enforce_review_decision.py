"""REVIEW in enforce mode becomes a user decision or a denial at the CLI boundary.

``touch ran-$JRX_PROBE`` is inert and needs REVIEW from deterministic rules alone
(an unresolved expansion in a write target). ``jrx exec`` runs argv without a shell,
so if it executes, a file literally named ``ran-$JRX_PROBE`` appears.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from jev_reflex.cli import app

COMMAND = "touch ran-$JRX_PROBE"
MARKER = "ran-$JRX_PROBE"


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / ".git").mkdir()
    (tmp_path / "reflex.yaml").write_text("mode: enforce\n")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _exec(workspace: Path, *extra: str, answer: str = ""):
    args = ["exec", "--config", str(workspace / "reflex.yaml"), "--demo", "--command", COMMAND]
    return CliRunner().invoke(app, [*args, *extra], input=answer)


def test_check_reports_review_as_blocked_in_enforce_mode(workspace: Path) -> None:
    result = CliRunner().invoke(
        app, ["check", "--config", "reflex.yaml", "--demo", "--command", COMMAND, "--json"]
    )
    assert json.loads(result.stdout)["decision"] == "REVIEW"
    assert result.exit_code == 2


def test_exec_without_an_answer_denies_review(workspace: Path) -> None:
    result = _exec(workspace)
    assert result.exit_code == 2, result.output
    assert "Approve and execute?" in result.output
    assert not (workspace / MARKER).exists()


def test_exec_runs_review_only_after_the_user_confirms(workspace: Path) -> None:
    declined = _exec(workspace, answer="n\n")
    assert declined.exit_code == 2
    assert not (workspace / MARKER).exists()
    confirmed = _exec(workspace, answer="y\n")
    assert confirmed.exit_code == 0, confirmed.output
    assert (workspace / MARKER).exists()


def test_exec_still_runs_allow_without_asking(workspace: Path) -> None:
    result = CliRunner().invoke(
        app,
        ["exec", "--config", "reflex.yaml", "--demo", "--command", "touch allowed"],
    )
    assert result.exit_code == 0, result.output
    assert "Approve" not in result.output
    assert (workspace / "allowed").exists()
