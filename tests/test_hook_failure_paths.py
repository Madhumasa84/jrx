"""What a host receives when a hook evaluation fails, through the real entry points.

Every failure jrx can catch becomes the adapter's deny response with exit status 0,
because hosts disagree about non-zero exits (Claude Code lets the call proceed on any
status other than 2). A process that cannot start or import jrx cannot answer at all;
that case is shown here so the host-side setting that covers it is not forgotten.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from jev_reflex import cli
from jev_reflex.cli import app

HOOKS = {
    "claude-code-hook": lambda out: out["hookSpecificOutput"]["permissionDecision"] == "deny",
    "codex-hook": lambda out: out["hookSpecificOutput"]["permissionDecision"] == "deny",
    "deepseek-hook": lambda out: out["hookSpecificOutput"]["permissionDecision"] == "deny",
    "antigravity-hook": lambda out: out["decision"] == "deny",
    "openrouter-hook": lambda out: bool(out.get("block")) or out.get("decision") == "deny",
    "pi-hook": lambda out: out["block"] is True,
}


@pytest.mark.parametrize("hook", sorted(HOOKS))
@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit, MemoryError])
def test_interrupts_inside_a_hook_still_deny(hook, interrupt, monkeypatch) -> None:
    def fail() -> dict:
        raise interrupt()

    monkeypatch.setattr(cli, "read_hook_payload", fail)
    result = CliRunner().invoke(app, [hook, "--demo", "--mode", "enforce"], input="{}")
    assert result.exit_code == 0, result.output
    assert HOOKS[hook](json.loads(result.stdout)), result.stdout


def _hook_process(args: list[str], stdin: str, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, "-m", "jev_reflex", *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, **(env or {})},
        check=False,
    )


@pytest.mark.parametrize("stdin", ["", "not json", "[]", "{}"])
def test_real_process_denies_malformed_events_with_status_zero(tmp_path: Path, stdin) -> None:
    (tmp_path / "reflex.yaml").write_text("mode: enforce\n")
    completed = _hook_process(
        ["claude-code-hook", "--config", str(tmp_path / "reflex.yaml")], stdin
    )
    assert completed.returncode == 0, completed.stderr
    assert HOOKS["claude-code-hook"](json.loads(completed.stdout))


def test_real_process_denies_a_missing_or_invalid_policy(tmp_path: Path) -> None:
    event = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(tmp_path)})
    missing = _hook_process(["claude-code-hook", "--config", str(tmp_path / "absent.yaml")], event)
    invalid_policy = tmp_path / "invalid.yaml"
    invalid_policy.write_text("mode: [\n")
    invalid = _hook_process(["claude-code-hook", "--config", str(invalid_policy)], event)
    for completed in (missing, invalid):
        assert completed.returncode == 0, completed.stderr
        assert HOOKS["claude-code-hook"](json.loads(completed.stdout))


def test_a_hook_that_cannot_import_jrx_gives_the_host_no_answer(tmp_path: Path) -> None:
    # Shadow a dependency so the interpreter fails before jrx's own error handling runs.
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "typer.py").write_text("raise ImportError('simulated broken install')\n")
    completed = _hook_process(["claude-code-hook", "--demo"], "{}", env={"PYTHONPATH": str(shadow)})
    assert completed.returncode not in (0, 2)
    assert completed.stdout == ""
    # Only the host can stop the call here: `jrx setup` writes onFailure: block for
    # Claude Code (tests/test_review_cli_workspace.py), and the TypeScript bridges block
    # on any non-zero exit (tests/test_typescript_adapters.py).


@pytest.mark.parametrize("stdin", ["{not json", "", "[]"])
def test_unreadable_openrouter_event_is_denied_in_both_event_shapes(stdin) -> None:
    # jrx cannot tell PreToolUse from PermissionRequest, so the answer must deny under
    # both: PreToolUse reads "block", PermissionRequest reads "decision".
    result = CliRunner().invoke(app, ["openrouter-hook", "--demo"], input=stdin)
    assert result.exit_code == 0, result.output
    output = json.loads(result.stdout)
    assert output["block"]
    assert output["decision"] == "deny"
