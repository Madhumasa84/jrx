"""The enforcement matrix, checked through the real entry points.

Every native hook adapter, ``jrx check`` and ``jrx exec`` is driven with an installed
policy file (mode set in the file, not on the command line) and inputs that produce
ALLOW, REVIEW and HOLD from deterministic rules, an unavailable semantic judge, a broker
that never answers, and malformed or missing input. ``EXPECTED`` is the single
statement of what each host must do; ``docs/guarantees.md`` renders the same table
and ``test_guarantees_doc_matches_the_tested_matrix`` keeps the two equal.
"""

from __future__ import annotations

import json
import re
import socket
import tempfile
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from jev_reflex.cli import app

ROOT = Path(__file__).resolve().parents[1]
MODES = ("advisory", "review", "enforce")

# Inputs: (command, demo). Demo mode replaces only the semantic judge; the decisions
# below come from deterministic rules. "unavailable" runs the real judge without a key.
COMMANDS = {
    "ALLOW": ("pytest tests/", True),
    "REVIEW": ("ssh build-host ls", True),
    "HOLD": ("rm -rf ./cache", True),
    "judge unavailable": ("pytest tests/", False),
    "judge timeout": ("pytest tests/", False),
}
FAILURES = ("malformed JSON", "empty input", "missing policy", "invalid policy")

# Which hosts can put a question to the user.
ADAPTERS: dict[str, tuple[str, bool]] = {
    "claude": ("claude-code-hook", True),
    "antigravity": ("antigravity-hook", True),
    "openrouter-permission": ("openrouter-hook", True),
    "codex": ("codex-hook", False),
    "deepseek": ("deepseek-hook", False),
    "openrouter-pre": ("openrouter-hook", False),
    "pi": ("pi-hook", False),
}


def expected(can_ask: bool, mode: str, case: str) -> str:
    """What the host must do: proceed (JRX does not stop it), ask, or deny."""
    if case in FAILURES:
        return "deny"
    if mode == "advisory":
        return "proceed"
    if case.startswith("judge"):
        return "deny"
    decision = "REVIEW" if mode == "review" and case == "ALLOW" else case
    if decision == "HOLD":
        return "deny"
    if decision == "REVIEW":
        return "ask" if can_ask else "deny"
    return "proceed"


EXPECTED = {
    (adapter, mode, case): expected(can_ask, mode, case)
    for adapter, (_, can_ask) in ADAPTERS.items()
    for mode in MODES
    for case in (*COMMANDS, *FAILURES)
}


def _payload(adapter: str, command: str, workspace: Path) -> dict[str, object]:
    cwd = str(workspace)
    if adapter == "antigravity":
        args = {"CommandLine": command, "Cwd": cwd}
        return {"workspacePaths": [cwd], "toolCall": {"name": "run_command", "args": args}}
    if adapter.startswith("openrouter"):
        event = "PermissionRequest" if adapter.endswith("permission") else "PreToolUse"
        return {"hookName": event, "toolName": "bash", "toolInput": {"command": command}}
    if adapter == "pi":
        return {"toolName": "bash", "input": {"command": command}, "cwd": cwd}
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": cwd,
    }


def outcome(adapter: str, output: dict[str, object]) -> str:
    if adapter in {"claude", "codex", "deepseek"}:
        specific = output.get("hookSpecificOutput", {})
        assert isinstance(specific, dict)
        decision = specific.get("permissionDecision")
        # An explicit allow would skip the host's own permission prompt.
        assert decision != "allow", output
        return {"deny": "deny", "ask": "ask", None: "proceed"}[decision]
    if adapter == "antigravity":
        # Antigravity's "allow" delegates to the next hook or its default policy.
        return {"deny": "deny", "force_ask": "ask", "allow": "proceed"}[output["decision"]]
    if adapter == "openrouter-permission":
        return {"deny": "deny", "ask_user": "ask"}.get(output.get("decision"), "proceed")
    return "deny" if output.get("block") else "proceed"


@pytest.fixture(scope="module")
def silent_broker() -> Iterator[str]:
    """A Unix socket that accepts connections and never answers."""
    directory = tempfile.mkdtemp(prefix="jrx-", dir="/tmp")  # short path for AF_UNIX
    path = str(Path(directory) / "broker.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(16)
    held: list[socket.socket] = []
    stop = threading.Event()

    def accept() -> None:
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                held.append(server.accept()[0])
            except OSError:
                continue

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield path
    stop.set()
    thread.join(timeout=2)
    for connection in held:
        connection.close()
    server.close()
    Path(path).unlink(missing_ok=True)
    Path(directory).rmdir()


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / ".git").mkdir()
    (tmp_path / "cache").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _policy(workspace: Path, mode: str, case: str, broker: str) -> Path:
    policy = workspace / "reflex.yaml"
    if case == "invalid policy":
        policy.write_text("mode: [\n")
    elif case == "judge timeout":
        settings = {"transport": "broker", "socket": broker, "request_timeout": 0.5}
        policy.write_text(json.dumps({"mode": mode, "jev": settings}))
    else:
        policy.write_text(f"mode: {mode}\n")
    return policy


def _run_hook(adapter: str, mode: str, case: str, workspace: Path, broker: str) -> str:
    hook, _ = ADAPTERS[adapter]
    policy = _policy(workspace, mode, case, broker)
    args = [hook, "--config", str(policy)]
    if case == "missing policy":
        args = [hook, "--config", str(workspace / "absent.yaml")]
    if case == "malformed JSON":
        stdin = "{not json"
    elif case == "empty input":
        stdin = ""
    else:
        command, demo = COMMANDS.get(case, ("ls", True))
        stdin = json.dumps(_payload(adapter, command, workspace))
        if demo:
            args.append("--demo")
    result = CliRunner().invoke(app, args, input=stdin)
    assert result.exit_code == 0, result.output
    return outcome(adapter, json.loads(result.stdout))


@pytest.mark.parametrize("case", [*COMMANDS, *FAILURES])
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("adapter", sorted(ADAPTERS))
def test_hook_matrix(adapter, mode, case, workspace, silent_broker) -> None:
    got = _run_hook(adapter, mode, case, workspace, silent_broker)
    assert got == EXPECTED[(adapter, mode, case)], (adapter, mode, case)


# --- jrx check and jrx exec ------------------------------------------------------------

CHECK_EXIT = {"proceed": 0, "deny": 2}
EXEC_COMMANDS = {
    "ALLOW": "touch allowed",
    "REVIEW": "touch ran-$JRX_PROBE",
    "HOLD": "rm -rf ./cache",
}
EXEC_MARKERS: dict[str, Callable[[Path], bool]] = {
    "ALLOW": lambda ws: (ws / "allowed").exists(),
    "REVIEW": lambda ws: (ws / "ran-$JRX_PROBE").exists(),
    "HOLD": lambda ws: not (ws / "cache").exists(),
}


@pytest.mark.parametrize("case", ["ALLOW", "REVIEW", "HOLD", "judge unavailable"])
@pytest.mark.parametrize("mode", MODES)
def test_check_exit_status(mode, case, workspace, silent_broker) -> None:
    command, demo = COMMANDS[case]
    policy = _policy(workspace, mode, case, silent_broker)
    args = ["check", "--config", str(policy), "--command", command, *(["--demo"] if demo else [])]
    result = CliRunner().invoke(app, args)
    # check cannot ask: anything the host would have to ask about exits 2.
    verdict = expected(False, mode, case)
    assert result.exit_code == CHECK_EXIT[verdict], result.output


@pytest.mark.parametrize("case", ["ALLOW", "REVIEW", "HOLD"])
@pytest.mark.parametrize("mode", MODES)
def test_exec_runs_only_what_policy_or_the_user_allows(
    mode, case, workspace, silent_broker
) -> None:
    policy = _policy(workspace, mode, case, silent_broker)
    args = ["exec", "--config", str(policy), "--demo", "--command", EXEC_COMMANDS[case]]
    # No terminal answer: an action that needs confirmation must not run.
    result = CliRunner().invoke(app, args, input="")
    ran = EXEC_MARKERS[case](workspace)
    should_run = expected(False, mode, case) == "proceed"
    assert ran is should_run, (mode, case, result.output)
    assert (result.exit_code == 0) is should_run, result.output


# --- the documentation renders this matrix ---------------------------------------------


def _doc_matrix() -> dict[tuple[str, str, str], str]:
    text = (ROOT / "docs" / "guarantees.md").read_text(encoding="utf-8")
    section = text.split("<!-- matrix:start -->", 1)[1].split("<!-- matrix:end -->", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("| ")]
    header = [cell.strip() for cell in rows[0].strip("|").split("|")]
    cases = [re.sub(r"`", "", cell) for cell in header[2:]]
    found: dict[tuple[str, str, str], str] = {}
    for row in rows[2:]:
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        adapter, mode = cells[0].strip("`"), cells[1].strip("`")
        for case, value in zip(cases, cells[2:], strict=True):
            found[(adapter, mode, case)] = value
    return found


def test_guarantees_doc_matches_the_tested_matrix() -> None:
    assert _doc_matrix() == EXPECTED
