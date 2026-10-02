"""Offline harness CLI checks; no model requests or provider credentials."""

from __future__ import annotations

import asyncio
import os
import pty
import sys
import termios
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from jev_reflex import harness_cli

runner = CliRunner()


def test_harness_help_lists_commands():
    result = runner.invoke(harness_cli.app, ["--help"])
    assert result.exit_code == 0
    for name in ("run", "resume", "status", "acp"):
        assert name in result.output


def test_status_missing_session_offline(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    result = runner.invoke(
        harness_cli.app, ["status", "not-a-session", "--workspace", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert "invalid harness session ID" in result.output


def test_acp_missing_executable(tmp_path):
    config = tmp_path / "policy.yaml"
    config.write_text("mode: enforce\n")
    result = runner.invoke(
        harness_cli.app,
        ["acp", "--task", "hello", "--workspace", str(tmp_path), "--config", str(config)],
    )
    assert result.exit_code == 2
    assert "executable after --" in result.output


def test_acp_real_local_agent(tmp_path, monkeypatch):
    pytest.importorskip("acp")
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    config = tmp_path / "policy.yaml"
    config.write_text("mode: enforce\n")
    agent = tmp_path / "agent.py"
    agent.write_text("""import json,sys
for line in sys.stdin:
 request=json.loads(line)
 method=request['method']
 if method=='initialize': result={'protocolVersion':1,'agentCapabilities':{}}
 elif method=='session/new': result={'sessionId':'offline'}
 elif method=='session/prompt': result={'stopReason':'end_turn'}
 else: continue
 print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}),flush=True)
""")
    result = runner.invoke(
        harness_cli.app,
        [
            "acp",
            "--task",
            "hello",
            "--workspace",
            str(tmp_path),
            "--config",
            str(config),
            "--",
            sys.executable,
            str(agent),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "offline" in result.output
    assert "end_turn" in result.output


def request(kind="execute", raw=None):
    return {
        "tool_call": {"kind": kind, "rawInput": raw if raw is not None else {"command": "pwd"}},
        "options": [{"kind": "allow_once", "optionId": "once"}],
    }


@pytest.mark.parametrize(
    "kind,raw",
    [
        ("other", {"command": "pwd"}),
        (None, {"command": "pwd"}),
        ("execute", {"argv": ["pwd"]}),
        ("edit", "unstructured"),
    ],
)
def test_uninspectable_acp_permission_denied(tmp_path, kind, raw):
    assert (
        asyncio.run(harness_cli._acp_permission(request(kind, raw), tmp_path, "task", None)) is None
    )


def test_acp_rechecks_policy_after_approval(tmp_path, monkeypatch):
    from jev_reflex.adapters import harness

    results = iter(["ALLOW", "HOLD"])
    calls = []

    def evaluate(payload, **kwargs):
        calls.append(payload)
        return SimpleNamespace(decision=next(results), degraded=False), "fresh policy"

    async def approve():
        return True

    monkeypatch.setattr(harness, "evaluate_harness_hook", evaluate)
    monkeypatch.setattr(harness_cli, "_confirm_acp_once", approve)
    assert (
        asyncio.run(
            asyncio.wait_for(harness_cli._acp_permission(request(), tmp_path, "task", None), 3)
        )
        is None
    )
    assert len(calls) == 2


def test_acp_terminal_wait_cancellable(monkeypatch):
    master, slave = pty.openpty()
    stream = os.fdopen(os.dup(slave), "r")
    monkeypatch.setattr(harness_cli.typer, "get_text_stream", lambda name: stream)

    async def check():
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(harness_cli._confirm_acp_once(), 0.02)
        os.write(master, b"y\n")
        assert await asyncio.wait_for(harness_cli._confirm_acp_once(), 1)

    try:
        asyncio.run(check())
    finally:
        stream.close()
        os.close(master)
        os.close(slave)


def test_acp_raw_terminal_denied(monkeypatch):
    master, slave = pty.openpty()
    stream = os.fdopen(os.dup(slave), "r")
    attributes = termios.tcgetattr(slave)
    attributes[3] &= ~termios.ICANON
    termios.tcsetattr(slave, termios.TCSANOW, attributes)
    monkeypatch.setattr(harness_cli.typer, "get_text_stream", lambda name: stream)
    try:
        assert asyncio.run(harness_cli._confirm_acp_once()) is False
    finally:
        stream.close()
        os.close(master)
        os.close(slave)
