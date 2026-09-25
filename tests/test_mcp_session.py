"""Structured MCP enforcement and atomic session budget checks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from jev_reflex.cli import _execute_argv, app
from jev_reflex.config import ReflexConfig, SessionLimitsConfig
from jev_reflex.session_limits import SessionLimitError, SessionStore


def _session(tmp_path: Path, **limits) -> SessionLimitsConfig:
    return SessionLimitsConfig.model_validate(
        {"enabled": True, "path": str(tmp_path / "sessions.sqlite3"), **limits}
    )


def test_session_limits_are_atomic_and_stop_is_persistent(tmp_path: Path) -> None:
    config = _session(
        tmp_path,
        max_tool_calls=3,
        max_semantic_evaluations=2,
        max_semantic_spend_usd=0.02,
        reserved_cost_per_evaluation_usd=0.01,
        max_risky_attempts=2,
    )
    store = SessionStore(config)

    def reserve():
        try:
            store.reserve("agent-1", semantic=1)
            return True
        except SessionLimitError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda _: reserve(), range(10))) == 2
    status = store.status("agent-1")
    assert status["semantic_evaluations"] == 2
    assert status["reserved_spend_usd"] == pytest.approx(0.02)
    store.record_risky("agent-1", "same action")
    with pytest.raises(SessionLimitError, match="repeated risky"):
        store.record_risky("agent-1", "same action")
    store.stop("agent-1")
    with pytest.raises(SessionLimitError, match="stopped"):
        store.reserve("agent-1", semantic=0)
    assert SessionStore(config).status("agent-1")["stopped"] is True


def test_semantic_spend_and_tool_call_limits(tmp_path: Path) -> None:
    store = SessionStore(
        _session(
            tmp_path,
            max_tool_calls=2,
            max_semantic_evaluations=10,
            max_semantic_spend_usd=0.015,
            reserved_cost_per_evaluation_usd=0.01,
        )
    )
    store.reserve("agent-1", semantic=1)
    with pytest.raises(SessionLimitError, match="spend"):
        store.reserve("agent-1", semantic=1)
    store.reserve("agent-1", semantic=0)
    with pytest.raises(SessionLimitError, match="tool-call"):
        store.reserve("agent-1", semantic=0)


def test_repeated_risk_limit_persistently_stops_session(tmp_path: Path) -> None:
    config = _session(tmp_path, max_risky_attempts=2)
    store = SessionStore(config)
    store.reserve("agent-1", semantic=0)
    store.record_risky("agent-1", "risky action")
    assert store.status("agent-1")["stopped"] is False
    with pytest.raises(SessionLimitError, match="repeated risky"):
        store.record_risky("agent-1", "risky action")

    reopened = SessionStore(config)
    assert reopened.status("agent-1")["stopped"] is True
    with pytest.raises(SessionLimitError, match="stopped"):
        reopened.reserve("agent-1", semantic=0)
    with pytest.raises(SessionLimitError, match="stopped"):
        reopened.reserve("agent-1", semantic=0, tool_calls=0)
    with pytest.raises(SessionLimitError, match="stopped"):
        reopened.record_risky("agent-1", "different action")
    reopened.reserve("agent-2", semantic=0)


def test_exec_timeout_and_admin_stop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = ReflexConfig.model_validate(
        {"session": _session(tmp_path, max_execution_seconds=1).model_dump()}
    )
    monkeypatch.setenv("JRX_SESSION_ID", "agent-1")
    with pytest.raises(SessionLimitError, match="execution time"):
        _execute_argv([sys.executable, "-c", "import time; time.sleep(10)"], tmp_path, config)
    SessionStore(config.session).stop("agent-1")
    with pytest.raises(SessionLimitError, match="stopped"):
        _execute_argv([sys.executable, "-c", "print('should not run')"], tmp_path, config)


def test_admin_stop_cli_blocks_next_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "reflex.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "mode": "enforce",
                "session": {"enabled": True, "path": str(tmp_path / "sessions.sqlite3")},
            }
        )
    )
    monkeypatch.setenv("JRX_SESSION_ID", "agent-1")
    runner = CliRunner()
    stopped = runner.invoke(app, ["session", "stop", "agent-1", "--config", str(config_path)])
    assert stopped.exit_code == 0, stopped.output
    check = runner.invoke(app, ["check", "--config", str(config_path), "--command", "pwd"])
    assert check.exit_code == 2


def test_admin_stop_terminates_running_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = ReflexConfig.model_validate(
        {"session": _session(tmp_path, max_execution_seconds=20).model_dump()}
    )
    monkeypatch.setenv("JRX_SESSION_ID", "agent-1")
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            _execute_argv,
            [sys.executable, "-c", "import time; time.sleep(10)"],
            tmp_path,
            config,
        )
        store = SessionStore(config.session)
        for _ in range(50):
            try:
                store.status("agent-1")
                break
            except SessionLimitError:
                time.sleep(0.02)
        store.stop("agent-1")
        with pytest.raises(SessionLimitError, match="stopped"):
            future.result(timeout=3)


def test_stdio_mcp_gateway_blocks_unknown_and_write_calls(tmp_path: Path) -> None:
    calls = tmp_path / "calls.jsonl"
    upstream = tmp_path / "upstream.py"
    upstream.write_text(
        "import json,sys\n"
        "from pathlib import Path\n"
        f"path=Path({str(calls)!r})\n"
        "for line in sys.stdin:\n"
        " m=json.loads(line)\n"
        " if m.get('method')=='tools/call':\n"
        "  with path.open('a') as f: f.write(json.dumps(m)+'\\n')\n"
        " result={'content':[{'type':'text','text':'ok'}]}\n"
        " print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':result}),flush=True)\n"
    )
    config = tmp_path / "reflex.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "mode": "enforce",
                "mcp": {
                    "use_jev": False,
                    "tools": [
                        {
                            "server": "data",
                            "name": "db.read",
                            "effect": "read",
                            "argument_schema": {
                                "type": "object",
                                "required": ["query", "database"],
                                "properties": {
                                    "query": {"type": "string", "pattern": "^SELECT [12]$"},
                                    "database": {"type": "string"},
                                },
                                "additionalProperties": False,
                            },
                            "argument_constraints": {"/database": ["development"]},
                        },
                        {"server": "data", "name": "db.update", "effect": "write"},
                        {"server": "data", "name": "cloud.delete", "effect": "destructive"},
                    ],
                },
                "session": {
                    "enabled": True,
                    "path": str(tmp_path / "sessions.sqlite3"),
                    "max_tool_calls": 10,
                },
            }
        )
    )
    requests = [
        {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "db.read",
                "arguments": {"query": "SELECT 1", "database": "development"},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "db.update", "arguments": {"sql": "UPDATE users SET active=0"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "cloud.delete", "arguments": {"bucket": "prod"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "ticket.change", "arguments": {"id": 1}},
        },
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "db.read",
                "arguments": {
                    "query": "SELECT 2",
                    "database": "development",
                    "admin": True,
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "db.read",
                "arguments": {"query": "SELECT 2", "database": "production"},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "db.read",
                "arguments": {"query": "SELECT 2", "database": "development"},
            },
        },
    ]
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "jev_reflex",
            "mcp",
            "serve",
            "--server",
            "data",
            "--config",
            str(config),
            "--session-id",
            "agent-1",
            "--",
            sys.executable,
            str(upstream),
        ],
        input="".join(json.dumps(item) + "\n" for item in requests),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
        env={**os.environ, "JRX_SESSION_ID": "agent-1"},
    )
    assert completed.returncode == 0, completed.stderr
    responses = {item["id"]: item for item in map(json.loads, completed.stdout.splitlines())}
    assert responses[0]["result"]["content"][0]["text"] == "ok"
    assert responses[1]["result"]["content"][0]["text"] == "ok"
    assert all(responses[index]["result"]["isError"] for index in (2, 3, 4, 5, 6))
    assert responses[7]["result"]["content"][0]["text"] == "ok"
    assert [json.loads(line)["params"]["name"] for line in calls.read_text().splitlines()] == [
        "db.read",
        "db.read",
    ]


def test_mcp_gateway_times_out_upstream_tool(tmp_path: Path) -> None:
    upstream = tmp_path / "slow.py"
    upstream.write_text("import sys,time\nfor line in sys.stdin:\n time.sleep(10)\n")
    config = tmp_path / "reflex.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "mode": "enforce",
                "mcp": {
                    "use_jev": False,
                    "timeout_seconds": 0.2,
                    "tools": [{"server": "data", "name": "db.read", "effect": "read"}],
                },
            }
        )
    )
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "db.read", "arguments": {"query": "SELECT 1"}},
    }
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "jev_reflex",
            "mcp",
            "serve",
            "--server",
            "data",
            "--config",
            str(config),
            "--",
            sys.executable,
            str(upstream),
        ],
        input=json.dumps(request) + "\n",
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    response = json.loads(completed.stdout.splitlines()[0])
    assert response["result"]["isError"] is True
    assert "time limit" in response["result"]["content"][0]["text"]


def test_mcp_gateway_upstream_process_does_not_inherit_jrx_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from io import BytesIO

    from jev_reflex.mcp_gateway import MCPGateway

    out_file = tmp_path / "mcp_child_env.json"
    code = f"import json, os; json.dump(dict(os.environ), open({repr(str(out_file))}, 'w'))"
    monkeypatch.setenv("JRX_ID_TOKEN", "mcp-secret-oidc-identity")
    monkeypatch.setenv("TYPESAFE_API_KEY", "mcp-secret-typesafe-key")
    monkeypatch.setenv("JRX_API_KEY", "mcp-jrx-api-key")
    monkeypatch.setenv("JRX_SECRET_TOKEN", "mcp-jrx-secret-token")
    monkeypatch.setenv("USER_ALLOWED_VAR", "mcp-allowed-value")

    gw = MCPGateway(
        config=ReflexConfig(),
        server_name="test-server",
        command=[sys.executable, "-c", code],
        source=BytesIO(),
        sink=BytesIO(),
    )
    gw.run()

    captured = json.loads(out_file.read_text())
    assert "JRX_ID_TOKEN" not in captured
    assert "TYPESAFE_API_KEY" not in captured
    assert "JRX_API_KEY" not in captured
    assert "JRX_SECRET_TOKEN" not in captured
    assert captured.get("USER_ALLOWED_VAR") == "mcp-allowed-value"
