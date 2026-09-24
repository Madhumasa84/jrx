from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

from jev_reflex.config import ReflexConfig
from jev_reflex.mcp_gateway import MCPGateway

SCHEMA = {
    "type": "object",
    "properties": {"project": {"type": "string", "enum": ["development", "production"]}},
    "required": ["project"],
    "additionalProperties": False,
}


def _schema_hash(schema: dict[str, object]) -> str:
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read_line(process: subprocess.Popen[str]) -> dict[str, object]:
    assert process.stdout is not None
    line = process.stdout.readline()
    assert line, "MCP gateway did not return a response"
    return json.loads(line)


def _send(process: subprocess.Popen[str], request: dict[str, object]) -> dict[str, object]:
    assert process.stdin is not None
    process.stdin.write(json.dumps(request) + "\n")
    process.stdin.flush()
    return _read_line(process)


def test_pinned_mcp_input_schema_allows_match_and_blocks_drift(tmp_path: Path) -> None:
    calls = tmp_path / "upstream-calls.jsonl"
    upstream = tmp_path / "upstream.py"
    upstream.write_text(
        "import json,sys\n"
        f"schema=json.loads({json.dumps(SCHEMA)!r})\n"
        f"calls={str(calls)!r}\n"
        "drift = sys.argv[1] == 'drift'\n"
        "malformed = sys.argv[1] == 'malformed'\n"
        "for line in sys.stdin:\n"
        " m=json.loads(line)\n"
        " if m.get('method') == 'tools/list':\n"
        "  sent=dict(schema)\n"
        "  if drift: sent['properties']={'project': {'type': 'integer'}}\n"
        "  result={'tools':[{'name':'project.read','inputSchema':sent}]}\n"
        "  if malformed: result['tools'].append({})\n"
        " elif m.get('method') == 'tools/call':\n"
        "  with open(calls,'a') as f: f.write(json.dumps(m)+'\\n')\n"
        "  result={'content':[{'type':'text','text':'ok'}]}\n"
        " else: result={}\n"
        " print(json.dumps({'jsonrpc':'2.0','id':m.get('id'),'result':result}),flush=True)\n"
        " if sys.argv[1] == 'notify' and m.get('method') == 'tools/call':\n"
        "  print(json.dumps({'jsonrpc':'2.0','method':'notifications/tools/list_changed'}),flush=True)\n",
        encoding="utf-8",
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
                            "server": "projects",
                            "name": "project.read",
                            "effect": "read",
                            "expected_input_schema_sha256": _schema_hash(SCHEMA),
                            "argument_schema": SCHEMA,
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    for mode in ("match", "drift", "malformed", "notify"):
        try:
            calls.unlink()
        except FileNotFoundError:
            pass
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "jev_reflex",
                "mcp",
                "serve",
                "--server",
                "projects",
                "--config",
                str(config),
                "--",
                sys.executable,
                str(upstream),
                mode,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "JRX_SESSION_ID": ""},
        )
        assert process.stdin is not None

        tool_call = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "project.read", "arguments": {"project": "development"}},
        }
        unverified = _send(process, tool_call)
        assert unverified["result"]["isError"] is True
        assert "not been verified" in unverified["result"]["content"][0]["text"]

        catalog = _send(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        if mode in {"match", "notify"}:
            assert catalog["result"]["tools"][0]["name"] == "project.read"
            allowed = _send(process, {**tool_call, "id": 3})
            assert allowed["result"]["content"][0]["text"] == "ok"
            assert len(calls.read_text(encoding="utf-8").splitlines()) == 1
            if mode == "notify":
                assert _read_line(process)["method"] == "notifications/tools/list_changed"
                denied = _send(process, {**tool_call, "id": 4})
                assert denied["result"]["isError"] is True
                assert len(calls.read_text(encoding="utf-8").splitlines()) == 1
        else:
            assert catalog["error"]["code"] == -32002
            if mode == "drift":
                assert "schema changed" in catalog["error"]["message"]
            else:
                repeated = _send(process, {"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
                assert repeated["error"]["code"] == -32002
            denied = _send(process, {**tool_call, "id": 3})
            assert denied["result"]["isError"] is True
            assert not calls.exists()

        process.stdin.close()
        assert process.wait(timeout=5) == 0, process.stderr.read() if process.stderr else ""


def test_pinned_mcp_schema_supports_catalog_pagination() -> None:
    second_schema = {"type": "object", "properties": {"name": {"type": "string"}}}
    config = ReflexConfig.model_validate(
        {
            "mcp": {
                "tools": [
                    {
                        "server": "projects",
                        "name": "project.read",
                        "effect": "read",
                        "expected_input_schema_sha256": _schema_hash(SCHEMA),
                    },
                    {
                        "server": "projects",
                        "name": "project.search",
                        "effect": "read",
                        "expected_input_schema_sha256": _schema_hash(second_schema),
                    },
                ]
            }
        }
    )
    gateway = MCPGateway(config, "projects", ["unused"])
    gateway._catalog_generation = 1

    assert (
        gateway._validate_tool_catalog(
            {
                "result": {
                    "tools": [{"name": "project.read", "inputSchema": SCHEMA}],
                    "nextCursor": "next",
                }
            },
            1,
        )
        is None
    )
    assert gateway._schema_is_verified("project.read")
    assert not gateway._schema_is_verified("project.search")
    assert (
        gateway._validate_tool_catalog(
            {"result": {"tools": [{"name": "project.search", "inputSchema": second_schema}]}},
            1,
        )
        is None
    )
    assert gateway._schema_is_verified("project.search")

    gateway._validated_schemas.clear()
    assert (
        gateway._validate_tool_catalog(
            {"result": {"tools": [{"name": "project.read", "inputSchema": SCHEMA}]}},
            1,
        )
        == "MCP tool catalog is missing a pinned tool"
    )


def test_older_mcp_catalog_response_cannot_restore_schema_trust() -> None:
    config = ReflexConfig.model_validate(
        {
            "mcp": {
                "tools": [
                    {
                        "server": "projects",
                        "name": "project.read",
                        "effect": "read",
                        "expected_input_schema_sha256": _schema_hash(SCHEMA),
                    }
                ]
            }
        }
    )
    gateway = MCPGateway(config, "projects", ["unused"])
    gateway._catalog_generation = 2

    mismatch = gateway._validate_tool_catalog(
        {"result": {"tools": [{"name": "project.read", "inputSchema": SCHEMA}]}}, 1
    )

    assert mismatch == "MCP tool catalog scan is stale or unverified"
    assert not gateway._schema_is_verified("project.read")
