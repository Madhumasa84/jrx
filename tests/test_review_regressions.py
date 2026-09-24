from __future__ import annotations

import hashlib
import ipaddress
import json
import sys
from io import BytesIO
from types import SimpleNamespace

import pytest

from jev_reflex import _egress_proxy as proxy
from jev_reflex import sandbox
from jev_reflex.config import ReflexConfig, SandboxConfig
from jev_reflex.mcp_gateway import MCPGateway

SCHEMA = {"type": "object"}
DIGEST = hashlib.sha256(b'{"type":"object"}').hexdigest()


def gateway() -> MCPGateway:
    config = ReflexConfig.model_validate(
        {
            "mcp": {
                "tools": [
                    {
                        "server": "test",
                        "name": "read",
                        "effect": "read",
                        "expected_input_schema_sha256": DIGEST,
                    }
                ]
            }
        }
    )
    return MCPGateway(config, "test", ["unused"], source=BytesIO(), sink=BytesIO())


@pytest.mark.parametrize(
    "extra", [[], ["--allow-port", "8443"], ["--allow-port", "80", "--allow-port", "8443"]]
)
def test_proxy_cli_respects_exact_port_policy(monkeypatch, extra):
    observed = []

    class Server:
        def __init__(self, address, hosts, ports, networks):
            observed.append(ports)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def serve_forever(self, **kwargs):
            pass

    monkeypatch.setattr(proxy, "_ProxyServer", Server)
    monkeypatch.setattr(sys, "argv", ["proxy", "--allow-host", "example.com", *extra])
    proxy.main()
    assert observed == [{int(extra[i]) for i in range(1, len(extra), 2)} if extra else {443}]


@pytest.mark.parametrize(
    "address", ["224.0.0.1", "ff02::1", "127.0.0.1", "169.254.169.254", "0.0.0.0", "::", "10.0.0.1"]
)
def test_proxy_rejects_nonpublic_destinations_by_default(address):
    assert not proxy._destination_allowed(address, [])


def test_proxy_accepts_public_and_explicit_private_destinations():
    assert proxy._destination_allowed("8.8.8.8", [])
    assert proxy._destination_allowed("10.0.0.1", [ipaddress.ip_network("10.0.0.0/24")])


@pytest.mark.parametrize(
    "bad_tool", [{}, None, {"name": []}, {"name": "read", "inputSchema": {"type": "string"}}]
)
def test_rejected_catalog_cannot_leave_partial_trust(bad_tool):
    instance = gateway()
    response = {"result": {"tools": [{"name": "read", "inputSchema": SCHEMA}, bad_tool]}}
    assert instance._validate_tool_catalog(response, 0)
    assert not instance._schema_is_verified("read")


def test_failed_catalog_page_revokes_previous_page_and_stale_responses():
    instance = gateway()
    assert (
        instance._validate_tool_catalog(
            {
                "result": {
                    "tools": [{"name": "read", "inputSchema": SCHEMA}],
                    "nextCursor": "page2",
                }
            },
            0,
        )
        is None
    )
    assert instance._schema_is_verified("read")
    assert instance._validate_tool_catalog({"error": {"code": -1}}, 0) is None
    assert not instance._schema_is_verified("read")
    assert instance._validate_tool_catalog(
        {
            "result": {
                "tools": [{"name": "read", "inputSchema": SCHEMA}],
            }
        },
        0,
    )
    assert not instance._schema_is_verified("read")


def test_catalog_notification_revokes_trust():
    instance = gateway()
    instance._validated_schemas["read"] = DIGEST
    process = SimpleNamespace(
        stdout=BytesIO(b'{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\n')
    )
    instance._read_upstream(process)
    assert not instance._schema_is_verified("read")
    assert json.loads(instance.sink.getvalue())["method"] == "notifications/tools/list_changed"


@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e400"])
def test_nonfinite_tool_argument_is_rejected_before_forwarding(number):
    instance = gateway()
    downstream = BytesIO()
    process = SimpleNamespace(stdin=downstream, poll=lambda: None)
    raw = (
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
        '{"name":"read","arguments":{"amount":' + number + "}}}\n"
    ).encode()
    instance._handle(process, raw)
    assert json.loads(instance.sink.getvalue())["error"]["code"] == -32700
    assert downstream.getvalue() == b""


def test_catalog_revocation_during_evaluation_blocks_forwarding(monkeypatch):
    instance = gateway()
    instance._validated_schemas["read"] = DIGEST

    def authorize(*args):
        with instance._catalog_lock:
            instance._invalidate_catalog_locked()
        return True, ""

    monkeypatch.setattr(instance, "_authorize_tool", authorize)
    downstream = BytesIO()
    process = SimpleNamespace(stdin=downstream, poll=lambda: None)
    instance._handle(
        process, b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}\n'
    )
    assert json.loads(instance.sink.getvalue())["result"]["isError"]
    assert not downstream.getvalue()
    assert not instance._pending


def test_network_creation_failure_or_interrupt_rolls_back(monkeypatch):
    config = SandboxConfig(
        enabled=True, image="python:3.11", proxy_image="python:3.11", allowed_hosts=["example.com"]
    )
    removed = []

    def create(*args, **kwargs):
        if args[1] == "version":
            return "29.0.0"
        raise KeyboardInterrupt

    monkeypatch.setattr(sandbox, "_docker", create)
    monkeypatch.setattr(sandbox, "remove_sandbox_egress", lambda *args: removed.append(args[1]))
    with pytest.raises(KeyboardInterrupt):
        sandbox.prepare_sandbox_egress(config, "jrx-test")
    assert removed == ["jrx-test"]


@pytest.mark.parametrize("version", ["27.5.0", "unknown", ""])
def test_egress_rejects_unsupported_daemon_before_creating_resources(monkeypatch, version):
    calls = []

    def docker(*args, **kwargs):
        calls.append(args[1])
        return version

    monkeypatch.setattr(sandbox, "_docker", docker)
    config = SandboxConfig(
        enabled=True, image="python:3.11", proxy_image="python:3.11", allowed_hosts=["example.com"]
    )
    with pytest.raises(RuntimeError, match="Docker Engine 28"):
        sandbox.prepare_sandbox_egress(config, "jrx-test")
    assert calls == ["version"]


def test_session_stop_during_network_setup_prevents_command_start(tmp_path, monkeypatch):
    import jev_reflex.cli as cli
    from jev_reflex.session_limits import SessionLimitError, SessionStore

    config = ReflexConfig.model_validate(
        {
            "session": {"enabled": True, "path": str(tmp_path / "sessions.sqlite3")},
            "sandbox": {
                "enabled": True,
                "image": "python:3.11",
                "proxy_image": "python:3.11",
                "allowed_hosts": ["example.com"],
            },
        }
    )
    removed = []
    monkeypatch.setenv("JRX_SESSION_ID", "review-stop")
    monkeypatch.setattr(cli, "build_sandbox_command", lambda *args: (["unused"], "jrx-test"))
    monkeypatch.setattr(
        cli,
        "prepare_sandbox_egress",
        lambda *args: SessionStore(config.session).stop("review-stop"),
    )
    monkeypatch.setattr(cli, "remove_sandbox_egress", lambda *args: removed.append(args[1]))
    monkeypatch.setattr(
        cli.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("stopped session launched a command"),
    )
    with pytest.raises(SessionLimitError):
        cli._execute_argv(["unused"], tmp_path, config)
    assert removed == ["jrx-test"]
