from __future__ import annotations

import asyncio
import http.client
import json
import socket
import stat
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from typer.testing import CliRunner

from jev_reflex.adapters.codex import evaluate_codex_hook
from jev_reflex.broker import MAX_BYTES, BrokerClient, BrokerServer, secure_directory, verify_socket
from jev_reflex.cli import app
from jev_reflex.config import BrokerTLSConfig, ReflexConfig
from jev_reflex.evaluator import JUDGMENT_NAMES, DefaultEvaluator
from jev_reflex.models import EvaluationContext, ProposedAction, RiskInfo, SemanticSignals


class MockJEV:
    def __init__(self, delay=0, fail=False):
        self.contexts = []
        self.delay = delay
        self.fail = fail

    def evaluate(self, context):
        self.contexts.append(context)
        time.sleep(self.delay)
        if self.fail:
            raise RuntimeError("TYPESAFE_API_KEY=must-never-be-logged")
        return SemanticSignals(
            probabilities={name: 0.01 for name in JUDGMENT_NAMES} | {"dependency_risk": 0.88},
            risk=RiskInfo(choice="medium"),
            source="jev",
        )


@contextmanager
def running_broker(tmp_path=None, evaluator=None, *, config=None, **timeouts):
    base = Path("/tmp").resolve()
    temp_dir = tempfile.TemporaryDirectory(prefix="jrx-", dir=base)
    directory = Path(temp_dir.name)
    directory.chmod(0o700)
    path = directory / "reflex.sock"
    if config is None:
        config = ReflexConfig(jev={"transport": "broker", "socket": str(path), **timeouts})
    else:
        config = config.model_copy(
            update={"jev": config.jev.model_copy(update={"socket": str(path)})}
        )
    ready = threading.Event()
    service = BrokerServer(config, evaluator or MockJEV(), configured=True)
    loop = asyncio.new_event_loop()

    async def serve():
        server = await asyncio.start_unix_server(service.handle, path=str(path), limit=MAX_BYTES)
        path.chmod(0o600)
        ready.set()
        async with server:
            await service.stop_event.wait()

    def worker():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(serve())
        except Exception:
            pass
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        assert ready.wait(5), "Broker failed to start within timeout"
        yield config, service
    finally:
        if loop.is_running():
            loop.call_soon_threadsafe(service.stop_event.set)
        thread.join(2)
        path.unlink(missing_ok=True)
        temp_dir.cleanup()


def context(command="pip install --upgrade some-package"):
    return EvaluationContext(proposed_action=ProposedAction(command=command))


def exchange(config, raw):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(config.jev.socket)
        client.sendall(raw)
        data = b""
        while not data.endswith(b"\n"):
            data += client.recv(MAX_BYTES)
        return json.loads(data)


def test_signals_ids_health_permissions_and_local_policy(tmp_path):
    with running_broker(tmp_path) as (config, _):
        verify_socket(Path(config.jev.socket))
        assert Path(config.jev.socket).stat().st_mode & 0o777 == 0o600
        client = BrokerClient(config)
        assert client.health()["running"]
        assert client.health()["jev_configured"]
        raw = {
            "protocol_version": 1,
            "request_id": "my-id",
            "action": {"argv": ["pip", "install", "x"]},
            "context": {},
        }
        response = exchange(config, json.dumps(raw).encode() + b"\n")
        assert response["request_id"] == "my-id"
        assert response["signals"]["dependency_risk"] == 0.88
        assert response["source"] == "live_jev"
        result = DefaultEvaluator(config).evaluate(context())
        assert result.decision == "REVIEW"
        assert result.semantic_source == "broker/live"
        assert not result.degraded
        assert (
            DefaultEvaluator(config).evaluate(context("rm -rf ./important-data")).decision == "HOLD"
        )


@pytest.mark.parametrize(
    "raw,code",
    [
        (b"no json\n", "INVALID_REQUEST"),
        (b"[]\n", "INVALID_REQUEST"),
        (b'{"protocol_version":2,"request_id":"v2"}\n', "UNSUPPORTED_PROTOCOL"),
        (b"x" * MAX_BYTES + b"\n", "REQUEST_TOO_LARGE"),
    ],
)
def test_invalid_requests(tmp_path, raw, code):
    with running_broker(tmp_path) as (config, _):
        response = exchange(config, raw)
        assert response["status"] == "error"
        assert response["error_code"] == code
        assert response["degraded"]


@pytest.mark.parametrize("mode", ["advisory", "review", "enforce"])
def test_unavailable_hook_fails_safely(tmp_path, mode, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    config = ReflexConfig(
        mode=mode, jev={"transport": "broker", "socket": str(tmp_path / "missing.sock")}
    )
    result, output = evaluate_codex_hook(
        {"tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": str(tmp_path)},
        config=config,
    )
    assert result.degraded and result.decision == "REVIEW"
    decision = output["hookSpecificOutput"].get("permissionDecision")
    assert decision == (None if mode == "advisory" else "deny")


def test_hook_without_key_redacts_and_never_executes(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setenv("JRX_DEBUG", "1")
    mock = MockJEV()
    marker = tmp_path / "should-not-exist"
    with running_broker(tmp_path, mock) as (config, _):
        result, output = evaluate_codex_hook(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "pip install --upgrade some-package"},
                "cwd": str(tmp_path),
            },
            config=config,
        )
        assert "LIVE JEV VIA BROKER" in json.dumps(output)
        assert not result.degraded
        BrokerClient(config).evaluate(
            context(f"touch {marker}; echo TYPESAFE_API_KEY=super-secret-value")
        )
        assert "super-secret-value" not in mock.contexts[-1].model_dump_json()
        assert not marker.exists()
    captured = capsys.readouterr()
    assert "super-secret-value" not in captured.out + captured.err


def test_broker_redacts_raw_client_input(tmp_path):
    mock = MockJEV()
    with running_broker(tmp_path, mock) as (config, _):
        response = exchange(
            config,
            json.dumps(
                {
                    "protocol_version": 1,
                    "request_id": "redact",
                    "action": {"command": "echo API_KEY=super-secret-value"},
                    "context": {"git_diff": "password=super-secret-value"},
                }
            ).encode()
            + b"\n",
        )
        assert "super-secret-value" not in mock.contexts[-1].model_dump_json()
        assert "super-secret-value" not in json.dumps(response)


@pytest.mark.parametrize("failure", ["api_timeout", "request_timeout", "exception"])
def test_timeout_and_failure(tmp_path, failure, capsys):
    mock = MockJEV(delay=0.15 if failure != "exception" else 0, fail=failure == "exception")
    with running_broker(
        tmp_path,
        mock,
        api_timeout=0.02 if failure == "api_timeout" else 1,
        request_timeout=0.02 if failure == "request_timeout" else 1,
    ) as (config, _):
        started = time.monotonic()
        client = BrokerClient(config)
        result = client.evaluate(context())
        assert result.degraded
        assert client.last_api_requests == (1 if failure == "exception" else None)
        assert time.monotonic() - started < 1
        time.sleep(0.18)
    assert "must-never-be-logged" not in capsys.readouterr().err


def test_unsafe_socket_is_rejected(tmp_path):
    with running_broker(tmp_path) as (config, _):
        Path(config.jev.socket).chmod(0o666)
        assert not BrokerClient(config).health()["running"]
        assert BrokerClient(config).evaluate(context()).degraded


def test_rejected_symlink_directory_is_left_untouched(tmp_path):
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    original_mode = stat.S_IMODE(target.stat().st_mode)
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    for path in (alias, alias / "child"):
        with pytest.raises(ValueError, match="symbolic links"):
            secure_directory(path, create=True)
    assert stat.S_IMODE(target.stat().st_mode) == original_mode
    assert not (target / "child").exists()


def test_real_lifecycle_cli(monkeypatch):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    monkeypatch.setenv("JRX_METRICS_PORT", str(port))
    base = Path("/tmp").resolve()
    with tempfile.TemporaryDirectory(prefix="jrx-", dir=base) as td:
        path = Path(td) / "run" / "reflex.sock"
        runner = CliRunner()
        started = runner.invoke(app, ["broker", "start", "--socket", str(path)])
        assert started.exit_code == 0, started.stdout
        try:
            status = runner.invoke(
                app, ["broker", "status", "--socket", str(path), "--local", "--json"]
            )
            assert json.loads(status.stdout)["running"]
            assert path.stat().st_mode & 0o777 == 0o600
            assert path.parent.stat().st_mode & 0o777 == 0o700
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                connection.request("GET", "/metrics")
                response = connection.getresponse()
                assert response.status == 200
                assert b"jrx_broker_uptime_seconds" in response.read()
                connection.request("GET", "/metrics", headers={"X-Padding": "x" * 8192})
                assert connection.getresponse().status == 431
            finally:
                connection.close()
            duplicate = runner.invoke(app, ["broker", "start", "--socket", str(path)])
            assert duplicate.exit_code == 0
        finally:
            stopped = runner.invoke(app, ["broker", "stop", "--socket", str(path)])
            assert stopped.exit_code == 0
        for _ in range(50):
            if not path.exists():
                break
            time.sleep(0.02)
        assert not path.exists()


def test_tls_startup_failure_closes_metrics_and_local_socket(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="jrx-", dir=Path("/tmp").resolve()) as td:
        path = Path(td) / "run" / "reflex.sock"
        config = ReflexConfig(
            jev={
                "transport": "broker-tls",
                "socket": str(path),
                "broker_tls": {
                    "cert_path": "server.crt",
                    "key_path": "server.key",
                    "client_ca_path": "ca.crt",
                },
            }
        )
        service = BrokerServer(config, evaluator=MockJEV(), metrics_port=0)
        start_server = asyncio.start_server
        metrics_servers = []

        async def capture_metrics(*args, **kwargs):
            server = await start_server(*args, **kwargs)
            metrics_servers.append(server)
            return server

        async def fail_tls():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                with pytest.raises(ConnectionRefusedError):
                    client.connect(str(path))
            raise ValueError("TLS configuration unavailable")

        monkeypatch.setattr(asyncio, "start_server", capture_metrics)
        monkeypatch.setattr(service, "_start_tls_server", fail_tls)
        with pytest.raises(ValueError, match="TLS configuration unavailable"):
            asyncio.run(service.run())
        assert not path.exists()
        assert len(metrics_servers) == 1
        assert not metrics_servers[0].sockets


def test_local_status_with_tls_server_config(tmp_path):
    with running_broker() as (config, _):
        config.jev.transport = "broker-tls"
        config.jev.broker_tls = BrokerTLSConfig(
            listen_addr="127.0.0.1:8443",
            cert_path="server.crt",
            key_path="server.key",
            client_ca_path="ca.crt",
        )
        config_path = tmp_path / "tls.json"
        config_path.write_text(json.dumps({"jev": config.jev.model_dump()}))
        runner = CliRunner()
        args = ["broker", "status", "--config", str(config_path), "--json"]
        remote = runner.invoke(app, args)
        assert remote.exit_code == 1
        local = runner.invoke(app, [*args, "--local"])
        assert local.exit_code == 0
        assert json.loads(local.stdout)["socket"] == config.jev.socket
        start = runner.invoke(app, ["broker", "start", "--config", str(config_path)])
        assert start.exit_code == 0
        stop = ["broker", "stop", "--config", str(config_path)]
        assert runner.invoke(app, stop).exit_code == 2
        assert runner.invoke(app, [*args, "--local"]).exit_code == 0
        assert runner.invoke(app, [*stop, "--local"]).exit_code == 0


def test_broker_captures_evaluation_accounting_in_worker():
    evaluator = MockJEV()
    evaluator.last_api_requests = 1
    evaluator.last_usage = {"input_tokens": 5}
    service = BrokerServer(ReflexConfig(), evaluator)
    outcome = asyncio.run(service.evaluate(context()))
    evaluator.last_api_requests = 0
    evaluator.last_usage["input_tokens"] = 99
    assert outcome.api_requests == 1
    assert outcome.usage == {"input_tokens": 5}


def test_client_ignores_remote_decision_and_keeps_hard_hold(monkeypatch):
    config = ReflexConfig(jev={"transport": "broker"})
    monkeypatch.setattr(
        BrokerClient,
        "request",
        lambda *args, **kwargs: {
            "status": "ok",
            "degraded": False,
            "source": "live_jev",
            "decision": "ALLOW",
            "signals": {name: 0 for name in JUDGMENT_NAMES},
            "risk": {"choice": "low"},
        },
    )
    first = DefaultEvaluator(config).evaluate(context("rm -rf ./important-data"))
    second = DefaultEvaluator(config).evaluate(context("rm -rf ./important-data"))
    assert first.decision == second.decision == "HOLD"
    assert first.triggered_rules == second.triggered_rules


@pytest.mark.parametrize(
    "signals",
    [
        {},
        {"dependency_risk": float("nan")},
        {name: 2.0 for name in JUDGMENT_NAMES},
        {name: 0.01 for name in JUDGMENT_NAMES} | {"untrusted_name": 0.3},
    ],
)
def test_client_rejects_malformed_probabilities(monkeypatch, signals):
    monkeypatch.setattr(
        BrokerClient,
        "request",
        lambda *args, **kwargs: {
            "status": "ok",
            "degraded": False,
            "source": "live_jev",
            "signals": signals,
            "risk": {"choice": "low"},
        },
    )
    assert BrokerClient().evaluate(context()).degraded


def test_connect_timeout_is_degraded(tmp_path, monkeypatch):
    with running_broker(tmp_path) as (config, _):

        def timeout(*args):
            raise TimeoutError

        monkeypatch.setattr(socket.socket, "connect", timeout)
        assert BrokerClient(config).evaluate(context()).degraded


def test_private_directory_and_symlink_checks(tmp_path):
    from jev_reflex.broker import secure_directory

    directory = tmp_path / "private"
    directory.mkdir(mode=0o755)
    with pytest.raises(ValueError):
        secure_directory(directory)
    directory.chmod(0o700)
    link = tmp_path / "alias"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ValueError):
        secure_directory(link)


def test_wrong_owner_is_rejected(tmp_path, monkeypatch):
    with running_broker(tmp_path) as (config, _):
        monkeypatch.setattr("jev_reflex.broker.os.getuid", lambda: -1)
        assert BrokerClient(config).evaluate(context()).degraded


def test_busy_worker_stays_bounded_after_timeout(tmp_path):
    mock = MockJEV(delay=0.15)
    with running_broker(tmp_path, mock, api_timeout=0.02) as (config, _):
        client = BrokerClient(config)
        assert client.evaluate(context()).degraded
        assert client.evaluate(context()).degraded
        assert len(mock.contexts) == 1
        assert client.health()["running"]
        time.sleep(0.18)


def test_status_and_check_cli_with_mocked_broker(tmp_path):
    with running_broker(tmp_path) as (config, _):
        config_path = tmp_path / "reflex.yaml"
        config_path.write_text(config.model_dump_json())
        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "check",
                "--transport",
                "broker",
                "--config",
                str(config_path),
                "--command",
                "pip install --upgrade some-package",
                "--json",
            ],
        )
        assert result.exit_code == 0
        body = json.loads(result.stdout)
        assert body["semantic_source"] == "broker/live" and not body["degraded"]
        assert body["decision"] == "REVIEW"


def test_status_returns_nonzero_when_broker_is_unavailable(tmp_path):
    result = CliRunner().invoke(
        app, ["broker", "status", "--socket", str(tmp_path / "missing.sock"), "--json"]
    )
    assert json.loads(result.stdout)["running"] is False
    assert result.exit_code == 1


def test_broker_rejects_stale_response_over_socket(tmp_path, monkeypatch):
    from jev_reflex import broker

    real_encode = broker.encode

    def stale_response(value):
        if "server_time" in value:
            value = {**value, "server_time": value["server_time"] - 301}
        return real_encode(value)

    monkeypatch.setattr(broker, "encode", stale_response)
    with running_broker(tmp_path) as (config, _):
        assert BrokerClient(config).evaluate(context()).degraded
        assert not BrokerClient(config).health()["running"]
