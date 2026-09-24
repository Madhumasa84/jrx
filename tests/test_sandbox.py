from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from jev_reflex.config import ReflexConfig, SandboxConfig
from jev_reflex.sandbox import build_sandbox_command


def test_sandbox_is_disabled_by_default() -> None:
    assert ReflexConfig().sandbox.enabled is False


def test_sandbox_fails_closed_without_docker_and_never_runs_host_command(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from jev_reflex.cli import app

    marker = tmp_path / "host-execution.txt"
    config = tmp_path / "reflex.yaml"
    config.write_text(
        "mode: enforce\nsandbox:\n  enabled: true\n  image: alpine:3.20\n  "
        "docker_binary: /missing/jrx-docker\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app,
        [
            "exec",
            "--demo",
            "--config",
            str(config),
            "--cwd",
            str(tmp_path),
            "--",
            "python3",
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')",
        ],
    )

    assert result.exit_code == 127
    assert not marker.exists()


@pytest.mark.parametrize(
    "settings",
    [
        {"enabled": True},
        {"enabled": True, "image": "--privileged"},
        {"image": "python:3.11-slim", "memory_limit": "unlimited"},
        {"image": "python:3.11-slim", "tmp_size": "0m"},
        {"image": "python:3.11-slim", "cpus": float("inf")},
        {"enabled": True, "image": "python:3.11-slim", "allowed_hosts": ["*.example.com"]},
        {
            "enabled": True,
            "image": "python:3.11-slim",
            "allowed_hosts": ["example.com"],
        },
        {
            "enabled": True,
            "image": "python:3.11-slim",
            "proxy_image": "python:3.11-slim",
            "allowed_hosts": ["example.com"],
            "allowed_ports": [],
        },
        {
            "enabled": True,
            "image": "python:3.11-slim",
            "allowed_private_networks": ["10.1.2.3/8"],
        },
    ],
)
def test_sandbox_rejects_invalid_or_unsafe_configuration(settings: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SandboxConfig.model_validate(settings)


def test_docker_command_applies_isolation_and_resource_limits(tmp_path: Path) -> None:
    config = SandboxConfig(
        enabled=True,
        image="python:3.11-slim",
        runtime="runsc",
        memory_limit="768m",
        cpus=1.5,
        pids_limit=64,
        tmp_size="128m",
    )
    command, name = build_sandbox_command(["python", "-c", "print('inside')"], tmp_path, config)

    assert command[:2] == ["docker", "run"]
    assert command[2:4] == ["--pull", "never"]
    assert "--network" in command and command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--security-opt") + 1] == "no-new-privileges"
    assert command[command.index("--pids-limit") + 1] == "64"
    assert command[command.index("--memory") + 1] == "768m"
    assert command[command.index("--cpus") + 1] == "1.5"
    assert command[command.index("--runtime") + 1] == "runsc"
    assert command[command.index("--mount") + 1] == f"type=bind,src={tmp_path},dst={tmp_path}"
    assert command[command.index("--entrypoint") + 1] == "python"
    assert command[-3:] == ["python:3.11-slim", "-c", "print('inside')"]
    assert "-e" not in command and "--env" not in command
    assert name.startswith("jrx-")


def test_sandbox_preserves_subdirectory_working_directory(tmp_path: Path) -> None:
    nested = tmp_path / "packages" / "sample"
    nested.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    command, _ = build_sandbox_command(
        ["pwd"], nested, SandboxConfig(enabled=True, image="alpine:3.20")
    )
    assert str(command[command.index("--workdir") + 1]) == str(nested)
    assert f"type=bind,src={tmp_path},dst={tmp_path}" in command


def test_allowlisted_egress_uses_proxy_network_and_does_not_pass_host_environment(
    tmp_path: Path,
) -> None:
    config = SandboxConfig(
        enabled=True,
        image="python:3.11-slim",
        proxy_image="python:3.11-slim",
        allowed_hosts=["EXAMPLE.COM."],
        allowed_private_networks=["10.0.0.0/8"],
        allowed_ports=[443],
    )
    command, name = build_sandbox_command(["python", "-c", "pass"], tmp_path, config)

    assert command[command.index("--network") + 1] == f"jrx-net-{name.removeprefix('jrx-')}"
    assert command[command.index("--dns") + 1] == "127.0.0.1"
    assert "HTTPS_PROXY=http://jrx-egress:3128" in command
    assert "https_proxy=http://jrx-egress:3128" in command
    assert config.allowed_hosts == ["example.com"]
    assert config.allowed_private_networks == ["10.0.0.0/8"]
    assert "-e" not in command


def test_sandbox_timeout_stops_the_container_and_returns_timeout(tmp_path: Path) -> None:
    from jev_reflex.cli import _execute_argv

    calls = tmp_path / "docker-calls.txt"
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {str(calls)!r}\n"
        'if [ "$1" = run ]; then sleep 10; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    config = ReflexConfig.model_validate(
        {
            "sandbox": {
                "enabled": True,
                "image": "alpine:3.20",
                "docker_binary": str(docker),
                "max_execution_seconds": 1,
            }
        }
    )

    with pytest.raises(subprocess.TimeoutExpired):
        _execute_argv(["sleep", "10"], tmp_path, config)

    assert " run " in f" {calls.read_text(encoding='utf-8')} "
    assert "rm --force jrx-" in calls.read_text(encoding="utf-8")


def test_keyboard_interrupt_cleans_sandbox_container_and_egress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import jev_reflex.cli as cli

    events: list[str] = []

    class InterruptedProcess:
        pid = 1234

        def wait(self, timeout: float | None = None) -> int:
            if timeout != 1:
                raise KeyboardInterrupt
            events.append("waited")
            return 0

    monkeypatch.setattr(cli.subprocess, "Popen", lambda *args, **kwargs: InterruptedProcess())
    monkeypatch.setattr(cli.os, "killpg", lambda pid, signal: events.append("terminated"))
    monkeypatch.setattr(cli, "build_sandbox_command", lambda *args: (["docker", "run"], "jrx-test"))
    monkeypatch.setattr(cli, "prepare_sandbox_egress", lambda *args: events.append("prepared"))
    monkeypatch.setattr(cli, "remove_sandbox_container", lambda *args: events.append("container"))
    monkeypatch.setattr(cli, "remove_sandbox_egress", lambda *args: events.append("egress"))
    config = ReflexConfig.model_validate(
        {
            "sandbox": {
                "enabled": True,
                "image": "python:3.11-slim",
                "proxy_image": "python:3.11-slim",
                "allowed_hosts": ["example.com"],
            }
        }
    )

    with pytest.raises(KeyboardInterrupt):
        cli._execute_argv(["python", "-c", "pass"], tmp_path, config)

    assert events == ["prepared", "terminated", "waited", "container", "egress"]


def test_docker_cleanup_retries_container_and_network_removal_races(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import jev_reflex.sandbox as sandbox

    config = SandboxConfig()
    calls: list[list[str]] = []
    responses = iter(
        [
            SimpleNamespace(
                returncode=1,
                stderr="Error response from daemon: removal of container jrx-test is already in progress",
            ),
            SimpleNamespace(returncode=0, stderr=""),
        ]
    )

    def docker_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        del kwargs
        calls.append(command)
        return next(responses)

    monkeypatch.setattr(sandbox.subprocess, "run", docker_run)
    monkeypatch.setattr(sandbox.time, "sleep", lambda _: None)
    sandbox.remove_sandbox_container(config, "jrx-test")
    assert len(calls) == 2

    calls.clear()
    responses = iter(
        [
            SimpleNamespace(
                returncode=1,
                stderr="Error response from daemon: network jrx-net-test has active endpoints",
            ),
            SimpleNamespace(returncode=0, stderr=""),
        ]
    )
    sandbox._docker_cleanup(
        config,
        "network",
        "rm",
        "jrx-net-test",
        missing_ok=True,
        retry_if_busy=True,
    )
    assert len(calls) == 2
