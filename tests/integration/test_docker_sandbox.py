from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from jev_reflex.cli import app


def _image_or_skip() -> str:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable")
    daemon = subprocess.run(
        [docker, "info"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=5,
    )
    if daemon.returncode:
        pytest.skip("Docker daemon is unavailable")
    image = os.environ.get("JRX_TEST_DOCKER_IMAGE", "python:3.11-slim")
    inspected = subprocess.run(
        [docker, "image", "inspect", image],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if inspected.returncode:
        pytest.skip(f"Docker test image is not cached: {image}")
    return image


def test_jrx_exec_runs_in_isolated_container_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = _image_or_skip()
    working_directory = tmp_path / "repo"
    working_directory.mkdir()
    script = working_directory / "sandbox_probe.py"
    marker = working_directory / "sandbox-result.txt"
    host_secret = tmp_path / "host-secret.txt"
    host_secret.write_text("outside-the-mounted-workspace", encoding="utf-8")
    script.write_text(
        "import os, pathlib, socket\n"
        "if 'JRX_TEST_HOST_SECRET' in os.environ: raise SystemExit(31)\n"
        f"try: pathlib.Path({str(host_secret)!r}).read_text()\n"
        "except OSError: pass\n"
        "else: raise SystemExit(34)\n"
        "pathlib.Path('sandbox-result.txt').write_text('workspace-mounted')\n"
        "try:\n"
        "    pathlib.Path('/jrx-readonly-probe').write_text('bad')\n"
        "except OSError:\n"
        "    pass\n"
        "else:\n"
        "    raise SystemExit(32)\n"
        "sock = socket.socket()\n"
        "sock.settimeout(0.5)\n"
        "try:\n"
        "    sock.connect(('1.1.1.1', 443))\n"
        "except OSError:\n"
        "    pass\n"
        "else:\n"
        "    raise SystemExit(33)\n"
        "finally:\n"
        "    sock.close()\n",
        encoding="utf-8",
    )
    config = tmp_path / "reflex.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "mode": "enforce",
                "sandbox": {
                    "enabled": True,
                    "image": image,
                    "max_execution_seconds": 30,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("JRX_TEST_HOST_SECRET", "never-forward-this")

    result = CliRunner().invoke(
        app,
        [
            "exec",
            "--demo",
            "--config",
            str(config),
            "--cwd",
            str(working_directory),
            "--",
            "python3",
            str(script),
        ],
    )

    assert result.exit_code == 0, result.output
    assert marker.read_text(encoding="utf-8") == "workspace-mounted"
    assert not Path("/jrx-readonly-probe").exists()


def test_sandbox_timeout_removes_running_container(
    tmp_path: Path,
) -> None:
    image = _image_or_skip()
    docker = shutil.which("docker")
    assert docker is not None
    calls = tmp_path / "docker-calls.txt"
    errors = tmp_path / "docker-errors.txt"
    temporary_error = tmp_path / "docker-error-current.txt"
    wrapper = tmp_path / "docker-wrapper"
    wrapper.write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {str(calls)!r}\n"
        f'{docker!r} "$@" 2>{str(temporary_error)!r}\n'
        "status=$?\n"
        f"cat {str(temporary_error)!r} >> {str(errors)!r}\n"
        f"cat {str(temporary_error)!r} >&2\n"
        'exit "$status"\n',
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    config = tmp_path / "reflex.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "mode": "enforce",
                "sandbox": {
                    "enabled": True,
                    "image": image,
                    "docker_binary": str(wrapper),
                    "max_execution_seconds": 1,
                },
            }
        ),
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
            "import time; time.sleep(60)",
        ],
    )

    assert result.exit_code == 124, result.output
    assert "sandbox time limit reached" in result.stderr
    commands = calls.read_text(encoding="utf-8").splitlines()
    run_call = next(call for call in commands if call.startswith("run "))
    name = run_call.split(" --name ", 1)[1].split(" ", 1)[0]
    assert any(call == f"rm --force {name}" for call in commands)
    inspected = subprocess.run(
        [docker, "container", "inspect", name],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    assert inspected.returncode != 0


def test_allowlisted_egress_uses_proxy_and_blocks_direct_routes(
    tmp_path: Path,
) -> None:
    image = _image_or_skip()
    docker = shutil.which("docker")
    assert docker is not None
    network_result = subprocess.run(
        [
            docker,
            "network",
            "inspect",
            "bridge",
            "--format",
            "{{json .IPAM.Config}}",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    bridge_config = yaml.safe_load(network_result.stdout)
    bridge = next(item for item in bridge_config if item.get("Gateway") and item.get("Subnet"))

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 0))
    listener.listen()
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    stopped = threading.Event()

    def serve() -> None:
        while not stopped.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                try:
                    connection.settimeout(2)
                    request = b""
                    while b"\n" not in request:
                        request += connection.recv(4096)
                    if request == b"probe\n":
                        connection.sendall(b"egress-ok\n")
                except OSError:
                    pass

    def resource_ids(*arguments: str) -> set[str]:
        result = subprocess.run(
            [docker, *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return set(result.stdout.split())

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    script = tmp_path / "egress_probe.py"
    script.write_text(
        "import socket\n"
        f"def connect_proxy(host, early=b'', target_port={port}):\n"
        "    client = socket.create_connection(('jrx-egress', 3128), timeout=3)\n"
        "    client.settimeout(3)\n"
        "    client.sendall((f'CONNECT {host}:{target_port} HTTP/1.1\\r\\nHost: {host}:{target_port}\\r\\n\\r\\n').encode() + early)\n"
        "    response = b''\n"
        "    while b'\\r\\n\\r\\n' not in response:\n"
        "        response += client.recv(4096)\n"
        "    header, initial = response.split(b'\\r\\n\\r\\n', 1)\n"
        "    return client, header, initial\n"
        "client, header, initial = connect_proxy('host.docker.internal', b'probe\\n')\n"
        "assert header.startswith(b'HTTP/1.1 200 '), header\n"
        "payload = initial\n"
        "while b'\\n' not in payload:\n"
        "    payload += client.recv(4096)\n"
        "assert payload.split(b'\\n', 1)[0] == b'egress-ok', payload\n"
        "client.close()\n"
        "denied, header, _ = connect_proxy('not-allowlisted.invalid')\n"
        "assert header.startswith(b'HTTP/1.1 403 '), header\n"
        "denied.close()\n"
        "denied, header, _ = connect_proxy('host.docker.internal', target_port=443)\n"
        "assert header.startswith(b'HTTP/1.1 403 '), header\n"
        "denied.close()\n"
        "try:\n"
        f"    socket.create_connection(({bridge['Gateway']!r}, {port}), timeout=0.5)\n"
        "except OSError:\n"
        "    pass\n"
        "else:\n"
        "    raise SystemExit('sandbox reached host gateway directly')\n"
        "try:\n"
        "    socket.getaddrinfo('example.com', 443, type=socket.SOCK_STREAM)\n"
        "except OSError:\n"
        "    pass\n"
        "else:\n"
        "    raise SystemExit('sandbox resolved external DNS directly')\n",
        encoding="utf-8",
    )
    config = tmp_path / "reflex.yaml"
    settings = {
        "mode": "enforce",
        "sandbox": {
            "enabled": True,
            "image": image,
            "proxy_image": image,
            "allowed_hosts": ["host.docker.internal"],
            "allowed_private_networks": [bridge["Subnet"]],
            "allowed_ports": [port],
            "max_execution_seconds": 30,
        },
    }
    config.write_text(yaml.safe_dump(settings), encoding="utf-8")

    try:
        original_containers = resource_ids(
            "container", "ls", "--all", "-q", "--filter", "name=jrx-egress-"
        )
        original_networks = resource_ids("network", "ls", "-q", "--filter", "name=jrx-net-")
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
                str(script),
            ],
        )
        assert result.exit_code == 0, result.output
        assert (
            resource_ids("container", "ls", "--all", "-q", "--filter", "name=jrx-egress-")
            == original_containers
        )
        assert resource_ids("network", "ls", "-q", "--filter", "name=jrx-net-") == original_networks

        timeout_settings = {
            **settings,
            "sandbox": {**settings["sandbox"], "max_execution_seconds": 1},
        }
        config.write_text(yaml.safe_dump(timeout_settings), encoding="utf-8")
        timeout_result = CliRunner().invoke(
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
                "import time; time.sleep(60)",
            ],
        )
        assert timeout_result.exit_code == 124, timeout_result.output
        assert (
            resource_ids("container", "ls", "--all", "-q", "--filter", "name=jrx-egress-")
            == original_containers
        )
        assert resource_ids("network", "ls", "-q", "--filter", "name=jrx-net-") == original_networks
    finally:
        stopped.set()
        listener.close()
        server.join(timeout=2)
