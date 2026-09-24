"""Construction and cleanup for isolated Docker command execution."""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from pathlib import Path

from .config import SandboxConfig


def _workspace(cwd: Path) -> tuple[Path, Path]:
    """Find the repository mount and preserve its absolute path in the container."""

    working_directory = cwd.resolve(strict=True)
    if not working_directory.is_dir():
        raise ValueError("sandbox working directory must be a directory")
    try:
        result = subprocess.run(
            ["git", "-C", str(working_directory), "rev-parse", "--show-toplevel"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=3,
            shell=False,
        )
        root = (
            Path(result.stdout.strip()).resolve(strict=True)
            if result.returncode == 0
            else working_directory
        )
    except (OSError, subprocess.SubprocessError, RuntimeError):
        root = working_directory
    if not root.is_dir():
        raise ValueError("sandbox repository root is unavailable")
    try:
        working_directory.relative_to(root)
    except ValueError:
        raise ValueError("sandbox working directory is outside its repository") from None
    if any(char in str(root) for char in ",\n\r"):
        raise ValueError("sandbox repository path contains characters unsupported by Docker mounts")
    if root == Path("/"):
        raise ValueError("sandbox cannot mount the host filesystem root")
    return root, working_directory


def build_sandbox_command(
    argv: list[str], cwd: Path, config: SandboxConfig
) -> tuple[list[str], str]:
    """Build a no-network, read-only-root Docker command with one workspace mount."""

    if not config.enabled or not config.image:
        raise ValueError("an enabled sandbox with a configured image is required")
    root, workdir = _workspace(cwd)
    container_name = f"jrx-{uuid.uuid4().hex}"
    network_name = egress_network_name(container_name)
    command = [
        config.docker_binary,
        "run",
        "--pull",
        "never",
        "--rm",
        "--init",
        "--name",
        container_name,
        "--network",
        network_name if config.allowed_hosts else "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(config.pids_limit),
        "--memory",
        config.memory_limit,
        "--cpus",
        str(config.cpus),
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--tmpfs",
        f"/tmp:rw,nosuid,nodev,noexec,size={config.tmp_size}",
        "--mount",
        f"type=bind,src={root},dst={root}",
        "--workdir",
        workdir,
    ]
    if config.runtime:
        command.extend(["--runtime", config.runtime])
    if config.allowed_hosts:
        command.extend(
            [
                "--dns",
                "127.0.0.1",
                "--env",
                "HTTPS_PROXY=http://jrx-egress:3128",
                "--env",
                "https_proxy=http://jrx-egress:3128",
            ]
        )
    command.extend(["--entrypoint", argv[0], config.image, *argv[1:]])
    return command, container_name


def egress_network_name(container_name: str) -> str:
    token = container_name.removeprefix("jrx-")
    return f"jrx-net-{token}"


def egress_proxy_name(container_name: str) -> str:
    token = container_name.removeprefix("jrx-")
    return f"jrx-egress-{token}"


def _docker(config: SandboxConfig, *arguments: str, timeout: float = 30) -> str:
    try:
        result = subprocess.run(
            [config.docker_binary, *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("isolated network setup failed") from None
    if result.returncode != 0:
        raise RuntimeError("isolated network setup failed")
    return result.stdout.strip()


def _docker_cleanup(
    config: SandboxConfig,
    *arguments: str,
    missing_ok: bool = False,
    retry_if_busy: bool = False,
) -> None:
    deadline = time.monotonic() + 5 if retry_if_busy else 0
    while True:
        try:
            result = subprocess.run(
                [config.docker_binary, *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=15,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise RuntimeError("could not clean up isolated network") from None
        if result.returncode == 0:
            return
        detail = result.stderr.lower()
        if missing_ok and (
            "no such container" in detail
            or "no such network" in detail
            or ("network " in detail and " not found" in detail)
        ):
            return
        if retry_if_busy and ("active endpoint" in detail or "network is in use" in detail):
            if time.monotonic() < deadline:
                time.sleep(0.1)
                continue
        raise RuntimeError("could not clean up isolated network")


def prepare_sandbox_egress(config: SandboxConfig, container_name: str) -> None:
    """Create a private network and a filtered proxy sidecar for this execution."""

    if not config.allowed_hosts:
        return
    if not config.proxy_image:
        raise ValueError("sandbox.proxy_image is required for allowlisted network access")
    network = egress_network_name(container_name)
    proxy = egress_proxy_name(container_name)
    proxy_script = Path(__file__).with_name("_egress_proxy.py").resolve(strict=True)
    version = _docker(config, "version", "--format", "{{.Server.Version}}", timeout=5)
    try:
        supported = int(version.split(".", 1)[0]) >= 28
    except ValueError:
        supported = False
    if not supported:
        raise RuntimeError("allowlisted egress requires Docker Engine 28 or newer")
    try:
        _docker(
            config,
            "network",
            "create",
            "--driver",
            "bridge",
            "--internal",
            "--opt",
            "com.docker.network.bridge.gateway_mode_ipv4=isolated",
            "--opt",
            "com.docker.network.bridge.gateway_mode_ipv6=isolated",
            network,
        )
        proxy_args = [
            "run",
            "--pull",
            "never",
            "--detach",
            "--init",
            "--name",
            proxy,
            "--network",
            network,
            "--network-alias",
            "jrx-egress",
            "--add-host",
            "host.docker.internal:host-gateway",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "128m",
            "--cpus",
            "0.5",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=16m",
            "--mount",
            f"type=bind,src={proxy_script},dst=/opt/jrx-egress-proxy.py,readonly",
            "--entrypoint",
            "python3",
            config.proxy_image,
            "/opt/jrx-egress-proxy.py",
        ]
        for host in config.allowed_hosts:
            proxy_args.extend(["--allow-host", host])
        for port in config.allowed_ports:
            proxy_args.extend(["--allow-port", str(port)])
        for cidr in config.allowed_private_networks:
            proxy_args.extend(["--allow-network", cidr])
        _docker(config, *proxy_args)
        _docker(config, "network", "connect", "bridge", proxy)
        deadline = time.monotonic() + 8
        while True:
            try:
                _docker(
                    config,
                    "exec",
                    proxy,
                    "python3",
                    "-c",
                    "import socket; socket.create_connection(('127.0.0.1', 3128), timeout=.2).close()",
                    timeout=2,
                )
                return
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
    except BaseException:
        try:
            remove_sandbox_egress(config, container_name)
        except RuntimeError:
            pass
        raise


def remove_sandbox_egress(config: SandboxConfig, container_name: str) -> None:
    """Remove the per-run proxy and isolated network after command completion."""

    if not config.allowed_hosts:
        return
    cleanup_error: RuntimeError | None = None
    try:
        _docker_cleanup(config, "rm", "--force", egress_proxy_name(container_name), missing_ok=True)
    except RuntimeError as exc:
        cleanup_error = exc
    try:
        _docker_cleanup(
            config,
            "network",
            "rm",
            egress_network_name(container_name),
            missing_ok=True,
            retry_if_busy=True,
        )
    except RuntimeError as exc:
        cleanup_error = cleanup_error or exc
    if cleanup_error is not None:
        raise cleanup_error


def remove_sandbox_container(config: SandboxConfig, container_name: str) -> None:
    """Force-remove a container if its attached Docker client was interrupted."""

    deadline = time.monotonic() + 5
    while True:
        try:
            result = subprocess.run(
                [config.docker_binary, "rm", "--force", container_name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=10,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise RuntimeError("could not stop the isolated command container") from None
        if result.returncode == 0:
            return
        detail = result.stderr.lower()
        if "no such container" in detail:
            return
        if "removal of container" in detail and "already in progress" in detail:
            if time.monotonic() < deadline:
                time.sleep(0.1)
                continue
        raise RuntimeError("could not stop the isolated command container")
