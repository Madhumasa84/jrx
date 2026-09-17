"""Host broker lifecycle commands; no PID files or shell-based launchers."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

import typer

from .broker import BrokerClient, BrokerServer, secure_directory, socket_path
from .config import ReflexConfig, load_config

app = typer.Typer(help="Run the trusted host-side semantic broker.")


def configuration(config: Path | None, socket: Path | None) -> ReflexConfig:
    loaded = load_config(config)
    if socket is not None:
        loaded.jev.socket = str(socket)
    return loaded


def display(value: dict, json_output: bool = False) -> None:
    if json_output:
        typer.echo(json.dumps(value, sort_keys=True))
    else:
        typer.echo("JEV Reflex Broker\n\nStatus: " + ("running" if value["running"] else "stopped"))
        typer.echo(f"Transport: unix socket\nSocket: {value['socket']}")
        typer.echo("JEV: " + ("configured" if value["jev_configured"] else "not configured"))
        if value.get("pid"):
            typer.echo(f"PID: {value['pid']}")


@app.command()
def status(
    config: Path | None = None,
    socket: Path | None = None,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    display(BrokerClient(configuration(config, socket)).health(), json_output)


@app.command()
def run(config: Path | None = None, socket: Path | None = None) -> None:
    """Stay in the foreground; inherit credentials only from this host shell."""
    try:
        loaded = configuration(config, socket)
        typer.echo(f"JEV Reflex Broker\nTransport: unix socket\nSocket: {socket_path(loaded)}")
        asyncio.run(BrokerServer(loaded).run())
    except (OSError, RuntimeError, ValueError):
        typer.echo(
            "Broker could not start; check directory permissions and existing listener.", err=True
        )
        raise typer.Exit(2) from None


@app.command()
def start(config: Path | None = None, socket: Path | None = None) -> None:
    """Start a detached host process; use run for foreground diagnostic logs."""
    loaded = configuration(config, socket)
    client = BrokerClient(loaded)
    health = client.health()
    if health["running"]:
        display(health)
        return
    try:
        secure_directory(socket_path(loaded).parent, create=True)
        argv = [
            sys.executable,
            "-m",
            "jev_reflex",
            "broker",
            "run",
            "--socket",
            str(socket_path(loaded)),
        ]
        if config is not None:
            argv += ["--config", str(config.resolve())]
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            health = client.health()
            if health["running"]:
                display(health)
                return
            if process.poll() is not None:
                break
            time.sleep(0.05)
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
        pass
    typer.echo("Broker startup failed; use broker run for diagnostics.", err=True)
    raise typer.Exit(2)


@app.command()
def stop(config: Path | None = None, socket: Path | None = None) -> None:
    client = BrokerClient(configuration(config, socket))
    if not client.health()["running"]:
        typer.echo("Broker is not running.")
        return
    try:
        response = client.request("stop")
        if response.get("status") != "ok":
            raise ValueError
        typer.echo("Broker stop requested.")
    except (OSError, RuntimeError, ValueError):
        typer.echo("Broker stop failed.", err=True)
        raise typer.Exit(2) from None
