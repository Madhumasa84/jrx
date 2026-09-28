"""User-facing commands for optional open-source agent harnesses."""

from __future__ import annotations

import asyncio
import json
import os
import termios
from pathlib import Path
from typing import Any

import typer

from .config import load_config
from .redaction import redact_text
from .workspace.state import WorkspaceError, validate_workspace
from .workspace.streaming import sanitize_terminal_text

app = typer.Typer(help="Plan, delegate, checkpoint and review work with open-source harnesses.")


def _display(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return sanitize_terminal_text(redact_text(text), 32_000)


def _model(name: str, timeout: float) -> Any:
    try:
        from langchain.chat_models import init_chat_model
    except ImportError as exc:
        raise WorkspaceError('Install: pip install "jev-reflex[harness]"') from exc
    # Explicit model selection: credentials and billing use this provider's SDK.
    return init_chat_model(name, timeout=min(timeout, 60), max_retries=1)


def _show_result(record: dict[str, Any]) -> None:
    typer.echo(
        _display(
            {
                key: record.get(key)
                for key in (
                    "session_id",
                    "state",
                    "model_calls",
                    "tool_calls",
                    "todos",
                    "summary",
                    "pending",
                )
            }
        )
    )
    if record.get("pending"):
        typer.echo(
            "Review the pending actions, then use harness resume SESSION --decision approve|reject."
        )
        raise typer.Exit(3)


def _report_error(exc: Exception) -> None:
    typer.echo(f"Harness stopped ({type(exc).__name__}): {_display(str(exc))}", err=True)
    raise typer.Exit(2) from None


@app.command("run")
def run(
    task: str = typer.Argument(..., help="Task for the planning coordinator."),
    model: str = typer.Option(..., "--model", help="Explicit provider:model identifier."),
    workspace: Path = typer.Option(Path.cwd(), "--workspace"),
    config: Path | None = typer.Option(None, "--config"),
    max_model_calls: int = typer.Option(60, min=1, max=1000),
    max_tool_calls: int = typer.Option(120, min=1, max=10000),
    timeout: float = typer.Option(600, min=1, max=86400),
) -> None:
    """Start a persistent Deep Agents task; pause before edits, commands and memory writes."""
    try:
        from .workspace.deep_harness import HarnessSession

        root = validate_workspace(workspace)
        loaded = load_config(config, scope=str(root))
        session = HarnessSession(
            root,
            loaded,
            _model(model, timeout),
            model_name=model,
            max_model_calls=max_model_calls,
            max_tool_calls=max_tool_calls,
            timeout=timeout,
        )
        typer.echo(f"Session: {session.session_id}")
        _show_result(session.run(task, on_event=lambda event: typer.echo(_display(event))))
    except KeyboardInterrupt:
        typer.echo("Cancelled. Inspect the checkpoint and workspace before recovery.", err=True)
        raise typer.Exit(130) from None
    except (ImportError, ValueError, RuntimeError, OSError) as exc:
        _report_error(exc)


@app.command("resume")
def resume(
    session_id: str = typer.Argument(...),
    workspace: Path = typer.Option(Path.cwd(), "--workspace"),
    config: Path | None = typer.Option(None, "--config"),
    decision: str | None = typer.Option(
        None, "--decision", help="approve or reject pending actions."
    ),
    task: str | None = typer.Option(None, "--task", help="Follow-up task after a completed turn."),
    recover: bool = typer.Option(
        False, "--recover", help="Resume after inspecting an interrupted run for partial effects."
    ),
    timeout: float = typer.Option(600, min=1, max=86400),
) -> None:
    """Resume the same checkpoint, model, policy and workspace; approvals apply once."""
    try:
        from .workspace.deep_harness import HarnessSession, load_session

        root = validate_workspace(workspace)
        record = load_session(root, session_id)
        loaded = load_config(config, scope=str(root))
        session = HarnessSession(
            root,
            loaded,
            _model(record["model"], timeout),
            model_name=record["model"],
            session_id=session_id,
            timeout=timeout,
        )
        _show_result(
            session.run(
                task,
                decision=decision,
                recover=recover,
                on_event=lambda event: typer.echo(_display(event)),
            )
        )
    except KeyboardInterrupt:
        typer.echo("Cancelled. Checkpoint retained.", err=True)
        raise typer.Exit(130) from None
    except (ImportError, ValueError, RuntimeError, OSError) as exc:
        _report_error(exc)


@app.command("status")
def status(session_id: str, workspace: Path = typer.Option(Path.cwd(), "--workspace")) -> None:
    """Inspect a saved plan, budget and pending approval without contacting a model."""
    try:
        from .workspace.deep_harness import load_session

        record = load_session(workspace, session_id)
        typer.echo(_display(record))
    except (ValueError, RuntimeError, OSError) as exc:
        _report_error(exc)


async def _confirm_acp_once() -> bool:
    """Read a canonical terminal line without leaving a blocked input thread."""
    stream = typer.get_text_stream("stdin")
    try:
        fd = stream.fileno()
        if not stream.isatty() or not termios.tcgetattr(fd)[3] & termios.ICANON:
            return False
    except (AttributeError, OSError, ValueError, termios.error):
        return False
    loop = asyncio.get_running_loop()
    answer = loop.create_future()
    line = bytearray()

    def readable() -> None:
        if answer.done():
            return
        try:
            chunk = os.read(fd, 256)
            line.extend(chunk)
            if not chunk or b"\n" in line or len(line) > 256:
                if not answer.done():
                    answer.set_result(bytes(line).strip().lower() in {b"y", b"yes"})
        except OSError:
            if not answer.done():
                answer.set_result(False)

    typer.echo("Allow this action once? [y/N]: ", nl=False)
    try:
        loop.add_reader(fd, readable)
        return await answer
    finally:
        loop.remove_reader(fd)


async def _acp_permission(
    request: dict[str, Any], root: Path, task: str, loaded: Any
) -> str | None:
    from .adapters.harness import evaluate_harness_hook

    call = request["tool_call"]
    kind = call.get("kind")
    raw = call.get("rawInput")
    if kind not in {"read", "edit", "delete", "move", "search", "execute", "fetch"}:
        typer.echo("Permission denied: unsupported tool kind.")
        return None
    if not isinstance(raw, dict) or not raw:
        typer.echo("Permission denied: the agent did not supply inspectable tool arguments.")
        return None
    if kind == "execute" and not any(
        isinstance(raw.get(key), str) and raw[key].strip()
        for key in ("command", "cmd", "script", "CommandLine", "commandLine")
    ):
        typer.echo("Permission denied: command arguments use an unsupported representation.")
        return None
    options = [item for item in request["options"] if item.get("kind") == "allow_once"]
    if len(options) != 1:
        return None
    payload = {"cwd": str(root), "tool_name": "acp_" + kind, "tool_input": raw, "user_task": task}
    result, reason = await asyncio.to_thread(evaluate_harness_hook, payload, config=loaded)
    typer.echo(_display({"tool": call, "policy": result.decision, "reason": reason}))
    if result.degraded or result.decision == "HOLD" or not await _confirm_acp_once():
        return None
    # Rebuild repository context after the user has reviewed the action.
    result, reason = await asyncio.to_thread(evaluate_harness_hook, payload, config=loaded)
    if result.degraded or result.decision == "HOLD":
        typer.echo(_display({"permission": "denied", "reason": reason}))
        return None
    return options[0]["optionId"]


@app.command("acp", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def acp_run(
    ctx: typer.Context,
    task: str = typer.Option(..., "--task"),
    workspace: Path = typer.Option(Path.cwd(), "--workspace"),
    config: Path | None = typer.Option(None, "--config"),
    provider: str | None = typer.Option(
        None, "--provider", help="codex, claude, antigravity; selects credential filtering."
    ),
    allow_api_key: bool = typer.Option(
        False, "--allow-api-key", help="Allow selected provider credentials and API billing."
    ),
    resume_session: str | None = typer.Option(None, "--resume-session"),
    timeout: float = typer.Option(600, min=1, max=86400),
) -> None:
    """Run an installed ACP agent: jrx harness acp --task TEXT -- agent-executable args."""
    try:
        from .workspace.acp_harness import run_acp
        from .workspace.providers import child_environment

        root = validate_workspace(workspace)
        loaded = load_config(config, scope=str(root))
        if loaded.mode != "enforce" or loaded.access is not None:
            raise WorkspaceError(
                "ACP harness requires enforce mode without enterprise access configuration"
            )
        argv = list(ctx.args)
        if argv[:1] == ["--"]:
            argv.pop(0)
        if not argv:
            raise WorkspaceError("supply an installed ACP agent executable after --")
        if allow_api_key and provider is None:
            raise WorkspaceError("--allow-api-key requires an explicit --provider")
        env = child_environment(provider, allow_api_key=allow_api_key) if provider else None

        approval_lock = asyncio.Lock()

        async def permission(request: dict[str, Any]) -> str | None:
            async with approval_lock:
                return await _acp_permission(request, root, task, loaded)

        result = asyncio.run(
            run_acp(
                argv,
                root,
                task,
                lambda event: typer.echo(_display(event)),
                permission,
                resume_session_id=resume_session,
                timeout=timeout,
                env=env,
            )
        )
        typer.echo(_display({"session_id": result.session_id, "stop_reason": result.stop_reason}))
        if result.stop_reason != "end_turn":
            raise typer.Exit(2)
    except KeyboardInterrupt:
        typer.echo("Cancelled ACP session.", err=True)
        raise typer.Exit(130) from None
    except (ImportError, ValueError, RuntimeError, OSError) as exc:
        _report_error(exc)
