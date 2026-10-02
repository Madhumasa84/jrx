"""Managed provider process lifecycle and bounded structured output rendering."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .providers import build_native_argv, child_environment, provider_by_key
from .state import WorkspaceError, WorkspaceLock, validate_workspace
from .streaming import NormalizedEvent, parse_provider_event

EventHandler = Callable[[NormalizedEvent], bool]


def _terminate_group(process: subprocess.Popen[Any]) -> None:
    if os.name == "nt":
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        return
    for sig, timeout in ((signal.SIGINT, 2.0), (signal.SIGTERM, 1.0), (signal.SIGKILL, 1.0)):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=timeout)
            break
        except subprocess.TimeoutExpired:
            continue


def _wait_with_cleanup(process: subprocess.Popen[Any]) -> int:
    old_term = None
    if os.name != "nt":
        old_term = signal.getsignal(signal.SIGTERM)

        def terminate_handler(signum: int, _frame: Any) -> None:
            raise SystemExit(128 + signum)

        signal.signal(signal.SIGTERM, terminate_handler)
    try:
        return process.wait()
    except BaseException:
        _terminate_group(process)
        raise
    finally:
        if old_term is not None:
            signal.signal(signal.SIGTERM, old_term)


def launch_native(
    provider: str,
    workspace: Path,
    *,
    model: str | None = None,
    resume: bool = False,
    session_ref: str | None = None,
    new_session_id: str | None = None,
    initial_prompt: str | None = None,
    allow_api_key: bool = False,
    lock: WorkspaceLock | None = None,
) -> tuple[int | None, list[str]]:
    """Run one official native CLI with inherited terminal streams and no shell."""
    canonical = validate_workspace(workspace)
    provider_by_key(provider)
    argv = build_native_argv(
        provider,
        model=model,
        resume=resume,
        session_ref=session_ref,
        initial_prompt=initial_prompt,
        new_session_id=new_session_id,
    )
    environment = child_environment(provider, allow_api_key=allow_api_key)
    held = lock is not None
    manager = lock or WorkspaceLock(canonical)
    terminal_fd: int | None = None
    previous_foreground: int | None = None
    parent_group = os.getpgrp() if os.name != "nt" else None
    if os.name != "nt":
        try:
            terminal_fd = sys.stdin.fileno()
            previous_foreground = os.tcgetpgrp(terminal_fd)
        except (AttributeError, OSError, ValueError):
            terminal_fd = None
            previous_foreground = None
    try:
        if not held:
            manager.acquire()
        process = subprocess.Popen(
            argv,
            cwd=canonical,
            env=environment,
            stdin=None,
            stdout=None,
            stderr=None,
            shell=False,
            close_fds=True,
            # A native interactive CLI needs the controlling terminal. Give it
            # its own process group so cancellation can still stop its tree.
            start_new_session=False,
            process_group=0 if os.name != "nt" else None,
        )
        if terminal_fd is not None and parent_group is not None:
            previous_ttou = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
            try:
                os.tcsetpgrp(terminal_fd, process.pid)
            except OSError as exc:
                _terminate_group(process)
                raise OSError("could not give the terminal to the provider CLI") from exc
            finally:
                signal.signal(signal.SIGTTOU, previous_ttou)
    except FileNotFoundError:
        if not held:
            manager.release()
        return None, argv
    except (OSError, WorkspaceError):
        if not held:
            manager.release()
        return None, argv
    try:
        return _wait_with_cleanup(process), argv
    finally:
        if terminal_fd is not None and parent_group is not None:
            previous_ttou = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
            try:
                os.tcsetpgrp(terminal_fd, previous_foreground or parent_group)
            except OSError:
                pass
            finally:
                signal.signal(signal.SIGTTOU, previous_ttou)
        if not held:
            manager.release()


def structured_argv(
    provider: str,
    prompt: str,
    *,
    model: str | None = None,
    resume_session_ref: str | None = None,
    sandbox_mode: str | None = None,
) -> list[str]:
    """Build documented one-turn structured CLI invocations."""
    spec = provider_by_key(provider)
    if provider == "codex":
        if sandbox_mode not in {None, "read-only", "workspace-write"}:
            raise ValueError("unsupported Codex sandbox mode")
        if resume_session_ref and sandbox_mode is not None:
            raise ValueError(
                "Codex exec resume has no documented sandbox override; use the saved session mode"
            )
        argv = [spec.executable, "exec"]
        if resume_session_ref:
            argv += ["resume", "--json"]
        else:
            argv.append("--json")
        if sandbox_mode:
            argv += ["--sandbox", sandbox_mode]
        if model:
            argv += ["--model", model]
        if resume_session_ref:
            argv.append(resume_session_ref)
        return [*argv, prompt]
    if sandbox_mode is not None:
        raise ValueError(f"sandbox mode selection is not supported for {provider}")
    if provider == "claude":
        if resume_session_ref:
            raise ValueError(f"structured session resume is not supported for {provider}")
        argv = [
            spec.executable,
            "--print",
            "--output-format",
            "stream-json",
            "--verbose",
            "--include-partial-messages",
        ]
        if model:
            argv += ["--model", model]
        return [*argv, prompt]
    # Antigravity takes the next token after bare --print as its prompt, even
    # when options follow. Bind the prompt to the flag so parsing cannot consume
    # --output-format as task text.
    argv = [spec.executable, f"--print={prompt}", "--output-format", "stream-json"]
    if resume_session_ref:
        argv += ["--conversation", resume_session_ref]
    if model:
        argv += ["--model", model]
    return argv


def stream_structured(
    provider: str,
    workspace: Path,
    prompt: str,
    on_event: EventHandler,
    *,
    model: str | None = None,
    resume_session_ref: str | None = None,
    sandbox_mode: str | None = None,
    allow_api_key: bool = False,
    lock: WorkspaceLock | None = None,
    cancel_requested: Callable[[], bool] | None = None,
    max_buffer: int = 2_000_000,
) -> tuple[int | None, list[str]]:
    """Stream documented JSONL output with bounded buffers and process cleanup."""
    canonical = validate_workspace(workspace)
    argv = structured_argv(
        provider,
        prompt,
        model=model,
        resume_session_ref=resume_session_ref,
        sandbox_mode=sandbox_mode,
    )
    environment = child_environment(provider, allow_api_key=allow_api_key)
    manager = lock or WorkspaceLock(canonical)
    held = lock is not None
    process: subprocess.Popen[bytes] | None = None
    if not held:
        manager.acquire()
    try:
        process = subprocess.Popen(
            argv,
            cwd=canonical,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=(os.name != "nt"),
            bufsize=0,
        )
        if process.stdout is None or process.stderr is None:
            raise OSError("provider output stream unavailable")
        selector = selectors.DefaultSelector()
        buffers: dict[int, bytearray] = {}
        labels: dict[int, str] = {}
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
            buffers[stream.fileno()] = bytearray()
            labels[stream.fileno()] = label
        seen_output = False
        while selector.get_map():
            ready = selector.select(timeout=0.2)
            if cancel_requested is not None and cancel_requested():
                _terminate_group(process)
                on_event(
                    NormalizedEvent(
                        provider,
                        "cancelled",
                        "jrx.cancel",
                        text="JRX cancelled the provider process tree",
                    )
                )
                return process.returncode, argv
            for key, _mask in ready:
                fd = key.fd
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if labels[fd] == "stderr":
                    buffer = buffers[fd]
                    buffer.extend(chunk)
                    if len(buffer) > max_buffer:
                        del buffer[: len(buffer) - max_buffer]
                    while b"\n" in buffer:
                        line, _, rest = buffer.partition(b"\n")
                        buffer[:] = rest
                        display = line.decode("utf-8", errors="replace")[:4096]
                        if display:
                            keep_running = on_event(
                                NormalizedEvent(provider, "unknown", "stderr", text=display)
                            )
                            if not keep_running:
                                _terminate_group(process)
                                return process.returncode, argv
                    continue
                buffer = buffers[fd]
                buffer.extend(chunk)
                if len(buffer) > max_buffer and b"\n" not in buffer:
                    buffer.clear()
                    keep_running = on_event(
                        NormalizedEvent(
                            provider,
                            "failure",
                            "oversized",
                            text="Oversized stream chunk discarded",
                        )
                    )
                    if not keep_running:
                        _terminate_group(process)
                        return process.returncode, argv
                while b"\n" in buffer:
                    line, _, rest = buffer.partition(b"\n")
                    buffer[:] = rest
                    if len(line) > max_buffer:
                        continue
                    event = parse_provider_event(provider, bytes(line))
                    seen_output = seen_output or (event.kind == "output" and bool(event.text))
                    if provider == "antigravity" and event.kind == "turn_ended" and seen_output:
                        event = NormalizedEvent(
                            event.provider,
                            event.kind,
                            event.raw_type,
                            event.session_id,
                            event.request_id,
                            "Antigravity provider turn ended; review streamed output and workspace",
                            details=event.details,
                        )
                    if not on_event(event):
                        _terminate_group(process)
                        return process.returncode, argv
            if process.poll() is not None and not selector.get_map():
                break
        for fd, buffer in buffers.items():
            if not buffer:
                continue
            trailing = bytes(buffer)
            buffer.clear()
            if labels[fd] == "stderr":
                display = trailing.decode("utf-8", errors="replace")[:4096]
                if display and not on_event(
                    NormalizedEvent(provider, "unknown", "stderr", text=display)
                ):
                    _terminate_group(process)
                    return process.returncode, argv
                continue
            if len(trailing) <= max_buffer:
                event = parse_provider_event(provider, trailing)
                if not on_event(event):
                    _terminate_group(process)
                    return process.returncode, argv
        return _wait_with_cleanup(process), argv
    except KeyboardInterrupt:
        if process is not None:
            _terminate_group(process)
        raise
    except (OSError, WorkspaceError):
        if process is not None:
            _terminate_group(process)
        return None, argv
    finally:
        if not held:
            manager.release()
