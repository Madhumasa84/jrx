"""Optional Agent Client Protocol transport with scoped permission decisions.

The external agent remains responsible for its own execution sandbox. Disabling
client filesystem and terminal capabilities prevents it delegating those actions
back into this process; it does not sandbox the external executable.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import math
import os
import signal
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .state import WorkspaceError, WorkspaceLock, validate_workspace


@dataclass(frozen=True)
class ACPResult:
    session_id: str
    stop_reason: str


async def run_acp(
    argv: list[str],
    workspace: Path,
    prompt: str,
    on_event: Callable[[dict[str, Any]], Any],
    on_permission: Callable[[dict[str, Any]], Awaitable[str | None]] | None = None,
    resume_session_id: str | None = None,
    timeout: float = 300,
    env: Mapping[str, str] | None = None,
) -> ACPResult:
    """Run one ACP turn. Permission callbacks select explicit, one-time IDs.

    Timeout raises TimeoutError and caller cancellation raises CancelledError,
    after cancelling the session and terminating its process group. Callbacks
    must cooperate with asyncio cancellation. No credentials are inherited from
    the environment unless explicitly supplied by the caller.
    """
    try:
        import acp
        from acp.schema import (
            AllowedOutcome,
            ClientCapabilities,
            DeniedOutcome,
            RequestPermissionResponse,
        )
    except ImportError as exc:
        raise WorkspaceError("ACP support requires: pip install 'jev-reflex[harness]'") from exc

    if not argv or not all(isinstance(arg, str) and arg and "\0" not in arg for arg in argv):
        raise WorkspaceError("ACP requires a nonempty executable argument list")
    if not math.isfinite(timeout) or timeout <= 0:
        raise WorkspaceError("ACP timeout must be positive and finite")
    canonical = validate_workspace(workspace)
    active_session: str | None = None
    accepting = False
    output_bytes = 0
    output_limit = 1024 * 1024

    async def emit(event: dict[str, Any]) -> None:
        nonlocal output_bytes
        encoded = json.dumps(event, ensure_ascii=True)
        if output_bytes + len(encoded) > output_limit:
            return
        output_bytes += len(encoded)
        result = on_event(event)
        if inspect.isawaitable(result):
            await result

    class Client:
        def on_connect(self, conn: Any) -> None:
            pass

        async def session_update(self, session_id: str, update: Any, **kwargs: Any) -> None:
            if accepting and session_id == active_session:
                await emit(
                    {
                        "type": "session_update",
                        "session_id": session_id,
                        "update": update.model_dump(mode="json", by_alias=True),
                    }
                )

        async def request_permission(
            self, session_id: str, tool_call: Any, options: list[Any], **kwargs: Any
        ) -> Any:
            denied = RequestPermissionResponse(outcome=DeniedOutcome(outcome="cancelled"))
            if not accepting or session_id != active_session or on_permission is None:
                return denied
            safe = [item for item in options if item.kind in {"allow_once", "reject_once"}]
            # Ambiguous IDs must never accidentally select an always grant.
            ids = [item.option_id for item in options]
            if len(ids) != len(set(ids)) or not safe:
                return denied
            try:
                selected = await on_permission(
                    {
                        "session_id": session_id,
                        "tool_call": tool_call.model_dump(mode="json", by_alias=True),
                        "options": [item.model_dump(mode="json", by_alias=True) for item in safe],
                    }
                )
            except Exception:
                return denied
            if (
                not accepting
                or session_id != active_session
                or selected not in {x.option_id for x in safe}
            ):
                return denied
            return RequestPermissionResponse(
                outcome=AllowedOutcome(outcome="selected", option_id=str(selected))
            )

        async def _deny(self, *args: Any, **kwargs: Any) -> Any:
            raise acp.RequestError(
                -32601, "Client filesystem, terminal and extension access disabled"
            )

        read_text_file = write_text_file = create_terminal = _deny
        terminal_output = release_terminal = wait_for_terminal_exit = kill_terminal = _deny
        create_elicitation = complete_elicitation = ext_method = ext_notification = _deny

    async def terminate(process: asyncio.subprocess.Process) -> None:
        # Kill the entire group even when its leader has already exited.
        if os.name != "nt":
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            await asyncio.sleep(0.05)
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        elif process.returncode is None:
            process.kill()
        await asyncio.wait_for(process.wait(), 3)

    with WorkspaceLock(canonical):
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=canonical,
            env=dict(env) if env is not None else dict(acp.default_environment()),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=1024 * 1024,
            start_new_session=os.name != "nt",
        )
        conn = None
        try:
            conn = acp.connect_to_agent(Client(), process.stdin, process.stdout)
            async with asyncio.timeout(timeout):
                initialized = await conn.initialize(
                    protocol_version=acp.PROTOCOL_VERSION,
                    client_capabilities=ClientCapabilities(terminal=False),
                )
                if initialized.protocol_version != acp.PROTOCOL_VERSION:
                    raise WorkspaceError("ACP agent negotiated an unsupported protocol version")
                if resume_session_id:
                    if (
                        not initialized.agent_capabilities
                        or not initialized.agent_capabilities.load_session
                    ):
                        raise WorkspaceError("ACP agent does not support loading sessions")
                    await conn.load_session(
                        cwd=str(canonical), session_id=resume_session_id, mcp_servers=[]
                    )
                    active_session = resume_session_id
                else:
                    created = await conn.new_session(cwd=str(canonical), mcp_servers=[])
                    active_session = created.session_id
                if not active_session:
                    raise WorkspaceError("ACP agent returned an empty session ID")
                accepting = True
                await emit({"type": "session_started", "session_id": active_session})
                result = await conn.prompt(
                    session_id=active_session, prompt=[acp.text_block(prompt)]
                )
                return ACPResult(active_session, result.stop_reason)
        finally:
            accepting = False
            if conn is not None and active_session:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(conn.cancel(session_id=active_session), 1)
            if conn is not None:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(conn.close(), 1)
            await terminate(process)
