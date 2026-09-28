"""Curses terminal workspace and safe provider diagnostics."""

from __future__ import annotations

import importlib
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    curses: Any = importlib.import_module("curses")
except ImportError:  # Windows diagnostics/setup remain usable without curses.
    curses = None

from ..broker import BrokerClient
from ..config import ReflexConfig, load_config
from .handoff import (
    build_portable_record,
    record_delivery,
    refresh_workspace_snapshot,
    render_handoff_prompt,
    render_initial_task_prompt,
    save_checkpoint,
)
from .hooks import apply_hook_change, hook_configured, preview_hook_change
from .process import launch_native, stream_structured
from .providers import (
    ModelChoice,
    ProviderStatus,
    detect_providers,
    discover_models,
)
from .state import (
    WorkspaceError,
    WorkspaceLock,
    collect_workspace_state,
    list_task_records,
    save_task_record,
    validate_workspace,
)
from .streaming import NormalizedEvent, sanitize_terminal_text


def _load_workspace_config(workspace: Path, config_path: Path | None = None) -> ReflexConfig:
    try:
        selected_path = config_path or workspace / "reflex.yaml"
        return load_config(
            selected_path,
            scope=str(workspace),
            default_if_missing=config_path is None,
        )
    except (OSError, RuntimeError, ValueError):
        raise WorkspaceError(
            "JRX workspace configuration is invalid or unavailable; no agent was started"
        ) from None


def _jev_status(config: ReflexConfig) -> str:
    if config.jev.transport in {"broker", "broker-tls"}:
        try:
            status = BrokerClient(config).health()
        except (OSError, RuntimeError, ValueError):
            return "broker unavailable"
        if status.get("running") and status.get("jev_configured"):
            return "broker connected; JEV configured"
        if status.get("running"):
            return "broker connected; JEV key/config missing"
        return "broker unavailable"
    if os.environ.get("TYPESAFE_API_KEY"):
        return "TypeSafe host key present; not inherited by provider children; API reachability not probed"
    return "TypeSafe key not configured; not inherited by provider children"


def doctor_report(
    workspace: Path,
    *,
    config_path: Path | None = None,
    provider_filter: str | None = None,
    include_models: bool = False,
    json_output: bool = False,
) -> str:
    root = validate_workspace(workspace)
    config = _load_workspace_config(root, config_path)
    providers = detect_providers(root)
    if provider_filter is not None:
        providers = tuple(status for status in providers if status.provider.key == provider_filter)
    rows: list[dict[str, Any]] = []
    for status in providers:
        try:
            hook_present, coverage = hook_configured(root, status.provider)
        except WorkspaceError as exc:
            hook_present, coverage = False, str(exc)
        row: dict[str, Any] = {
            "provider": status.provider.key,
            "name": status.provider.display_name,
            "executable": status.provider.executable,
            "status": status.status,
            "version": status.version,
            "authentication": status.authentication,
            "auth_verified": status.auth_verified,
            "provider_api_key_present": status.api_key_conflict,
            "hook_configured": hook_present,
            "hook_detail": coverage,
            "enforcement_coverage": (
                "unverified: no real shell and file-edit denial smoke; non-advisory launch is blocked"
            ),
            "structured_output": status.structured_output,
            "detail": status.detail,
        }
        if include_models and status.status == "installed":
            catalog = discover_models(status.provider.key, root)
            row["model_discovery"] = {
                "available": catalog.available,
                "source": catalog.source,
                "models": [
                    {"id": model.identifier, "name": model.display_name}
                    for model in catalog.choices
                ],
                "detail": catalog.detail,
            }
        rows.append(row)
    report = {
        "workspace": str(root),
        "jev": _jev_status(config),
        "policy_mode": config.mode,
        "enforced_provider_launch_available": False,
        "enforced_provider_launch_reason": (
            "No real-provider shell and file-edit denial smoke has been recorded for these CLI versions."
        ),
        "providers": rows,
        "platform": "POSIX terminal workspace"
        if os.name != "nt"
        else "unsupported for curses workspace",
    }
    if json_output:
        return json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True)
    lines = [
        f"Workspace: {root}",
        f"JEV: {_jev_status(config)}",
        f"Policy mode: {config.mode}",
        "Enforcement: non-advisory launches are blocked until real provider shell and file-edit denial checks pass.",
        "",
    ]
    for row in rows:
        version = row["version"] or "unknown version"
        lines.append(f"{row['name']}: {row['status']} ({row['executable']} {version})")
        if row["detail"]:
            lines.append(f"  Capability check: {row['detail']}")
        lines.append(f"  Authentication: {row['authentication']}")
        if row["provider_api_key_present"]:
            lines.append(
                "  Warning: provider API-key environment is present; it may select separately billed authentication."
            )
        lines.append(
            "  Hooks: "
            + ("configured" if row["hook_configured"] else "not configured")
            + f"; {row['hook_detail']}"
        )
        lines.append(f"  JRX coverage: {row['enforcement_coverage']}")
        if row["structured_output"]:
            lines.append("  Structured output: documented CLI mode detected")
        else:
            lines.append("  Structured output: unavailable or unknown; use native CLI")
        if include_models:
            catalog = row.get("model_discovery", {})
            if catalog.get("available"):
                lines.append(
                    f"  Models: {catalog['source']} ({len(catalog['models'])} account-visible)"
                )
            else:
                lines.append(f"  Models: {catalog.get('detail') or catalog.get('source')}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _put(window: Any, row: int, column: int, text: str, width: int) -> None:
    height, max_width = window.getmaxyx()
    if row < 0 or row >= height or column >= max_width:
        return
    safe = sanitize_terminal_text(text, max(1, width))
    try:
        window.addnstr(row, column, safe, max(1, min(width, max_width - column - 1)))
    except curses.error:
        pass


def _draw_lines(window: Any, lines: list[str], title: str = "JRX") -> None:
    window.erase()
    height, width = window.getmaxyx()
    _put(window, 0, 0, title, max(1, width - 1))
    for index, line in enumerate(lines[: max(0, height - 1)], start=1):
        _put(window, index, 0, line, max(1, width - 1))
    window.refresh()


def _message(window: Any, message: str, *, wait: bool = True) -> None:
    lines = message.splitlines() or [""]
    offset = 0
    while True:
        height, _width = window.getmaxyx()
        _draw_lines(
            window, [*lines[offset : offset + max(1, height - 2)], "", "Enter to continue"], "JRX"
        )
        if not wait:
            return
        key = window.getch()
        if key == curses.KEY_RESIZE:
            continue
        if key in (curses.KEY_DOWN, ord("j"), ord(" ")):
            offset = min(max(0, len(lines) - max(1, height - 2)), offset + max(1, height - 3))
            continue
        if key in (curses.KEY_UP, ord("k")):
            offset = max(0, offset - max(1, height - 3))
            continue
        return


def _wrap_review_lines(content: str, width: int) -> list[str]:
    """Wrap review text without dropping checkpoint data from the screen."""
    line_width = max(1, width)
    wrapped: list[str] = []
    for line in content.splitlines() or [""]:
        if not line:
            wrapped.append("")
            continue
        wrapped.extend(
            line[index : index + line_width] for index in range(0, len(line), line_width)
        )
    return wrapped


def _review_text(window: Any, content: str, title: str) -> bool:
    _height, width = window.getmaxyx()
    lines = _wrap_review_lines(content or "(empty preview)", max(1, width - 1))
    offset = 0
    while True:
        height, _width = window.getmaxyx()
        visible = max(1, height - 2)
        footer = (
            f"↑/↓ or j/k scroll • Enter continues • q declines • "
            f"{offset + 1}-{min(len(lines), offset + visible)}/{len(lines)}"
        )
        _draw_lines(window, [*lines[offset : offset + visible - 1], footer], title)
        key = window.getch()
        if key == curses.KEY_RESIZE:
            continue
        if key in (curses.KEY_DOWN, ord("j"), ord(" ")):
            offset = min(max(0, len(lines) - visible + 1), offset + max(1, visible - 2))
        elif key in (curses.KEY_UP, ord("k")):
            offset = max(0, offset - max(1, visible - 2))
        elif key in (ord("q"), 27):
            return False
        elif key in (10, 13, curses.KEY_ENTER):
            if offset + visible - 1 < len(lines):
                offset = min(len(lines) - visible + 1, offset + max(1, visible - 2))
            else:
                return True


def _prompt(window: Any, label: str, *, maximum: int = 8192) -> str | None:
    height, width = window.getmaxyx()
    _draw_lines(window, [label, "(Esc cancels)"], "JRX input")
    curses.echo()
    curses.curs_set(1)
    try:
        window.move(min(2, height - 1), 0)
        raw = window.getstr(max(1, min(width - 1, maximum)))
    except curses.error:
        return None
    finally:
        curses.noecho()
        curses.curs_set(0)
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def _prompt_list(window: Any, label: str, *, maximum_items: int = 30) -> list[str]:
    values: list[str] = []
    while len(values) < maximum_items:
        value = _prompt(window, f"{label} — item {len(values) + 1}; blank ends list:", maximum=2048)
        if value is None or not value.strip():
            return values
        values.append(value.strip())
    _message(window, f"Reached the {maximum_items}-item limit for {label}.")
    return values


def _updated_pending_work(window: Any, current: list[str]) -> list[str]:
    if not _confirm(
        window,
        "Replace the checkpoint's pending-work list? If yes, enter its full current contents; a blank first item clears it.",
    ):
        return current
    return _prompt_list(window, "Current remaining work")


def _collect_task_context(window: Any) -> dict[str, Any]:
    _message(
        window,
        "Add optional shared-task facts. Entered completed work and test results are user-reported; JRX does not verify them here. Blank list entries finish each section.",
    )
    context: dict[str, Any] = {
        "constraints": _prompt_list(window, "User constraints"),
        "approved_decisions": _prompt_list(window, "User-approved decisions"),
        "completed_work": _prompt_list(window, "User-reported completed work"),
        "pending_work": _prompt_list(window, "Pending work"),
        "open_questions": _prompt_list(window, "Open questions"),
        "known_failures": _prompt_list(window, "Known failures"),
        "test_results": [],
    }
    command = _prompt(window, "Observed test command (blank skips test evidence):", maximum=1000)
    if command:
        result = _prompt(window, "Observed test result:", maximum=2000)
        if result:
            context["test_results"] = [
                {
                    "command": command,
                    "observed_result": result,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "provenance": "user-reported at this timestamp; JRX did not run or verify it",
                }
            ]
    return context


def _confirm(window: Any, question: str) -> bool:
    _draw_lines(window, [question, "y = confirm • any other key = cancel"], "JRX confirmation")
    key = window.getch()
    return key in (ord("y"), ord("Y"))


def _launch_in_native_terminal(
    window: Any, *args: Any, **kwargs: Any
) -> tuple[int | None, list[str]]:
    """Hand the terminal to the native CLI, then restore the curses screen."""
    curses.def_prog_mode()
    curses.endwin()
    try:
        return launch_native(*args, **kwargs)
    finally:
        curses.reset_prog_mode()
        window.clearok(True)
        window.refresh()


def _model_menu(window: Any, provider: str, workspace: Path) -> str | None:
    catalog = discover_models(provider, workspace)
    if not catalog.available:
        _message(
            window,
            f"{catalog.detail}\n\nUse the provider's native model selector. Model remains unknown until confirmed.",
        )
        return None
    choices = [ModelChoice("", "Use provider native selector"), *catalog.choices]
    selected = 0
    while True:
        lines = [f"Models from {catalog.source}:"]
        lines += [
            f"{'>' if index == selected else ' '} {choice.display_name} "
            + (f"({choice.identifier})" if choice.identifier else "")
            for index, choice in enumerate(choices)
        ]
        lines.append("↑/↓ select • Enter confirms • q cancels")
        _draw_lines(window, lines, f"{provider} models")
        key = window.getch()
        if key in (curses.KEY_DOWN, ord("j")):
            selected = (selected + 1) % len(choices)
        elif key in (curses.KEY_UP, ord("k")):
            selected = (selected - 1) % len(choices)
        elif key in (ord("q"), 27):
            return None
        elif key in (10, 13, curses.KEY_ENTER):
            return choices[selected].identifier or None


def _enforcement_confirmation(
    window: Any,
    provider: str,
    config: ReflexConfig,
) -> bool:
    if config.mode == "advisory":
        return _confirm(
            window,
            f"Policy mode is advisory for {provider}. JRX will not block provider actions in this mode.\n"
            "The provider's own permission settings remain active. Continue with this advisory run?",
        )
    _message(
        window,
        f"JRX cannot yet verify a denied shell action and a denied file edit through {provider}'s real hook path.\n"
        "This non-advisory launch is blocked. Native restrictions remain active.\n"
        "Use advisory mode for native sessions, or run the provider-specific real hook smoke checks before enabling enforcement.",
    )
    return False


class _StreamView:
    def __init__(self, window: Any, provider: str) -> None:
        self.window = window
        self.provider = provider
        self.lines: list[str] = []
        self.session_id: str | None = None
        self.model_id: str | None = None
        self.requires_native_fallback = False
        self.cancelled = False

    def poll_cancel(self) -> bool:
        try:
            self.window.nodelay(True)
            key = self.window.getch()
        except curses.error:
            return False
        finally:
            try:
                self.window.nodelay(False)
            except curses.error:
                pass
        return key in (ord("q"), 3)

    def __call__(self, event: NormalizedEvent) -> bool:
        if event.session_id:
            self.session_id = event.session_id
        if event.details is not None:
            model = event.details.get("model")
            if isinstance(model, str) and model and len(model) <= 128:
                self.model_id = model
        if event.kind == "output":
            text = event.text
            label = ""
        elif event.kind == "approval_request" or (
            event.kind == "turn_ended"
            and event.details is not None
            and event.details.get("provider_status") == "WAITING"
        ):
            self.requires_native_fallback = True
            text = f"{event.text} Native approval required; no approval was sent by JRX."
            label = "APPROVAL"
        elif event.kind == "failure":
            text = event.text
            label = "ERROR"
        elif event.kind == "cancelled":
            self.cancelled = True
            text = event.text
            label = "CANCELLED"
        elif event.kind == "turn_ended":
            text = event.text
            label = "TURN"
        elif event.kind == "tool_activity":
            text = event.text
            label = "TOOL"
        elif event.raw_type == "stderr":
            text = event.text
            label = "stderr"
        else:
            text = event.text
            label = "event"
        for piece in text.splitlines() or ([text] if text else []):
            if piece:
                self.lines.append(f"{label}: {piece}" if label else piece)
        self.lines = self.lines[-200:]
        height, _width = self.window.getmaxyx()
        visible = max(1, height - 2)
        _draw_lines(
            self.window,
            [
                f"{self.provider} structured stream • advisory mode only",
                *self.lines[-(visible - 1) :],
                "q cancels and stops the process tree",
            ],
            "JRX integrated output",
        )
        return not self.requires_native_fallback


def _structured_process_state(exit_code: int | None, view: _StreamView) -> str:
    if view.cancelled:
        return "cancelled by user; checkpoint retained"
    return f"exited with code {exit_code}" if exit_code is not None else "spawn failed"


def _offer_native_approval_fallback(
    window: Any,
    workspace: Path,
    provider: str,
    view: _StreamView,
    *,
    allow_api_key: bool,
    lock: WorkspaceLock | None = None,
) -> int | None:
    if not view.requires_native_fallback:
        return None
    reference = view.session_id or "unknown; provider native resume behavior will be used"
    if not _confirm(
        window,
        "The structured process stopped at a provider approval boundary.\n"
        f"Session reference: {reference}\n"
        "Open the provider's native resume flow so its own approval UI can decide? JRX will not replay the prompt.",
    ):
        return None
    code, _argv = _launch_in_native_terminal(
        window,
        provider,
        workspace,
        resume=True,
        session_ref=view.session_id,
        allow_api_key=allow_api_key,
        lock=lock,
    )
    return code


def _task_record(
    workspace: Path,
    config: ReflexConfig,
    provider: str,
    *,
    objective: str,
    session_id: str | None,
    model: str | None,
    version: str | None,
    status: str,
    task_context: dict[str, Any] | None = None,
    session_kind: str = "native_interactive",
) -> dict[str, Any]:
    context = task_context or {}
    record = build_portable_record(
        workspace=workspace,
        config=config,
        objective=objective,
        constraints=context.get("constraints", []),
        approved_decisions=context.get("approved_decisions", []),
        completed_work=context.get("completed_work", []),
        pending_work=context.get("pending_work", []),
        open_questions=context.get("open_questions", []),
        known_failures=context.get("known_failures", []),
        test_results=context.get("test_results", []),
        source_provider=provider,
        source_session=session_id,
        destination_provider=provider,
    )
    record["session"] = {
        "provider": provider,
        "session_kind": session_kind,
        "native_session_reference": session_id,
        "session_reference_status": "known"
        if session_id
        else "unknown; use provider's native resume picker",
        "jrx_task_id": record["task_id"],
        "model": model,
        "model_status": "requested; provider confirmation unavailable"
        if model
        else "unknown; provider native selector",
        "cli_version": version,
        "process_state": "starting",
        "task_completion": "not independently verified",
    }
    record["context_delivery"] = status
    return record


def _record_task_context(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "constraints": record.get("constraints", []),
        "approved_decisions": record.get("approved_decisions", []),
        "completed_work": record.get("completed_work", []),
        "pending_work": record.get("pending_work", []),
        "open_questions": record.get("open_questions", []),
        "known_failures": record.get("known_failures", []),
        "test_results": record.get("tests", []),
    }


def _resume_record(window: Any, workspace: Path, provider: str) -> dict[str, Any] | None:
    try:
        records = list_task_records(workspace, provider)
    except WorkspaceError as exc:
        _message(window, f"Saved session records are unavailable.\n{exc}")
        return None
    if not records:
        _message(
            window,
            f"No JRX session record matches this workspace and {provider}.\n"
            "The next prompt will use the provider's native resume behavior.",
        )
        return None
    selected = 0
    while True:
        lines = ["Choose a saved provider session:"]
        for index, record in enumerate(records):
            session = record.get("session", {})
            reference_status = (
                session.get("session_reference_status", "unknown")
                if isinstance(session, dict)
                else "unknown"
            )
            objective = str(record.get("objective", "(no objective recorded)")).replace("\n", " ")
            lines.append(
                f"{'>' if index == selected else ' '} {record.get('updated_at', 'unknown time')} • "
                f"{objective[:65]} • {reference_status}"
            )
        lines.append("↑/↓ select • Enter resumes • q uses provider-native resume behavior")
        _draw_lines(window, lines, f"{provider} saved sessions")
        key = window.getch()
        if key == curses.KEY_RESIZE:
            continue
        if key in (ord("q"), 27):
            return None
        if key in (curses.KEY_DOWN, ord("j")):
            selected = (selected + 1) % len(records)
        elif key in (curses.KEY_UP, ord("k")):
            selected = (selected - 1) % len(records)
        elif key in (10, 13, curses.KEY_ENTER):
            return records[selected]


def _run_selected(
    window: Any,
    workspace: Path,
    config: ReflexConfig,
    selected: ProviderStatus,
    *,
    model: str | None,
    resume: bool,
    active_record: dict[str, Any] | None,
    objective: str,
    task_context: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    provider = selected.provider.key
    if selected.status != "installed":
        _message(
            window,
            f"{selected.provider.display_name} is {selected.status}.\n"
            f"{selected.detail or 'Check the executable and run jrx doctor.'}\n"
            "Install it using its official instructions if it is missing, then run jrx doctor.",
        )
        return active_record
    if not _enforcement_confirmation(window, provider, config):
        return active_record
    resume_ref: str | None = None
    if resume and active_record:
        session = active_record.get("session")
        if isinstance(session, dict) and session.get("provider") == provider:
            reference = session.get("native_session_reference")
            resume_ref = (
                reference if isinstance(reference, str) and 0 < len(reference) <= 256 else None
            )
    previous_session = active_record.get("session") if active_record else None
    previous_session_kind = (
        previous_session.get("session_kind") if isinstance(previous_session, dict) else None
    )
    if (
        not isinstance(previous_session_kind, str)
        and provider == "codex"
        and isinstance(active_record, dict)
        and str(active_record.get("context_delivery", "")).startswith("structured stream")
    ):
        # Older records used this delivery status for `codex exec --json`.
        previous_session_kind = "codex_exec"
    codex_exec_resume = resume and provider == "codex" and previous_session_kind == "codex_exec"
    antigravity_structured_resume = (
        resume
        and provider == "antigravity"
        and previous_session_kind == "antigravity_structured"
        and resume_ref is not None
    )
    previous_model = (
        previous_session.get("model") if resume and isinstance(previous_session, dict) else None
    )
    previous_sandbox_mode = (
        previous_session.get("sandbox_mode")
        if resume and isinstance(previous_session, dict)
        else None
    )
    if codex_exec_resume and resume_ref is None:
        _message(
            window,
            "This Codex structured session has no saved session ID. JRX cannot safely choose a different recent session.",
        )
        return active_record
    if codex_exec_resume and previous_sandbox_mode not in {"read-only", "workspace-write"}:
        _message(
            window,
            "JRX cannot verify this Codex structured session's saved sandbox mode.\n"
            "Managed resume is blocked; use the provider's native terminal and review its session settings.",
        )
        return active_record
    if codex_exec_resume and not _confirm(
        window,
        "Codex exec resume has no sandbox override. This JRX session records its initial sandbox mode as "
        f"{previous_sandbox_mode}; Codex will resume its saved native session restrictions. Continue?",
    ):
        return active_record
    if resume and resume_ref is None:
        if not _confirm(
            window,
            "This record has no provider session ID JRX can verify.\n"
            "Continue with the provider's own resume/recent-session behavior? It may select a different recent session.",
        ):
            return active_record
    if resume and not objective and active_record:
        saved_objective = active_record.get("objective")
        objective = saved_objective if isinstance(saved_objective, str) else ""
    if resume and not task_context and active_record:
        task_context = _record_task_context(active_record)

    native_objective_needs_manual_entry = (
        provider == "antigravity"
        and not resume
        and bool(objective)
        and not selected.structured_output
    )
    if native_objective_needs_manual_entry and not _confirm(
        window,
        "This Antigravity version has no verified structured prompt interface.\n"
        "JRX will show your objective, then open the native TUI without sending it.\n"
        "You will need to enter the objective again there. Continue?",
    ):
        return active_record

    allow_api_key = False
    if selected.api_key_conflict:
        if not _confirm(
            window,
            "A provider API-key environment variable is present. It may select separately billed authentication.\n"
            "JRX does not read or display its value. Continue with the official CLI's current authentication selection?",
        ):
            return active_record
        allow_api_key = True

    resume_prompt: str | None = None
    if codex_exec_resume or antigravity_structured_resume:
        label = (
            "Antigravity conversation" if antigravity_structured_resume else "Codex exec session"
        )
        resume_prompt = _prompt(window, f"Follow-up instruction for this saved {label}:")
        if not resume_prompt:
            return active_record

    new_session_id = str(uuid.uuid4()) if provider == "claude" and not resume else None
    record = _task_record(
        workspace,
        config,
        provider,
        objective=objective,
        session_id=resume_ref or new_session_id,
        model=model,
        version=selected.version,
        status=(
            "native CLI starting; objective must be entered by the user"
            if native_objective_needs_manual_entry
            else "agent starting; completion unknown"
        ),
        task_context=task_context,
        session_kind=(
            previous_session_kind
            if resume and isinstance(previous_session_kind, str)
            else "native_interactive"
        ),
    )
    if native_objective_needs_manual_entry:
        _message(window, "Objective to enter in Antigravity's native TUI:\n\n" + objective)
    if resume and model is None and isinstance(previous_model, str):
        record["session"]["model"] = previous_model
        record["session"]["model_status"] = (
            "last requested before resume; current session model is unknown"
        )
    if codex_exec_resume and previous_sandbox_mode in {"read-only", "workspace-write"}:
        record["session"]["sandbox_mode"] = previous_sandbox_mode
    try:
        save_task_record(record)
    except (OSError, WorkspaceError) as exc:
        _message(window, f"Could not save private task metadata.\n{exc}\nNo provider was started.")
        return active_record

    prompt = (
        render_initial_task_prompt(objective, task_context) if not resume and objective else None
    )
    if codex_exec_resume:
        view = _StreamView(window, provider)
        try:
            exit_code, _argv = stream_structured(
                provider,
                workspace,
                resume_prompt or "",
                view,
                model=model,
                resume_session_ref=resume_ref,
                allow_api_key=allow_api_key,
                cancel_requested=view.poll_cancel,
            )
            fallback_code = _offer_native_approval_fallback(
                window, workspace, provider, view, allow_api_key=allow_api_key
            )
        except (KeyboardInterrupt, SystemExit):
            record["session"]["process_state"] = "interrupted; checkpoint retained"
            save_task_record(record)
            raise
        if view.session_id and view.session_id != resume_ref:
            record["session"]["native_session_reference"] = resume_ref
            record["session"]["session_reference_status"] = (
                "provider returned a mismatched session ID; original reference retained"
            )
        else:
            record["session"]["native_session_reference"] = resume_ref
            record["session"]["session_reference_status"] = (
                "confirmed from resumed structured event"
                if view.session_id == resume_ref
                else "retained from requested Codex exec resume; provider omitted ID"
            )
        if view.model_id:
            record["session"]["model"] = view.model_id
            record["session"]["model_status"] = "confirmed from provider init event"
        record["session"]["process_state"] = _structured_process_state(exit_code, view)
        if view.requires_native_fallback:
            record["session"]["native_approval_fallback_exit_code"] = fallback_code
        record["session"]["task_completion"] = "not independently verified"
        record["context_delivery"] = (
            "Codex exec session cancelled; checkpoint retained"
            if view.cancelled
            else "Codex exec session resumed; follow-up receipt unconfirmed"
        )
        record["session"]["sandbox_mode_status"] = (
            "inherited from initial JRX launch; Codex exec resume exposes no sandbox override"
        )
        save_task_record(record)
        return record

    if antigravity_structured_resume:
        view = _StreamView(window, provider)
        try:
            exit_code, _argv = stream_structured(
                provider,
                workspace,
                resume_prompt or "",
                view,
                model=model or (previous_model if isinstance(previous_model, str) else None),
                resume_session_ref=resume_ref,
                allow_api_key=allow_api_key,
                cancel_requested=view.poll_cancel,
            )
            fallback_code = _offer_native_approval_fallback(
                window, workspace, provider, view, allow_api_key=allow_api_key
            )
        except (KeyboardInterrupt, SystemExit):
            record["session"]["process_state"] = "interrupted; checkpoint retained"
            save_task_record(record)
            raise
        if view.session_id and view.session_id != resume_ref:
            record["session"]["native_session_reference"] = resume_ref
            record["session"]["session_reference_status"] = (
                "provider returned a mismatched conversation ID; original reference retained"
            )
        else:
            record["session"]["native_session_reference"] = resume_ref
            record["session"]["session_reference_status"] = (
                "confirmed from resumed structured event"
                if view.session_id == resume_ref
                else "retained from requested Antigravity conversation; provider omitted ID"
            )
        if view.model_id:
            record["session"]["model"] = view.model_id
            record["session"]["model_status"] = "confirmed from provider init event"
        record["session"]["process_state"] = _structured_process_state(exit_code, view)
        if view.requires_native_fallback:
            record["session"]["native_approval_fallback_exit_code"] = fallback_code
        record["session"]["task_completion"] = "not independently verified"
        record["context_delivery"] = (
            "Antigravity conversation resume cancelled; checkpoint retained"
            if view.cancelled
            else "Antigravity conversation resumed; follow-up receipt unconfirmed"
        )
        save_task_record(record)
        return record

    if provider == "antigravity" and not resume and objective and selected.structured_output:
        if config.mode != "advisory":
            _message(
                window,
                "Antigravity structured headless mode cannot present its native interactive approvals.\n"
                "Enforced/review launch with an initial prompt is blocked. Start its native TUI and enter the task there.",
            )
            record["session"]["process_state"] = "not started; native approval fallback required"
            record["context_delivery"] = "destination validation failed; checkpoint retained"
            save_task_record(record)
            return record
        view = _StreamView(window, provider)
        try:
            exit_code, _argv = stream_structured(
                provider,
                workspace,
                prompt or objective,
                view,
                model=model,
                allow_api_key=allow_api_key,
                cancel_requested=view.poll_cancel,
            )
            fallback_code = _offer_native_approval_fallback(
                window, workspace, provider, view, allow_api_key=allow_api_key
            )
        except (KeyboardInterrupt, SystemExit):
            record["session"]["process_state"] = "interrupted; checkpoint retained"
            record["context_delivery"] = "destination launch failed; checkpoint retained"
            save_task_record(record)
            raise
        record["session"]["native_session_reference"] = view.session_id
        record["session"]["session_reference_status"] = (
            "known from structured init event" if view.session_id else "unknown"
        )
        if view.model_id:
            record["session"]["model"] = view.model_id
            record["session"]["model_status"] = "confirmed from provider init event"
        record["session"]["process_state"] = _structured_process_state(exit_code, view)
        record["context_delivery"] = (
            "structured stream cancelled; checkpoint retained"
            if view.cancelled
            else "structured stream started; provider receipt unconfirmed"
            if exit_code is not None
            else "destination launch failed; checkpoint retained"
        )
        if view.requires_native_fallback:
            record["session"]["native_approval_fallback_exit_code"] = fallback_code
        record["session"]["task_completion"] = "not independently verified"
        save_task_record(record)
        return record

    try:
        exit_code, _argv = _launch_in_native_terminal(
            window,
            provider,
            workspace,
            model=model,
            resume=resume,
            session_ref=resume_ref,
            new_session_id=new_session_id,
            initial_prompt=prompt,
            allow_api_key=allow_api_key,
        )
    except (KeyboardInterrupt, SystemExit):
        record["session"]["process_state"] = "interrupted; checkpoint retained"
        save_task_record(record)
        raise
    record["session"]["process_state"] = (
        f"exited with code {exit_code}" if exit_code is not None else "spawn failed"
    )
    record["session"]["task_completion"] = "not independently verified"
    if resume and exit_code != 0:
        record["session"]["session_reference_status"] = (
            "resume failed; native reference may be stale"
            if exit_code is not None
            else "resume could not start; reference retained"
        )
    save_task_record(record)
    if exit_code is None:
        _message(
            window,
            f"Could not start {selected.provider.display_name}.\nCheck installation and executable permissions.",
        )
    else:
        _message(
            window,
            f"{selected.provider.display_name} exited with code {exit_code}.\n"
            "JRX records process exit separately; task completion is not inferred.",
        )
    return record


def _setup_screen(window: Any, workspace: Path, selected: ProviderStatus) -> None:
    try:
        path, preview, changed = preview_hook_change(workspace, selected.provider)
    except (OSError, WorkspaceError) as exc:
        _message(window, f"Setup preview failed.\n{exc}")
        return
    if not _review_text(window, preview, f"Preview hook setup: {path}"):
        return
    if not changed:
        return
    if not _confirm(
        window,
        "Apply this merged provider hook configuration? A private targeted backup will be created.",
    ):
        return
    try:
        path, backup, applied = apply_hook_change(workspace, selected.provider)
        _message(
            window,
            f"{'Applied' if applied else 'No change'}: {path}\n"
            + (f"Backup: {backup}" if backup else "No existing file required a backup.")
            + "\nUse jrx setup --rollback for targeted removal.",
        )
    except (OSError, WorkspaceError) as exc:
        _message(window, f"Setup failed without overwriting unrelated settings.\n{exc}")


def _handoff_screen(
    window: Any,
    workspace: Path,
    config: ReflexConfig,
    statuses: tuple[ProviderStatus, ...],
    source_record: dict[str, Any] | None,
    objective_draft: str = "",
    context_draft: dict[str, Any] | None = None,
    source_provider_draft: str | None = None,
    models_by_provider: dict[str, str | None] | None = None,
) -> dict[str, Any] | None:
    source_info = source_record.get("session", {}) if source_record else {}
    source_provider = (
        source_info.get("provider") if isinstance(source_info, dict) else None
    ) or source_provider_draft
    targets = [
        item
        for item in statuses
        if item.status == "installed" and item.provider.key != source_provider
    ]
    if not targets:
        _message(window, "No installed destination CLI is available.")
        return source_record
    lines = ["Choose destination provider:"]
    lines.extend(
        f"{index + 1}. {target.provider.display_name} ({target.provider.key})"
        for index, target in enumerate(targets)
    )
    _draw_lines(window, lines, "JRX handoff")
    key = window.getch()
    if key not in tuple(ord(str(number)) for number in range(1, min(9, len(targets)) + 1)):
        return source_record
    destination = targets[key - ord("1")]
    destination_model = (models_by_provider or {}).get(destination.provider.key)
    source_session = (
        source_info.get("native_session_reference") if isinstance(source_info, dict) else None
    )
    objective = objective_draft
    constraints: list[str] = []
    decisions: list[str] = []
    completed: list[str] = []
    pending: list[str] = []
    questions: list[str] = []
    failures: list[str] = []
    test_results: list[dict[str, Any]] = []
    prior_summary = ""
    if source_record:
        objective = str(source_record.get("objective", ""))
        constraints = list(source_record.get("constraints", []))
        decisions = list(source_record.get("approved_decisions", []))
        completed = list(source_record.get("completed_work", []))
        pending = list(source_record.get("pending_work", []))
        questions = list(source_record.get("open_questions", []))
        failures = list(source_record.get("known_failures", []))
        test_results = list(source_record.get("tests", []))
        prior_summary = str(source_record.get("agent_authored_summary", ""))
        if objective_draft:
            objective = objective_draft
            if context_draft:
                constraints = list(context_draft.get("constraints", []))
                decisions = list(context_draft.get("approved_decisions", []))
                completed = list(context_draft.get("completed_work", []))
                pending = list(context_draft.get("pending_work", []))
                questions = list(context_draft.get("open_questions", []))
                failures = list(context_draft.get("known_failures", []))
                test_results = list(context_draft.get("test_results", []))
    elif context_draft:
        constraints = list(context_draft.get("constraints", []))
        decisions = list(context_draft.get("approved_decisions", []))
        completed = list(context_draft.get("completed_work", []))
        pending = list(context_draft.get("pending_work", []))
        questions = list(context_draft.get("open_questions", []))
        failures = list(context_draft.get("known_failures", []))
        test_results = list(context_draft.get("test_results", []))
    if source_record:
        _message(
            window,
            "Record operator-verified updates after the source stopped. Blank lists keep existing completed work, questions, failures, and tests. Remaining work can be replaced explicitly. Do not enter unverified agent claims as test results.",
        )
        completed.extend(_prompt_list(window, "Verified completed work"))
        pending = _updated_pending_work(window, pending)
        questions.extend(_prompt_list(window, "Current open questions"))
        failures.extend(_prompt_list(window, "Observed failures"))
        test_command = _prompt(
            window, "Test command you ran after the source stopped (blank skips):", maximum=1_000
        )
        if test_command:
            test_result = _prompt(
                window, "Observed test result and platform/version context:", maximum=2_000
            )
            if test_result:
                test_results.append(
                    {
                        "command": test_command,
                        "observed_result": test_result,
                        "timestamp": datetime.now(UTC).isoformat(),
                        "provenance": "operator-observed before handoff; JRX did not execute",
                    }
                )
    if not objective:
        value = _prompt(window, "User objective to share (required):")
        if not value:
            _message(window, "Handoff cancelled; no objective was shared.")
            return source_record
        objective = value
        context_draft = _collect_task_context(window)
        constraints = list(context_draft.get("constraints", []))
        decisions = list(context_draft.get("approved_decisions", []))
        completed = list(context_draft.get("completed_work", []))
        pending = list(context_draft.get("pending_work", []))
        questions = list(context_draft.get("open_questions", []))
        failures = list(context_draft.get("known_failures", []))
        test_results = list(context_draft.get("test_results", []))
    summary = _prompt(
        window, "Optional agent-authored summary (labelled unverified; blank to omit):"
    )
    summary = summary if summary is not None else prior_summary
    try:
        lock = WorkspaceLock(workspace)
        lock.acquire()
    except WorkspaceError as exc:
        _message(window, f"Handoff cannot start because the source may still be writing.\n{exc}")
        return source_record
    task_path: Path | None = None
    try:
        record = build_portable_record(
            workspace=workspace,
            config=config,
            objective=objective,
            constraints=constraints,
            approved_decisions=decisions,
            completed_work=completed,
            pending_work=pending,
            open_questions=questions,
            known_failures=failures,
            test_results=test_results,
            source_provider=source_provider,
            source_session=source_session,
            destination_provider=destination.provider.key,
            agent_summary=summary or "",
        )
        record["source"] = {"provider": source_provider, "session_id": source_session}
        record["destination"] = {"provider": destination.provider.key}
        prompt = render_handoff_prompt(record)
        task_path, _context_path = save_checkpoint(record)
        if not _review_text(window, prompt, "Review cross-provider checkpoint"):
            record_delivery(record, "user declined sharing")
            _message(window, f"Sharing declined. Recoverable checkpoint: {task_path}")
            return record
        try:
            snapshot_status = refresh_workspace_snapshot(record, workspace)
        except (OSError, WorkspaceError) as exc:
            record_delivery(record, "destination validation failed; checkpoint retained")
            _message(
                window, f"Workspace validation failed; checkpoint retained.\n{exc}\n{task_path}"
            )
            return record
        if snapshot_status != "unchanged":
            record_delivery(record, "workspace changed; refresh required")
            if snapshot_status == "incomplete":
                _message(
                    window,
                    "A changed file exceeds JRX's safe fingerprint limit, so workspace stability cannot be verified.\n"
                    f"Checkpoint retained at {task_path}; review and continue manually in the destination's native CLI.",
                )
                return record
            _message(
                window,
                f"Workspace changed during handoff review. Refresh and review again.\nCheckpoint: {task_path}",
            )
            return record
        if not _enforcement_confirmation(window, destination.provider.key, config):
            record_delivery(record, "destination validation failed; checkpoint retained")
            return record
        if destination.provider.key == "antigravity" and not destination.structured_output:
            record_delivery(record, "destination validation failed; checkpoint retained")
            _message(
                window,
                "Antigravity structured output is unavailable for this CLI version.\n"
                f"Checkpoint retained at {task_path}; copy its reviewed prompt into the native terminal.",
            )
            return record
        if destination.api_key_conflict:
            if not _confirm(
                window,
                "Destination API-key environment is present and may select separately billed authentication.\n"
                "JRX will not display its value. Continue with the current CLI authentication selection?",
            ):
                record_delivery(record, "destination validation failed; checkpoint retained")
                return record
        codex_sandbox_mode: str | None = None
        if destination.provider.key == "codex":
            if not _confirm(
                window,
                "Codex will receive this reviewed handoff through its documented workspace-write sandbox for this one advisory run.\n"
                "The model can write inside this selected workspace; other Codex sandbox boundaries remain active. Continue?",
            ):
                record_delivery(record, "destination write scope declined; checkpoint retained")
                return record
            codex_sandbox_mode = "workspace-write"
        if destination.provider.key == "antigravity" and config.mode != "advisory":
            record_delivery(record, "destination validation failed; checkpoint retained")
            _message(
                window,
                "Antigravity structured handoff cannot present interactive approval prompts.\n"
                "The checkpoint is saved. Use its task record from the native terminal in advisory mode.",
            )
            return record
        try:
            snapshot_status = refresh_workspace_snapshot(record, workspace)
        except (OSError, WorkspaceError) as exc:
            record_delivery(record, "destination validation failed; checkpoint retained")
            _message(
                window,
                f"Workspace validation failed before launch; checkpoint retained.\n{exc}\n{task_path}",
            )
            return record
        if snapshot_status != "unchanged":
            record_delivery(record, "workspace changed; refresh required")
            if snapshot_status == "incomplete":
                _message(
                    window,
                    "A changed file exceeds JRX's safe fingerprint limit, so workspace stability cannot be verified.\n"
                    f"Checkpoint retained at {task_path}; review and continue manually in the destination's native CLI.",
                )
                return record
            _message(
                window,
                f"Workspace changed before destination launch. Refresh and review again.\nCheckpoint: {task_path}",
            )
            return record
        record_delivery(record, "prompt passed as initial input; provider receipt unconfirmed")
        destination_started = True
        new_id = str(uuid.uuid4()) if destination.provider.key == "claude" else None
        record["session"] = {
            "provider": destination.provider.key,
            "session_kind": (
                "antigravity_structured"
                if destination.provider.key == "antigravity"
                else "codex_exec"
                if destination.provider.key == "codex"
                else "native_interactive"
            ),
            "native_session_reference": new_id,
            "session_reference_status": "known" if new_id else "unknown until provider event",
            "jrx_task_id": record["task_id"],
            "model": destination_model,
            "model_status": (
                "requested; provider confirmation unavailable"
                if destination_model
                else "native selector; model unknown until confirmed"
            ),
            "cli_version": destination.version,
            "process_state": "starting",
            "task_completion": "not independently verified",
        }
        if codex_sandbox_mode:
            record["session"]["sandbox_mode"] = codex_sandbox_mode
        save_task_record(record)
        if destination.provider.key == "antigravity":
            view = _StreamView(window, destination.provider.key)
            exit_code, _argv = stream_structured(
                destination.provider.key,
                workspace,
                prompt,
                view,
                model=destination_model,
                allow_api_key=destination.api_key_conflict,
                lock=lock,
                cancel_requested=view.poll_cancel,
            )
            fallback_code = _offer_native_approval_fallback(
                window,
                workspace,
                destination.provider.key,
                view,
                allow_api_key=destination.api_key_conflict,
                lock=lock,
            )
            record["session"]["native_session_reference"] = view.session_id
            record["session"]["session_reference_status"] = (
                "known from structured init event" if view.session_id else "unknown"
            )
            if view.model_id:
                record["session"]["model"] = view.model_id
                record["session"]["model_status"] = "confirmed from provider init event"
            record["session"]["process_state"] = _structured_process_state(exit_code, view)
            if view.requires_native_fallback:
                record["session"]["native_approval_fallback_exit_code"] = fallback_code
        elif destination.provider.key == "codex":
            view = _StreamView(window, destination.provider.key)
            exit_code, _argv = stream_structured(
                destination.provider.key,
                workspace,
                prompt,
                view,
                model=destination_model,
                sandbox_mode=codex_sandbox_mode,
                allow_api_key=destination.api_key_conflict,
                lock=lock,
                cancel_requested=view.poll_cancel,
            )
            fallback_code = _offer_native_approval_fallback(
                window,
                workspace,
                destination.provider.key,
                view,
                allow_api_key=destination.api_key_conflict,
                lock=lock,
            )
            record["session"]["native_session_reference"] = view.session_id
            record["session"]["session_reference_status"] = (
                "known from structured init event" if view.session_id else "unknown"
            )
            if view.model_id:
                record["session"]["model"] = view.model_id
                record["session"]["model_status"] = "confirmed from provider init event"
            record["session"]["process_state"] = _structured_process_state(exit_code, view)
            if view.requires_native_fallback:
                record["session"]["native_approval_fallback_exit_code"] = fallback_code
        else:
            exit_code, _argv = _launch_in_native_terminal(
                window,
                destination.provider.key,
                workspace,
                model=destination_model,
                initial_prompt=prompt,
                new_session_id=new_id,
                allow_api_key=destination.api_key_conflict,
                lock=lock,
            )
            record["session"]["process_state"] = (
                f"exited with code {exit_code}" if exit_code is not None else "spawn failed"
            )
        record["session"]["task_completion"] = "not independently verified"
        if view.cancelled:
            record_delivery(record, "destination run cancelled; checkpoint retained")
        elif exit_code is None:
            record_delivery(record, "destination launch failed; checkpoint retained")
        else:
            save_task_record(record)
        return record
    except (OSError, WorkspaceError):
        if "record" in locals():
            if task_path is None:
                task_path = save_task_record(record)
            record_delivery(
                record,
                "destination launch failed; checkpoint retained"
                if locals().get("destination_started", False)
                else "destination validation failed; checkpoint retained",
            )
            _message(window, f"Handoff failed; recoverable checkpoint retained.\n{task_path}")
            return record
        _message(window, "Could not prepare a safe handoff checkpoint.")
        return source_record
    except (KeyboardInterrupt, SystemExit):
        if "record" in locals():
            record["session"] = record.get("session", {})
            if isinstance(record["session"], dict):
                record["session"]["process_state"] = "interrupted; checkpoint retained"
            if task_path is None:
                task_path = save_task_record(record)
            record_delivery(record, "destination launch failed; checkpoint retained")
        raise
    finally:
        lock.release()


def _main(window: Any, workspace: Path, config_path: Path | None) -> None:
    try:
        root = validate_workspace(workspace)
    except WorkspaceError as exc:
        _draw_lines(window, [str(exc), "Press q to exit"], "JRX workspace error")
        while window.getch() != ord("q"):
            pass
        return
    config = _load_workspace_config(root, config_path)
    statuses = list(detect_providers(root))
    active_index = 0
    selected_models: dict[str, str | None] = {item.provider.key: None for item in statuses}
    objective = ""
    task_context: dict[str, Any] = {}
    active_record: dict[str, Any] | None = None
    status_text = ""
    while True:
        try:
            state = collect_workspace_state(root)
            git_summary = (
                f"{state.get('branch') or 'branch unknown'} • {state.get('current_commit') or 'no commit'}"
                if state.get("git")
                else "non-Git directory • reduced handoff facts"
            )
        except (OSError, WorkspaceError):
            git_summary = "workspace state unavailable"
        lines = [
            f"Workspace: {root}",
            f"Git: {git_summary}",
            f"JEV: {_jev_status(config)}",
            f"Policy mode: {config.mode}",
            "Enforcement: non-advisory provider launches are currently blocked pending real hook denial checks.",
            "",
        ]
        for index, item in enumerate(statuses):
            selected = ">" if index == active_index else " "
            selected_model = selected_models.get(item.provider.key)
            model_label = selected_model or "provider native selector"
            try:
                hook_state = (
                    "hook configured"
                    if hook_configured(root, item.provider)[0]
                    else "hook not configured"
                )
            except WorkspaceError:
                hook_state = "hook config invalid or unsafe"
            lines.append(
                f"{selected} {index + 1}. {item.provider.display_name}: {item.status} "
                f"{item.version or ''} • auth: {item.authentication} • {hook_state}"
            )
            if index == active_index:
                lines.append(f"    Model: {model_label}")
                if item.status == "unsupported" or item.status == "unknown":
                    lines.append(f"    Provider detail: {item.detail}")
                if not item.structured_output:
                    lines.append("    Structured mode unavailable; Enter launches native terminal.")
                if item.api_key_conflict:
                    lines.append(
                        "    API-key environment present; launch will ask before continuing."
                    )
        if status_text:
            lines.extend(["", status_text])
        lines.extend(
            [
                "",
                "↑/↓ or 1-3 select • m models • t task • Enter native CLI • r resume",
                "s preview/apply hooks • h reviewed handoff • i structured stream (advisory only) • q quit",
            ]
        )
        _draw_lines(window, lines, "JRX terminal workspace")
        key = window.getch()
        if key == curses.KEY_RESIZE:
            continue
        if key in (ord("q"), 27):
            return
        if key in (curses.KEY_UP, ord("k")):
            active_index = (active_index - 1) % len(statuses)
        elif key in (curses.KEY_DOWN, ord("j")):
            active_index = (active_index + 1) % len(statuses)
        elif key in (ord("1"), ord("2"), ord("3")):
            next_index = key - ord("1")
            if next_index < len(statuses):
                active_index = next_index
        elif key == ord("m"):
            provider_key = statuses[active_index].provider.key
            selected_models[provider_key] = _model_menu(window, provider_key, root)
        elif key == ord("t"):
            value = _prompt(window, "Initial user objective (sent as one argv value):")
            if value:
                objective = value
                task_context = _collect_task_context(window)
        elif key == ord("s"):
            _setup_screen(window, root, statuses[active_index])
            statuses = list(detect_providers(root))
        elif key == ord("h"):
            active_record = _handoff_screen(
                window,
                root,
                config,
                tuple(statuses),
                active_record,
                objective,
                task_context,
                statuses[active_index].provider.key,
                selected_models,
            )
            statuses = list(detect_providers(root))
        elif key in (10, 13, curses.KEY_ENTER, ord("r")):
            chosen = statuses[active_index]
            resume = key == ord("r")
            selected_record = active_record
            if resume and (
                not isinstance(selected_record, dict)
                or not isinstance(selected_record.get("session"), dict)
                or selected_record["session"].get("provider") != chosen.provider.key
            ):
                selected_record = _resume_record(window, root, chosen.provider.key)
            if (
                chosen.provider.key == "antigravity"
                and objective
                and config.mode != "advisory"
                and not resume
            ):
                _message(
                    window,
                    "An initial Antigravity task uses its documented headless interface, which cannot show native approvals.\n"
                    "Clear the task and start the native TUI, or select advisory mode.",
                )
                continue
            if (
                chosen.provider.key == "antigravity"
                and objective
                and config.mode == "advisory"
                and not resume
                and chosen.structured_output
            ):
                if not _enforcement_confirmation(window, chosen.provider.key, config):
                    continue
                if chosen.api_key_conflict and not _confirm(
                    window,
                    "A provider API-key environment variable is present and may select separately billed authentication.\n"
                    "JRX does not display its value. Continue with the CLI's current authentication selection?",
                ):
                    continue
                record = _task_record(
                    root,
                    config,
                    chosen.provider.key,
                    objective=objective,
                    session_id=None,
                    model=selected_models.get(chosen.provider.key),
                    version=chosen.version,
                    status="agent starting; task completion unknown",
                    task_context=task_context,
                    session_kind="antigravity_structured",
                )
                try:
                    save_task_record(record)
                    view = _StreamView(window, chosen.provider.key)
                    exit_code, _argv = stream_structured(
                        chosen.provider.key,
                        root,
                        render_initial_task_prompt(objective, task_context),
                        view,
                        model=selected_models.get(chosen.provider.key),
                        allow_api_key=chosen.api_key_conflict,
                        cancel_requested=view.poll_cancel,
                    )
                    fallback_code = _offer_native_approval_fallback(
                        window,
                        root,
                        chosen.provider.key,
                        view,
                        allow_api_key=chosen.api_key_conflict,
                    )
                    record["session"]["native_session_reference"] = view.session_id
                    record["session"]["session_kind"] = "antigravity_structured"
                    record["session"]["session_reference_status"] = (
                        "known from structured init event" if view.session_id else "unknown"
                    )
                    if view.model_id:
                        record["session"]["model"] = view.model_id
                        record["session"]["model_status"] = "confirmed from provider init event"
                    record["session"]["process_state"] = _structured_process_state(exit_code, view)
                    if view.requires_native_fallback:
                        record["session"]["native_approval_fallback_exit_code"] = fallback_code
                    record["context_delivery"] = (
                        "structured stream cancelled; checkpoint retained"
                        if view.cancelled
                        else "structured stream started; provider receipt unconfirmed"
                    )
                    save_task_record(record)
                    active_record = record
                except (OSError, WorkspaceError) as exc:
                    _message(window, f"Could not start Antigravity structured stream.\n{exc}")
                objective = ""
                task_context = {}
                continue
            active_record = _run_selected(
                window,
                root,
                config,
                chosen,
                model=selected_models.get(chosen.provider.key),
                resume=resume,
                active_record=selected_record,
                objective=objective,
                task_context=task_context,
            )
            statuses = list(detect_providers(root))
            if active_record and (not objective or active_record.get("objective") == objective):
                objective = ""
                task_context = {}
        elif key == ord("i"):
            chosen = statuses[active_index]
            if config.mode != "advisory":
                _message(
                    window,
                    "Integrated JSON streaming cannot present all providers' interactive native approvals.\n"
                    "Select advisory mode explicitly to use it, or press Enter for the native terminal with JRX hooks.",
                )
                continue
            task = objective or _prompt(window, "Task for one advisory structured run:")
            if not task:
                continue
            if chosen.status != "installed":
                _message(
                    window,
                    f"{chosen.provider.display_name} is {chosen.status}; structured run not started.",
                )
                continue
            if not chosen.structured_output:
                _message(
                    window,
                    f"{chosen.provider.display_name} has no verified structured output mode. Use Enter for its native terminal.",
                )
                continue
            if chosen.api_key_conflict:
                if not _confirm(
                    window,
                    "Provider API-key environment is present and may select separate billing. Continue?",
                ):
                    continue
            codex_sandbox_mode: str | None = None
            if chosen.provider.key == "codex":
                if not _confirm(
                    window,
                    "Codex will use its documented workspace-write sandbox for this one advisory run.\n"
                    "The model can write inside this selected workspace; other Codex sandbox boundaries remain active. Continue?",
                ):
                    continue
                codex_sandbox_mode = "workspace-write"
            record = _task_record(
                root,
                config,
                chosen.provider.key,
                objective=task,
                session_id=None,
                model=selected_models.get(chosen.provider.key),
                version=chosen.version,
                status="structured advisory stream starting",
                task_context=task_context,
                session_kind=(
                    "codex_exec" if chosen.provider.key == "codex" else "provider_structured"
                ),
            )
            try:
                if codex_sandbox_mode:
                    record["session"]["sandbox_mode"] = codex_sandbox_mode
                save_task_record(record)
                view = _StreamView(window, chosen.provider.key)
                exit_code, _argv = stream_structured(
                    chosen.provider.key,
                    root,
                    render_initial_task_prompt(task, task_context),
                    view,
                    model=selected_models.get(chosen.provider.key),
                    sandbox_mode=codex_sandbox_mode,
                    allow_api_key=chosen.api_key_conflict,
                    cancel_requested=view.poll_cancel,
                )
                fallback_code = _offer_native_approval_fallback(
                    window,
                    root,
                    chosen.provider.key,
                    view,
                    allow_api_key=chosen.api_key_conflict,
                )
                record["session"]["native_session_reference"] = view.session_id
                record["session"]["session_kind"] = (
                    "codex_exec" if chosen.provider.key == "codex" else "provider_structured"
                )
                record["session"]["session_reference_status"] = (
                    "known from structured event" if view.session_id else "unknown"
                )
                if view.model_id:
                    record["session"]["model"] = view.model_id
                    record["session"]["model_status"] = "confirmed from provider init event"
                record["session"]["process_state"] = _structured_process_state(exit_code, view)
                if view.requires_native_fallback:
                    record["session"]["native_approval_fallback_exit_code"] = fallback_code
                record["context_delivery"] = (
                    "structured stream cancelled; checkpoint retained"
                    if view.cancelled
                    else "structured stream started; provider receipt unconfirmed"
                )
                save_task_record(record)
                active_record = record
            except (OSError, WorkspaceError) as exc:
                _message(window, f"Structured provider process failed.\n{exc}")
            objective = ""
            task_context = {}


def run_workspace(workspace: Path | None = None, *, config_path: Path | None = None) -> int:
    root = workspace or Path.cwd()
    if os.name == "nt":
        print(
            "JRX terminal workspace currently requires a POSIX terminal (Linux or macOS).",
            file=sys.stderr,
        )
        return 2
    if curses is None:
        print("JRX terminal workspace requires Python curses on Linux or macOS.", file=sys.stderr)
        return 2
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(
            "jrx needs an interactive terminal for the workspace. Use jrx --help or run it from a TTY.",
            file=sys.stderr,
        )
        return 2
    try:
        curses.wrapper(_main, root, config_path)
    except KeyboardInterrupt:
        return 130
    except (curses.error, OSError, WorkspaceError) as exc:
        print(f"JRX terminal workspace could not start: {exc}", file=sys.stderr)
        return 2
    return 0
