"""Typer command-line interface for checks, wrappers, hooks, and calibration."""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

import typer

from .agent_cli import authority_app, intent_app
from .audit import AuditLog, AuditWriteError
from .broker_cli import app as broker_app
from .calibration import CalibrationStore
from .config import JEVConfig, Mode, ReflexConfig, load_config
from .context import RepositoryContextProvider, sanitized_child_env
from .enterprise import AccessDenied, ApprovalStore, action_binding, authorize, verified_identity
from .evaluator import DefaultEvaluator, DemoEvaluator, evaluate_context
from .formatters import (
    format_compare,
    format_human,
    format_json,
    format_stability,
    terminal_line,
)
from .harness_cli import app as harness_app
from .identity import resolve_approver
from .logging_config import log_structured
from .models import EvaluationContext, EvaluationResult, ProposedAction
from .policy import execution_allowed, host_guard_denied
from .sandbox import (
    build_sandbox_command,
    prepare_sandbox_egress,
    remove_sandbox_container,
    remove_sandbox_egress,
)
from .serialization import read_config_bytes, safe_yaml_load
from .session_limits import MAX_SESSION_OFFSET, SessionLimitError
from .signing import CosignSigner, Ed25519Signer, Signer, load_public_key, sign_file, verify_file
from .stability import StabilityRunner

_HOOK_MODULES = {
    "antigravity": "antigravity",
    "claude": "claude_code",
    "codex": "codex",
    "deepseek": "deepseek",
    "openrouter": "openrouter",
    "pi": "pi",
}
_HOOK_HELPERS = {
    "context_from_hook_payload",
    "ingest_post_tool_use",
    "is_post_tool_use",
    "read_hook_payload",
}


def __getattr__(name: str) -> Any:
    """Keep the existing adapter exports without loading them for other commands."""
    from importlib import import_module

    if name in _HOOK_HELPERS:
        module, attribute = "generic", name
    else:
        for kind, module in _HOOK_MODULES.items():
            if name == f"evaluate_{module}_hook":
                attribute = name
                break
            if name == f"{kind}_hook_error":
                attribute = "_hook_error" if kind in {"claude", "codex"} else name
                break
        else:
            raise AttributeError(name)
    return getattr(import_module(f".adapters.{module}", __package__), attribute)


app = typer.Typer(
    name="jev-reflex",
    help="Deterministic execution control for probabilistic coding agents.",
    no_args_is_help=False,
    invoke_without_command=True,
    add_completion=False,
)
benchmark_app = typer.Typer(name="benchmark", help="Run offline or live benchmark suites.")
audit_app = typer.Typer(name="audit", help="Audit log management and verification.")
policy_app = typer.Typer(name="policy", help="Policy file signing and verification.")
rollout_app = typer.Typer(
    name="rollout", help="Stage, promote, and roll back signed policy revisions."
)
approval_app = typer.Typer(name="approval", help="Request and grant action-bound approvals.")
dashboard_app = typer.Typer(name="dashboard", help="Serve a read-only operations dashboard.")
mcp_app = typer.Typer(name="mcp", help="Run a policy-enforcing MCP stdio gateway.")
session_app = typer.Typer(name="session", help="Inspect or stop an agent session.")
model_app = typer.Typer(name="model", help="Install and verify local ONNX models.")
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(broker_app, name="broker")
app.add_typer(model_app, name="model")
app.add_typer(audit_app, name="audit")
app.add_typer(policy_app, name="policy")
policy_app.add_typer(rollout_app, name="rollout")
app.add_typer(approval_app, name="approval")
app.add_typer(dashboard_app, name="dashboard")
app.add_typer(mcp_app, name="mcp")
app.add_typer(session_app, name="session")
app.add_typer(harness_app, name="harness")
app.add_typer(intent_app, name="intent")
app.add_typer(authority_app, name="authority")


@model_app.command("pull")
def model_pull(
    model_id: str | None = typer.Argument(None, help="Hugging Face model ID or alias."),
    config: Path | None = typer.Option(
        None, "--config", help="Read the model cache configuration."
    ),
) -> None:
    """Download and verify the configured Coba ONNX model."""
    from .model_cli import pull

    pull(model_id, config)


@model_app.command("status")
def model_status(
    json_output: bool = typer.Option(False, "--json", help="Emit a machine-readable report."),
    config: Path | None = typer.Option(
        None, "--config", help="Read the model cache configuration."
    ),
) -> None:
    """List installed local models and verify their manifests."""
    from .model_cli import status

    status(config, json_output)


@model_app.command("verify")
def model_verify(
    model_id: str | None = typer.Argument(None, help="Hugging Face model ID or alias."),
    config: Path | None = typer.Option(
        None, "--config", help="Read the model cache configuration."
    ),
) -> None:
    """Check each model artifact against its recorded SHA-256."""
    from .model_cli import verify

    verify(model_id, config)


@app.callback()
def _default_workspace(ctx: typer.Context) -> None:
    """Open the interactive workspace when jrx is run without a subcommand."""
    if ctx.invoked_subcommand is not None:
        return
    from .workspace.ui import run_workspace

    raise typer.Exit(run_workspace())


@app.command("doctor")
def workspace_doctor(
    workspace: Path = typer.Option(Path.cwd(), "--workspace", help="Workspace to inspect."),
    config: Path | None = typer.Option(None, "--config", help="Path to reflex.yaml."),
    provider: str | None = typer.Option(None, "--provider", help="Inspect one provider."),
    models: bool = typer.Option(False, "--models", help="Ask installed CLIs for model choices."),
    json_output: bool = typer.Option(False, "--json", help="Emit a machine-readable report."),
) -> None:
    """Show provider, authentication, hook, JEV, and policy status."""
    from .workspace.providers import PROVIDERS
    from .workspace.ui import doctor_report

    if provider is not None and provider not in {item.key for item in PROVIDERS}:
        raise typer.BadParameter("provider must be codex, claude, or antigravity")
    try:
        typer.echo(
            doctor_report(
                workspace,
                config_path=config,
                provider_filter=provider,
                include_models=models,
                json_output=json_output,
            )
        )
    except (OSError, ValueError, RuntimeError) as exc:
        typer.echo(f"JRX diagnostics failed: {exc}", err=True)
        raise typer.Exit(2) from None


@app.command("setup")
def workspace_setup(
    provider: str = typer.Option(..., "--provider", help="codex, claude, or antigravity."),
    workspace: Path = typer.Option(Path.cwd(), "--workspace", help="Workspace to configure."),
    apply: bool = typer.Option(False, "--apply", help="Apply the previewed change."),
    rollback: bool = typer.Option(False, "--rollback", help="Remove only JRX's hook entry."),
) -> None:
    """Preview, apply, or narrowly roll back a provider hook configuration."""
    from .workspace.hooks import apply_hook_change, preview_hook_change
    from .workspace.providers import PROVIDERS, provider_by_key

    if provider not in {item.key for item in PROVIDERS}:
        raise typer.BadParameter("provider must be codex, claude, or antigravity")
    if apply and rollback:
        raise typer.BadParameter("--apply and --rollback cannot be used together")
    spec = provider_by_key(provider)
    try:
        path, preview, changed = preview_hook_change(workspace, spec, rollback=rollback)
        typer.echo(f"Target: {path}")
        typer.echo(preview, nl=False)
        if not apply and not rollback:
            typer.echo("Preview only. Re-run with --apply to write this merged configuration.")
            return
        if not changed:
            typer.echo("No JRX hook change is needed.")
            return
        if not sys.stdin.isatty():
            typer.echo(
                "Applying hook configuration requires an interactive confirmation.", err=True
            )
            raise typer.Exit(2)
        if not typer.confirm(
            "Apply this targeted JRX hook change? Existing settings will be backed up and retained.",
            default=False,
        ):
            typer.echo("Cancelled; configuration was not changed.")
            return
        path, backup, changed = apply_hook_change(workspace, spec, rollback=rollback)
        typer.echo(f"{'Updated' if changed else 'Unchanged'} {path}")
        if backup:
            typer.echo(f"Original configuration backup: {backup}")
        typer.echo("Open the provider's native trust/settings screen and verify JRX is active.")
    except (OSError, ValueError, RuntimeError) as exc:
        typer.echo(f"JRX setup failed: {exc}", err=True)
        raise typer.Exit(2) from None


@app.command("init")
def init_policy(
    preset: str = typer.Option(
        ..., "--preset", help="dev-safe, strict-ci, enterprise, or production."
    ),
    output: Path = typer.Option(Path("reflex.yaml"), "--output", help="Policy file to write."),
    force: bool = typer.Option(False, "--force", help="Replace an existing policy file."),
) -> None:
    """Write a starter policy for the local semantic evaluator."""
    from .presets import write_preset

    path = output.expanduser()
    try:
        write_preset(preset, path, force=force)
    except FileExistsError:
        typer.echo(f"{path} already exists. Use --force to replace it.", err=True)
        raise typer.Exit(2) from None
    except (OSError, ValueError) as exc:
        typer.echo(f"Could not write policy. {exc}", err=True)
        raise typer.Exit(2) from None

    typer.echo(f"Wrote {path} using the {preset} preset.")
    typer.echo(
        'Install and pull the local evaluator with pip install "jev-reflex[local]" and jrx model pull.'
    )
    if preset == "enterprise":
        typer.echo(
            "Set your OIDC and role details and install the audit signing keys before starting the broker."
        )
    if preset == "production":
        typer.echo(
            "Fill the OIDC, checkout, and image placeholders, then run jrx policy lint --profile production."
        )


@benchmark_app.command("live")
def benchmark_live(
    runs: int = typer.Option(10, "--runs", min=1, max=1000),
    output: Path | None = typer.Option(None, "--output"),
    config: Path | None = typer.Option(None, "--config"),
    transport: str = typer.Option("broker", "--transport"),
    case: list[str] = typer.Option([], "--case", help="Restrict to named fixture; repeatable."),
) -> None:
    """Paid live evaluations; start with --runs 5 --case dependency-upgrade."""
    from .live_benchmark import run_benchmark

    if transport not in {"direct", "broker", "broker-tls"}:
        raise typer.BadParameter("transport must be direct, broker, or broker-tls")
    try:
        loaded = _load(config, None)
        loaded.jev.transport = cast(Literal["direct", "broker", "broker-tls"], transport)
        if output is not None and output.exists():
            raise ValueError("output already exists")
        report = run_benchmark(loaded, runs, cases=case or None)
        if output:
            # Exclusive creation avoids overwriting a previous benchmark artifact.
            with output.open("x", encoding="utf-8") as handle:
                json.dump(report, handle, indent=2, sort_keys=True)
        summary = report["summary"]
        typer.echo(f"Live benchmark: {report['total_cases']} cases, {runs} repetitions requested")
        typer.echo(
            f"Completed: {report['completed_evaluations']}; degraded: {summary['degraded_runs']}; API requests: {summary['api_request_count']}"
        )
        typer.echo("Labels are developer-defined expectations, not universal truth.")
        for name, metrics in summary["arms"].items():
            typer.echo(
                f"{name}: consistency={metrics['final_decision_consistency']:.1%}, "
                f"flip rate={metrics['decision_flip_rate']:.1%}, accuracy={metrics['accuracy']:.1%}, "
                f"false ALLOW={metrics['false_allow_rate']:.1%}, false HOLD={metrics['false_hold_rate']:.1%}"
            )
        typer.echo("Client latency ms: " + json.dumps(summary["latency_ms"]))
        typer.echo("JEV latency ms: " + json.dumps(summary["jev_latency_ms"]))
        for name, signals in summary["signals"].items():
            maximum = max((value["variance"] for value in signals.values()), default=0)
            typer.echo(f"{name}: maximum signal variance={maximum:.6f}")
            for signal_name, stats in signals.items():
                for label, crossing in stats["threshold_crossings"].items():
                    if crossing["crossings"]:
                        typer.echo(
                            f"  {signal_name} {label}: {crossing['crossings']} crossings, rate={crossing['rate']:.1%}"
                        )
        typer.echo("Usage metadata: " + json.dumps(summary["usage_metadata"]))
        if summary["api_request_count_unknown_runs"]:
            typer.echo(
                f"API request counts unknown for {summary['api_request_count_unknown_runs']} interrupted runs."
            )
        if summary["degraded_runs"]:
            typer.echo("Stopped on degraded evaluation; live benchmark is incomplete.", err=True)
            raise typer.Exit(2)
    except typer.Exit:
        # typer.Exit is a RuntimeError; keep the degraded-run message as the only error.
        raise
    except (OSError, RuntimeError, ValueError):
        typer.echo("Benchmark input/output error; check case names and output path.", err=True)
        raise typer.Exit(2) from None
    except Exception as exc:
        # Never surface a traceback or evaluator detail from a failed benchmark.
        typer.echo(f"Live benchmark failed ({type(exc).__name__}).", err=True)
        raise typer.Exit(2) from None


def _validated_mode(value: str | None) -> Mode | None:
    if value is None:
        return None
    if value not in {"advisory", "review", "enforce"}:
        raise typer.BadParameter("mode must be advisory, review, or enforce")
    return value  # type: ignore[return-value]


def _load(path: Path | None, mode: str | None, cwd: Path | None = None) -> ReflexConfig:
    try:
        return load_config(
            path,
            mode_override=_validated_mode(mode),
            scope=str(cwd.resolve()) if cwd is not None else None,
        )
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from None


def _provider(config: ReflexConfig, cwd: Path | None) -> RepositoryContextProvider:
    return RepositoryContextProvider(
        cwd=cwd,
        include_git_diff=config.context.include_git_diff,
        include_changed_files=config.context.include_changed_files,
        include_tests=config.context.include_tests,
        max_diff_chars=config.context.max_diff_chars,
        max_context_chars=config.context.max_context_chars,
    )


def _build_context(
    *,
    config: ReflexConfig,
    cwd: Path | None,
    task: str,
    command: str | None = None,
    argv: list[str] | None = None,
    stdin_diff: str = "",
    recent_context: str = "",
    external_content: str = "",
    test_results: str = "",
    changed_files: list[str] | None = None,
) -> EvaluationContext:
    action = ProposedAction(
        type="shell_command" if (command is not None or argv) else "observation",
        command=command,
        argv=argv or [],
    )
    return _provider(config, cwd).build(
        user_task=task,
        proposed_action=action,
        stdin_diff=stdin_diff,
        recent_context=recent_context,
        external_content=external_content,
        test_results=test_results,
        changed_files=changed_files,
    )


def _effective_config(
    config: ReflexConfig,
    *,
    samples: int | None = None,
    aggregation: str | None = None,
) -> ReflexConfig:
    if samples is not None and samples < 1:
        raise ValueError("samples must be at least 1")
    if aggregation is not None and aggregation not in {"median", "mean", "max"}:
        raise ValueError("aggregation must be median, mean, or max")
    if samples is None and aggregation is None:
        return config
    updates: dict[str, Any] = {}
    if samples is not None:
        updates["samples"] = samples
    if aggregation is not None:
        updates["aggregation"] = aggregation
    jev = JEVConfig.model_validate({**config.jev.model_dump(), **updates})
    return config.model_copy(update={"jev": jev})


def _evaluate(
    context: EvaluationContext,
    config: ReflexConfig,
    demo: bool,
    *,
    no_jev: bool = False,
    samples: int | None = None,
    aggregation: str | None = None,
    record_calibration: bool = True,
) -> EvaluationResult:
    if config.profile == "production" and (samples is not None or aggregation is not None):
        raise ValueError("Semantic sampling overrides are disabled by the production profile")
    effective = _effective_config(config, samples=samples, aggregation=aggregation)
    if no_jev:
        result = evaluate_context(context, config=effective, use_jev=False)
    else:
        evaluator = DemoEvaluator(effective) if demo else DefaultEvaluator(effective)
        result = evaluator.evaluate(context)
    if record_calibration and effective.calibration.enabled:
        try:
            CalibrationStore(
                Path(effective.calibration.path).expanduser()
                if effective.calibration.path
                else None
            ).record(result)
        except OSError:
            # The decision remains useful; do not print filesystem exception details.
            result = result.model_copy(
                update={"warnings": [*result.warnings, "Calibration event could not be stored."]}
            )
    return result


def _emit_result(result: EvaluationResult, *, json_output: bool) -> None:
    typer.echo(format_json(result) if json_output else format_human(result))


def _check_exit_code(result: EvaluationResult, config: ReflexConfig) -> int:
    if host_guard_denied(result):
        return 2
    return (
        0
        if execution_allowed(
            result.decision,
            mode=config.mode,
            degraded=result.degraded,
        )
        else 2
    )


def _read_diff(enabled: bool) -> str:
    if not enabled:
        return ""
    try:
        return sys.stdin.read()
    except OSError as exc:
        raise typer.BadParameter("could not read stdin diff") from exc


@approval_app.command("request")
def approval_request(
    command: str = typer.Option(..., "--command", help="Exact command to approve."),
    cwd: Path = typer.Option(..., "--cwd"),
    environment: str = typer.Option(..., "--environment"),
    config: Path | None = typer.Option(None, "--config"),
    hook_command: bool = typer.Option(
        False, "--hook-command", help="Bind the raw hook shell command."
    ),
) -> None:
    """Create a time-limited approval request for a command and repository state."""
    try:
        loaded = _load(config, None, cwd)
        if loaded.access is None:
            raise AccessDenied("Enterprise access is not configured")
        identity = verified_identity(loaded.access)
        argv = [command] if hook_command else shlex.split(command)
        if not argv or not environment.strip():
            raise AccessDenied("Command and environment are required")
        repository, binding = action_binding(loaded, cwd, argv, environment)
        authorize(identity, loaded.access, "execute", repository, environment)
        approval_id = ApprovalStore(loaded.access).request(
            identity, repository, environment, binding, command
        )
        typer.echo(approval_id)
    except (AccessDenied, OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
        typer.echo("Approval request denied.", err=True)
        raise typer.Exit(code=2) from None


@approval_app.command("grant")
def approval_grant(
    approval_id: str = typer.Argument(...),
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    """Record one verified, independent reviewer approval."""
    try:
        loaded = _load(config, None)
        if loaded.access is None:
            raise AccessDenied("Enterprise access is not configured")
        identity = verified_identity(loaded.access)
        count, required = ApprovalStore(loaded.access).grant(approval_id, identity)
        typer.echo(f"Approval granted by {identity.subject} ({count}/{required}).")
    except (AccessDenied, OSError, ValueError, sqlite3.Error):
        typer.echo("Approval grant denied.", err=True)
        raise typer.Exit(code=2) from None


@approval_app.command("pending")
def approval_pending(config: Path | None = typer.Option(None, "--config")) -> None:
    """Show pending requests visible to this verified reviewer."""
    try:
        loaded = _load(config, None)
        if loaded.access is None:
            raise AccessDenied("Enterprise access is not configured")
        identity = verified_identity(loaded.access)
        typer.echo(json.dumps(ApprovalStore(loaded.access).pending(identity), indent=2))
    except (AccessDenied, OSError, ValueError, sqlite3.Error):
        typer.echo("Pending approvals unavailable.", err=True)
        raise typer.Exit(code=2) from None


@app.command()
def check(
    transport: str | None = typer.Option(
        None, "--transport", help="direct or broker semantic backend."
    ),
    command: str | None = typer.Option(
        None, "--command", help="Proposed command to analyze; check never executes it."
    ),
    task: str = typer.Option("", "--task", help="The user's original task."),
    stdin_diff: bool = typer.Option(
        False, "--stdin-diff", help="Read a supplied Git diff from stdin."
    ),
    recent_context: str = typer.Option(
        "", "--recent-context", help="Optional recent agent context."
    ),
    external_content: str = typer.Option(
        "", "--external-content", help="Optional retrieved content."
    ),
    test_results: str = typer.Option("", "--test-results", help="Optional recent test results."),
    changed_file: list[str] = typer.Option(
        [], "--changed-file", help="Changed file path; repeatable."
    ),
    cwd: Path | None = typer.Option(None, "--cwd", help="Repository working directory."),
    config: Path | None = typer.Option(None, "--config", help="Path to reflex.yaml."),
    mode: str | None = typer.Option(
        None, "--mode", help="Override mode: advisory, review, or enforce."
    ),
    demo: bool = typer.Option(False, "--demo", help="Use deterministic offline demo judgments."),
    no_jev: bool = typer.Option(
        False, "--no-jev", help="Run deterministic checks only; do not call JEV."
    ),
    samples: int | None = typer.Option(
        None, "--samples", min=1, help="Repeat JEV evaluation this many times."
    ),
    aggregation: str | None = typer.Option(
        None, "--aggregation", help="Aggregate samples with median, mean, or max."
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit the stable JSON contract."),
    fail_closed_check: bool = typer.Option(
        False, "--fail-closed-check", help="Run fail-closed self-test against mock failure modes."
    ),
) -> None:
    """Analyze proposed commands without executing them."""

    if fail_closed_check:
        _run_fail_closed_check()
        return

    try:
        loaded = _load(config, mode, cwd)
        if transport is not None:
            if loaded.profile == "production":
                raise ValueError("Transport overrides are disabled by the production profile")
            if transport not in {"direct", "broker", "broker-tls"}:
                raise typer.BadParameter("transport must be direct, broker, or broker-tls")
            loaded.jev.transport = cast(Literal["direct", "broker", "broker-tls"], transport)
        context = _build_context(
            config=loaded,
            cwd=cwd,
            task=task,
            command=command,
            stdin_diff=_read_diff(stdin_diff),
            recent_context=recent_context,
            external_content=external_content,
            test_results=test_results,
            changed_files=changed_file or None,
        )
        result = _evaluate(
            context,
            loaded,
            demo,
            no_jev=no_jev,
            samples=samples,
            aggregation=aggregation,
        )
    except typer.BadParameter:
        raise
    except (OSError, RuntimeError, ValueError, sqlite3.Error, subprocess.SubprocessError):
        # Same contract as exec: corrupt session/approval state is an input error.
        if json_output:
            typer.echo(
                json.dumps({"decision": "REVIEW", "error": "invalid input or configuration"})
            )
        else:
            typer.echo("Configuration or input error. No action was executed.", err=True)
        raise typer.Exit(code=2) from None

    _emit_result(result, json_output=json_output)
    raise typer.Exit(code=_check_exit_code(result, loaded))


def _trailing_argv(ctx: typer.Context) -> list[str]:
    values = list(ctx.args)
    if values and values[0] == "--":
        values = values[1:]
    return values


def _resolve_exec_argv(command: str | None, trailing: list[str]) -> list[str]:
    if command and trailing:
        raise typer.BadParameter("use either --command or arguments after --, not both")
    if command:
        try:
            values = shlex.split(command)
        except ValueError as exc:
            raise typer.BadParameter("--command has invalid shell quoting") from exc
    else:
        values = trailing
    if not values:
        raise typer.BadParameter("provide a command after -- or with --command")
    return values


def _signal_command(process: subprocess.Popen[bytes], signum: int) -> None:
    """Signal an owned command's process group (POSIX) or the command itself."""
    if os.name != "posix":
        if signum == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()
        return
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass  # every member has exited and been reaped
    except PermissionError:
        # macOS refuses (EPERM) to signal a group whose remaining members have all exited
        # but are not yet reaped, such as an orphaned descendant awaiting launchd. Those
        # members cannot run again; a leader that is still running is signalled directly.
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(process.pid, signum)


def _stop_execution(process: subprocess.Popen[bytes]) -> None:
    """Reap an owned command and stop descendants even after its leader exits."""
    _signal_command(process, signal.SIGTERM)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    finally:
        _signal_command(process, signal.SIGKILL)
        process.wait()


def _execute_argv(argv: list[str], cwd: Path, config: ReflexConfig) -> int:
    """Run a command directly or in the configured isolated container."""
    if config.intent.enabled or config.authority.enabled:
        from .agent_controls import check_liveness

        check_liveness(config)
    sandbox_container: str | None = None
    command = argv
    child_env = sanitized_child_env(strict=config.strict_review_required)
    if config.sandbox.enabled:
        command, sandbox_container = build_sandbox_command(argv, cwd, config.sandbox)
    store = None
    session_id = ""
    if config.session.enabled:
        from .session_limits import SessionStore

        session_id = os.environ.get("JRX_SESSION_ID", "")
        store = SessionStore(config.session)
        store.reserve(session_id, semantic=0, tool_calls=0)
    egress_prepared = False
    process: subprocess.Popen[bytes] | None = None
    old_term = None
    if threading.current_thread() is threading.main_thread():
        old_term = signal.getsignal(signal.SIGTERM)

        def terminate_handler(signum: int, _frame: Any) -> None:
            raise SystemExit(128 + signum)

        signal.signal(signal.SIGTERM, terminate_handler)
    try:
        if sandbox_container is not None and config.sandbox.allowed_hosts:
            prepare_sandbox_egress(config.sandbox, sandbox_container)
            egress_prepared = True
        if store is not None:
            store.reserve(session_id, semantic=0, tool_calls=0)
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=child_env,
            shell=False,
            start_new_session=os.name == "posix",
        )
        timeout = config.sandbox.max_execution_seconds if config.sandbox.enabled else None
        if config.session.enabled:
            timeout = (
                min(timeout, config.session.max_execution_seconds)
                if timeout
                else config.session.max_execution_seconds
            )
        deadline = time.monotonic() + timeout if timeout is not None else None
        while True:
            try:
                return process.wait(timeout=0.1 if deadline is not None else None)
            except subprocess.TimeoutExpired:
                if deadline is not None and time.monotonic() >= deadline:
                    if config.sandbox.enabled:
                        assert timeout is not None
                        raise subprocess.TimeoutExpired(command, timeout) from None
                    raise SessionLimitError("session execution time limit reached") from None
                if store is not None:
                    store.reserve(session_id, semantic=0, tool_calls=0)
    finally:
        try:
            if process is not None:
                _stop_execution(process)
        finally:
            try:
                if sandbox_container is not None and process is not None:
                    remove_sandbox_container(config.sandbox, sandbox_container)
            finally:
                try:
                    if egress_prepared:
                        assert sandbox_container is not None
                        remove_sandbox_egress(config.sandbox, sandbox_container)
                finally:
                    if old_term is not None:
                        signal.signal(signal.SIGTERM, old_term)


@app.command(
    "exec",
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        # Everything after the first command word belongs to the wrapped command.
        "allow_interspersed_args": False,
    },
)
def exec_action(
    ctx: typer.Context,
    command: str | None = typer.Option(
        None, "--command", help="Command string parsed once with shlex."
    ),
    task: str = typer.Option("", "--task"),
    recent_context: str = typer.Option("", "--recent-context"),
    external_content: str = typer.Option("", "--external-content"),
    test_results: str = typer.Option("", "--test-results"),
    changed_file: list[str] = typer.Option([], "--changed-file"),
    cwd: Path | None = typer.Option(None, "--cwd"),
    config: Path | None = typer.Option(None, "--config"),
    mode: str | None = typer.Option(None, "--mode"),
    demo: bool = typer.Option(False, "--demo"),
    no_jev: bool = typer.Option(False, "--no-jev"),
    samples: int | None = typer.Option(None, "--samples", min=1),
    aggregation: str | None = typer.Option(None, "--aggregation"),
    json_output: bool = typer.Option(False, "--json"),
    approver: str | None = typer.Option(
        None, "--approver", help="Identity of human approver for REVIEW/HOLD override."
    ),
    justification: str | None = typer.Option(
        None, "--justification", help="Justification for human override."
    ),
    environment: str | None = typer.Option(None, "--environment"),
    approval_id: str | None = typer.Option(None, "--approval-id", envvar="JRX_APPROVAL_ID"),
    yes: bool = typer.Option(
        False, "-y", "--yes", help="Automatically confirm prompts without interactive input."
    ),
) -> None:
    """Evaluate and, when the configured mode permits it, execute one argv list."""

    try:
        argv = _resolve_exec_argv(command, _trailing_argv(ctx))
        loaded = _load(config, mode, cwd)
        if loaded.strict_review_required and (
            yes or approver is not None or argv[0].startswith("-")
        ):
            typer.echo(
                "Strict review rejects --yes, self-reported --approver labels, and unsupported runner flags.",
                err=True,
            )
            raise typer.Exit(code=2)
        if loaded.semantic_required and (demo or no_jev):
            typer.echo(
                "This policy requires live semantic evaluation. --demo and --no-jev are disabled.",
                err=True,
            )
            raise typer.Exit(code=2)
        enterprise_identity = None
        enterprise_binding = None
        if loaded.access is not None:
            if demo or no_jev or mode is not None or not environment:
                raise AccessDenied(
                    "Enterprise execution requires normal evaluation and an environment"
                )
            enterprise_identity = verified_identity(loaded.access)
            repository, enterprise_binding = action_binding(
                loaded, (cwd or Path.cwd()).resolve(), argv, environment
            )
            authorize(enterprise_identity, loaded.access, "execute", repository, environment)
        context = _build_context(
            config=loaded,
            cwd=cwd,
            task=task,
            argv=argv,
            recent_context=recent_context,
            external_content=external_content,
            test_results=test_results,
            changed_files=changed_file or None,
        )
        result = _evaluate(
            context,
            loaded,
            demo,
            no_jev=no_jev,
            samples=samples,
            aggregation=aggregation,
        )
    except typer.BadParameter:
        raise
    except (OSError, RuntimeError, ValueError, sqlite3.Error, subprocess.SubprocessError):
        typer.echo("Configuration, input, or command error. No action was executed.", err=True)
        raise typer.Exit(code=2) from None

    _emit_result(result, json_output=json_output)
    if "audit_unavailable" in result.triggered_rules:
        typer.echo("Execution blocked: required decision audit write failed.", err=True)
        raise typer.Exit(code=2)
    if host_guard_denied(result):
        typer.echo("Execution blocked by host agent controls.", err=True)
        raise typer.Exit(code=2)
    if result.degraded and loaded.mode != "advisory":
        typer.echo(
            "Execution blocked: semantic evaluation is unavailable or a required security dependency failed.",
            err=True,
        )
        raise typer.Exit(code=2)
    if loaded.access is not None:
        try:
            if verified_identity(loaded.access) != enterprise_identity:
                raise AccessDenied("Identity changed during evaluation")
        except AccessDenied:
            typer.echo("Verified identity expired or changed.", err=True)
            raise typer.Exit(code=2) from None
        if result.decision == "HOLD" and not loaded.policy.allow_hold_override:
            typer.echo("Execution blocked: HOLD override is disabled.", err=True)
            raise typer.Exit(code=2)
        if result.decision != "ALLOW" or result.degraded:
            if not approval_id:
                typer.echo("Execution requires a reviewed approval ID.", err=True)
                raise typer.Exit(code=2)
            try:
                assert (
                    enterprise_identity is not None
                    and enterprise_binding is not None
                    and environment is not None
                )
                _, current_binding = action_binding(
                    loaded, (cwd or Path.cwd()).resolve(), argv, environment
                )
                if current_binding != enterprise_binding:
                    raise AccessDenied("Repository state changed during evaluation")
                ApprovalStore(loaded.access).consume(
                    approval_id,
                    enterprise_identity,
                    current_binding,
                    config=loaded,
                    original_decision=result.decision,
                )
            except AuditWriteError as exc:
                typer.echo(f"Execution blocked: {exc}.", err=True)
                raise typer.Exit(code=2) from None
            except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
                typer.echo("Approval is invalid or incomplete.", err=True)
                raise typer.Exit(code=2) from None
        elif approval_id:
            typer.echo("Approval ID was supplied for an allowed action.", err=True)
            raise typer.Exit(code=2)
    elif not execution_allowed(
        result.decision,
        mode=loaded.mode,
        degraded=result.degraded,
    ):
        if loaded.strict_review_required:
            typer.echo(
                "Execution blocked: strict review requires enterprise access and a verified approval ID for exceptions.",
                err=True,
            )
            raise typer.Exit(code=2)
        # In enforce mode specifically, check policy.allow_hold_override
        if loaded.mode == "enforce" and result.decision == "HOLD":
            if not loaded.policy.allow_hold_override:
                typer.echo(
                    "Execution blocked: HOLD cannot be overridden in enforce mode "
                    "(policy.allow_hold_override is false).",
                    err=True,
                )
                raise typer.Exit(code=2)

        prompt_text = (
            f"Policy decision is {result.decision}. Override and execute?"
            if result.decision == "HOLD"
            else f"Policy decision is {result.decision}. Approve and execute?"
        )
        confirmed = yes
        if not confirmed:
            try:
                confirmed = typer.confirm(prompt_text, default=False)
            except (typer.Abort, EOFError, OSError):
                confirmed = False

        if not confirmed:
            typer.echo("Execution skipped by user.", err=True)
            raise typer.Exit(code=2)

        # Require approver identity
        approver_identity = resolve_approver(approver)
        if not approver_identity:
            typer.echo(
                "Human override refused: no approver identity available. "
                "Provide --approver, set $JRX_APPROVER, or run as a valid user.",
                err=True,
            )
            raise typer.Exit(code=2)

        if justification is not None:
            override_justification = justification
        elif yes:
            override_justification = ""
        else:
            try:
                override_justification = typer.prompt(
                    "Justification for override", default="", show_default=False
                )
            except (typer.Abort, EOFError, OSError):
                override_justification = ""

        # Log override via audit module
        try:
            audit_log = AuditLog(loaded)
            audit_log.write_human_override(
                identity=approver_identity,
                original_decision=result.decision,
                action_summary=result.action or " ".join(argv),
                justification=override_justification,
            )
        except Exception:
            if loaded.audit_required:
                typer.echo("Execution blocked: required override audit write failed.", err=True)
                raise typer.Exit(code=2) from None
            typer.echo("Warning: could not write override to audit log.", err=True)

        log_structured(
            level="WARNING",
            event="human_override",
            fields={
                "identity": approver_identity,
                "original_decision": result.decision,
                "action": result.action or " ".join(argv),
                "justification": override_justification,
            },
        )

    try:
        exit_code = _execute_argv(argv, _provider(loaded, cwd).working_directory, loaded)
    except SessionLimitError as exc:
        typer.echo(f"Execution stopped: {exc}", err=True)
        raise typer.Exit(code=124) from None
    except subprocess.TimeoutExpired:
        typer.echo("Execution stopped: sandbox time limit reached", err=True)
        raise typer.Exit(code=124) from None
    except (OSError, RuntimeError, ValueError):
        typer.echo("Command could not be started.", err=True)
        raise typer.Exit(code=127) from None
    raise typer.Exit(code=exit_code)


@app.command()
def compare(
    command: str | None = typer.Option(None, "--command"),
    task: str = typer.Option("", "--task"),
    stdin_diff: bool = typer.Option(False, "--stdin-diff"),
    recent_context: str = typer.Option("", "--recent-context"),
    external_content: str = typer.Option("", "--external-content"),
    test_results: str = typer.Option("", "--test-results"),
    changed_file: list[str] = typer.Option([], "--changed-file"),
    cwd: Path | None = typer.Option(None, "--cwd"),
    config: Path | None = typer.Option(None, "--config"),
    mode: str | None = typer.Option(None, "--mode"),
    demo: bool = typer.Option(False, "--demo", help="Use deterministic offline semantic signals."),
    samples: int | None = typer.Option(None, "--samples", min=1),
    aggregation: str | None = typer.Option(None, "--aggregation"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Compare deterministic-only control with deterministic policy plus JEV."""

    try:
        loaded = _load(config, mode)
        context = _build_context(
            config=loaded,
            cwd=cwd,
            task=task,
            command=command,
            stdin_diff=_read_diff(stdin_diff),
            recent_context=recent_context,
            external_content=external_content,
            test_results=test_results,
            changed_files=changed_file or None,
        )
        deterministic = _evaluate(
            context,
            loaded,
            demo=False,
            no_jev=True,
            record_calibration=False,
        )
        with_jev = _evaluate(
            context,
            loaded,
            demo=demo,
            samples=samples,
            aggregation=aggregation,
            record_calibration=False,
        )
    except typer.BadParameter:
        raise
    except (OSError, RuntimeError, ValueError):
        if json_output:
            typer.echo(
                json.dumps({"decision": "REVIEW", "error": "invalid input or configuration"})
            )
        else:
            typer.echo("Configuration or input error. No action was executed.", err=True)
        raise typer.Exit(code=2) from None

    typer.echo(format_compare(deterministic, with_jev, json_output=json_output))
    raise typer.Exit(code=_check_exit_code(with_jev, loaded))


@app.command()
def stability(
    command: str | None = typer.Option(None, "--command"),
    task: str = typer.Option("", "--task"),
    stdin_diff: bool = typer.Option(False, "--stdin-diff"),
    recent_context: str = typer.Option("", "--recent-context"),
    external_content: str = typer.Option("", "--external-content"),
    test_results: str = typer.Option("", "--test-results"),
    changed_file: list[str] = typer.Option([], "--changed-file"),
    cwd: Path | None = typer.Option(None, "--cwd"),
    config: Path | None = typer.Option(None, "--config"),
    mode: str | None = typer.Option(None, "--mode"),
    runs: int = typer.Option(100, "--runs", min=1, max=1_000),
    demo: bool = typer.Option(False, "--demo"),
    no_jev: bool = typer.Option(False, "--no-jev"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Measure observed final-decision stability over repeated identical evaluations."""

    try:
        loaded = _load(config, mode)
        context = _build_context(
            config=loaded,
            cwd=cwd,
            task=task,
            command=command,
            stdin_diff=_read_diff(stdin_diff),
            recent_context=recent_context,
            external_content=external_content,
            test_results=test_results,
            changed_files=changed_file or None,
        )
        single_config = _effective_config(loaded, samples=1)
        if no_jev:

            def no_jev_evaluation(value: EvaluationContext) -> EvaluationResult:
                return evaluate_context(value, config=single_config, use_jev=False)

            evaluate_once: Callable[[EvaluationContext], EvaluationResult] = no_jev_evaluation
        else:
            evaluator = DemoEvaluator(single_config) if demo else DefaultEvaluator(single_config)
            evaluate_once = evaluator.evaluate
        report = StabilityRunner(evaluate_once, single_config).run(context, runs)
    except typer.BadParameter:
        raise
    except (OSError, RuntimeError, ValueError):
        if json_output:
            typer.echo(json.dumps({"runs": runs, "error": "invalid input or configuration"}))
        else:
            typer.echo("Configuration or input error. No action was executed.", err=True)
        raise typer.Exit(code=2) from None

    typer.echo(format_stability(report, json_output=json_output))


def _benchmark_root() -> Path:
    source_tree = Path(__file__).resolve().parents[2] / "benchmarks" / "stability"
    if source_tree.exists():
        return source_tree
    target_data = (
        Path(__file__).resolve().parents[1] / "share" / "jev-reflex" / "benchmarks" / "stability"
    )
    if target_data.exists():
        return target_data
    installed_data = Path(sys.prefix) / "share" / "jev-reflex" / "benchmarks" / "stability"
    if installed_data.exists():
        return installed_data
    # Retain the useful checkout workflow when data files are unavailable.
    return Path.cwd() / "benchmarks" / "stability"


@benchmark_app.command("stability")
def benchmark_stability(
    path: Path | None = typer.Option(
        None, "--path", help="Directory containing benchmark JSON cases."
    ),
    runs: int = typer.Option(10, "--runs", min=1, max=1_000),
    config: Path | None = typer.Option(None, "--config"),
    mode: str | None = typer.Option(None, "--mode"),
    live: bool = typer.Option(False, "--live", help="Call JEV instead of the offline demo source."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Run the stability fixture suite; offline demo mode is the default."""

    try:
        loaded = _load(config, mode)
        cases_path = (path or _benchmark_root()).resolve(strict=False)
        files = sorted(cases_path.glob("*.json"))
        if not files:
            raise ValueError("no benchmark cases found")
        single_config = _effective_config(loaded, samples=1)
        fixture_config = single_config.model_copy(
            update={
                "context": single_config.context.model_copy(
                    update={"include_git_diff": False, "include_changed_files": False}
                )
            }
        )
        rows: list[dict[str, Any]] = []
        for case_path in files:
            with case_path.open("r", encoding="utf-8") as handle:
                case = json.load(handle)
            if not isinstance(case, dict) or not isinstance(case.get("command"), str):
                raise ValueError("benchmark case must contain a command")
            context = _build_context(
                config=fixture_config,
                cwd=None,
                task=str(case.get("task", "")),
                command=case["command"],
                external_content=str(case.get("external_content", "")),
                test_results=str(case.get("test_results", "")),
                changed_files=[str(item) for item in case.get("changed_files", [])],
            )
            evaluator = (
                DemoEvaluator(single_config) if not live else DefaultEvaluator(single_config)
            )
            report = StabilityRunner(evaluator.evaluate, single_config).run(context, runs)
            expected = str(case.get("expected", ""))
            rows.append(
                {
                    "case": str(case.get("name", case_path.stem)),
                    "expected": expected,
                    "dominant_decision": report.dominant_decision,
                    "consistency": report.decision_consistency,
                    "jev_signal_std": max(
                        (stats.std for stats in report.signals.values()), default=0.0
                    ),
                    "matches_expected": report.dominant_decision == expected,
                    "report": report.to_dict(),
                }
            )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        if json_output:
            typer.echo(json.dumps({"error": "invalid benchmark configuration or case"}))
        else:
            typer.echo("Benchmark configuration or case error.", err=True)
        raise typer.Exit(code=2) from None

    labeled_rows = [row for row in rows if row["expected"] in {"ALLOW", "REVIEW", "HOLD"}]
    correct = sum(row["matches_expected"] for row in labeled_rows)
    expected_non_allow = [row for row in labeled_rows if row["expected"] != "ALLOW"]
    expected_allow = [row for row in labeled_rows if row["expected"] == "ALLOW"]
    gold_metrics = {
        "decision_accuracy": correct / len(labeled_rows) if labeled_rows else None,
        "false_allow_rate": (
            sum(row["dominant_decision"] == "ALLOW" for row in expected_non_allow)
            / len(expected_non_allow)
            if expected_non_allow
            else None
        ),
        "false_hold_rate": (
            sum(row["dominant_decision"] == "HOLD" for row in expected_allow) / len(expected_allow)
            if expected_allow
            else None
        ),
    }
    if json_output:
        typer.echo(
            json.dumps(
                {"runs": runs, "offline": not live, "cases": rows, "gold_metrics": gold_metrics},
                indent=2,
                sort_keys=True,
            )
        )
        return
    lines = [
        "JEV Reflex stability benchmark",
        "",
        f"Runs per case: {runs}",
        f"Semantic source: {'live JEV' if live else 'offline demo'}",
        "",
        f"{'Case':<30} {'Consistency':>12} {'Dominant':>10} {'Expected':>10} {'max JEV std':>12}",
    ]
    for row in rows:
        lines.append(
            f"{row['case']:<30} {row['consistency']:>11.1%} {row['dominant_decision']:>10} "
            f"{row['expected']:>10} {row['jev_signal_std']:>12.3f}"
        )
    overall = sum(row["consistency"] for row in rows) / len(rows)
    variance = max((row["jev_signal_std"] for row in rows), default=0.0)
    lines.extend(
        [
            "",
            f"Overall final-decision consistency: {overall:.1%}",
            f"Maximum observed JEV signal std: {variance:.3f}",
            f"Gold-label decision accuracy: {_format_accuracy(gold_metrics['decision_accuracy'])}",
            "False-allow rate (expected non-ALLOW): "
            f"{_format_accuracy(gold_metrics['false_allow_rate'])}",
            f"False-hold rate (expected ALLOW): {_format_accuracy(gold_metrics['false_hold_rate'])}",
        ]
    )
    typer.echo("\n".join(lines))


def _antigravity_hook_workspace(payload: dict[str, Any]) -> Path:
    """Resolve the active Antigravity workspace from its documented hook event."""
    paths = payload.get("workspacePaths")
    if not isinstance(paths, Sequence) or isinstance(paths, str | bytes) or not paths:
        raise ValueError("Antigravity hook input is missing workspacePaths")

    roots: list[Path] = []
    for raw_path in paths:
        if not isinstance(raw_path, str) or not raw_path:
            raise ValueError("Antigravity hook input contains an invalid workspace path")
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            raise ValueError("Antigravity workspace paths must be absolute")
        root = candidate.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Antigravity workspace path is not a directory")
        if root not in roots:
            roots.append(root)

    tool_call = payload.get("toolCall")
    args = tool_call.get("args") if isinstance(tool_call, dict) else None
    action_paths: list[Path] = []
    if isinstance(payload.get("cwd"), str):
        action_paths.append(Path(payload["cwd"]))
    if isinstance(args, dict):
        for key in ("Cwd", "cwd", "TargetFile", "AbsolutePath", "path", "file_path"):
            value = args.get(key)
            if isinstance(value, str) and value:
                action_paths.append(Path(value))

    matched_roots: set[Path] = set()
    for action_path in action_paths:
        if not action_path.is_absolute():
            continue
        resolved = action_path.resolve(strict=False)
        matches = [root for root in roots if resolved == root or root in resolved.parents]
        if len(matches) > 1:
            raise ValueError("Antigravity action path matches multiple workspaces")
        matched_roots.update(matches)
    if len(matched_roots) > 1:
        raise ValueError("Antigravity action does not identify one workspace")
    if matched_roots:
        return matched_roots.pop()
    if len(roots) == 1:
        return roots[0]
    raise ValueError("Antigravity hook input does not identify the action workspace")


def _hook_start_directory(hook_cwd: object) -> Path:
    """Return the absolute directory a hook event names, else the process cwd."""
    if isinstance(hook_cwd, str) and hook_cwd:
        start = Path(hook_cwd)
        if not start.is_absolute():
            start = Path.cwd() / start
    else:
        start = Path.cwd()
    return start.resolve()


def _discover_hook_policy(start: Path) -> tuple[Path | None, Path]:
    """Find the nearest ``reflex.yaml`` from ``start`` up to the Git root.

    Returns the policy (or ``None``) and the directory where the search stopped.
    Hooks run in the agent's current directory, which moves when the agent
    changes directory, so a cwd-relative lookup is not a stable policy source.
    """
    for directory in (start, *start.parents):
        candidate = directory / "reflex.yaml"
        if candidate.is_file():
            return candidate, directory
        if (directory / ".git").exists():
            return None, directory
    return None, start


def _openrouter_permission_request(payload: dict[str, Any] | None) -> bool:
    return payload is not None and any(
        str(payload.get(name, "")).replace("_", "").replace("-", "").lower() == "permissionrequest"
        for name in ("hook_name", "hookName", "event", "event_name", "eventName")
    )


def _hook_error_output(kind: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    """Return the adapter's fail-safe deny response, in the parsed event's shape."""
    hooks = sys.modules[__name__]
    try:
        if kind == "openrouter" and payload is not None:
            from .adapters.openrouter import _event_name

            return cast(dict[str, Any], hooks.openrouter_hook_error(event=_event_name(payload)))
        return cast(dict[str, Any], getattr(hooks, f"{kind}_hook_error")())
    except Exception:
        # Last resort when an adapter cannot even be imported: still deny.
        reason = "JEV Reflex could not evaluate the hook input; action denied safely."
        if kind == "antigravity" or (
            kind == "openrouter" and _openrouter_permission_request(payload)
        ):
            return {"decision": "deny", "reason": reason}
        if kind == "openrouter":
            return {"block": reason}
        if kind == "pi":
            return {"block": True, "reason": reason}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }


def _run_hook(kind: str, config_path: Path | None, mode: str | None, demo: bool) -> None:
    hooks = sys.modules[__name__]
    post = False
    parsed: dict[str, Any] | None = None
    try:
        payload: dict[str, Any] = hooks.read_hook_payload()
        parsed = payload
        post = hooks.is_post_tool_use(payload)
        hook_cwd = payload.get("cwd")
        selected_config = config_path
        demo_defaults: Path | None = None
        if kind == "antigravity":
            workspace_root = _antigravity_hook_workspace(payload)
            hook_cwd = str(workspace_root)
            if selected_config is None:
                selected_config = workspace_root / "reflex.yaml"
                if not selected_config.is_file():
                    raise FileNotFoundError(
                        "workspace reflex.yaml is required for Antigravity hooks"
                    )
        elif selected_config is None:
            start = _hook_start_directory(hook_cwd)
            hook_cwd = str(start)
            selected_config, boundary = _discover_hook_policy(start)
            if selected_config is None:
                if not demo:
                    # Fail closed: built-in defaults are advisory and would allow
                    # every action whenever the agent leaves the policy directory.
                    raise FileNotFoundError(
                        "reflex.yaml is required between the hook directory and the Git root"
                    )
                demo_defaults = boundary / "reflex.yaml"
        if demo_defaults is not None:
            # Offline demo without a policy file: built-in defaults, enforced
            # unless --mode says otherwise. Never used by installed hooks.
            loaded = load_config(
                demo_defaults,
                mode_override=_validated_mode(mode) or "enforce",
                scope=hook_cwd,
                default_if_missing=True,
            )
        else:
            loaded = _load(
                selected_config,
                mode,
                Path(hook_cwd) if isinstance(hook_cwd, str) and hook_cwd else None,
            )
        if post:
            hooks.ingest_post_tool_use(payload, loaded)
            typer.echo("{}")
            return
        approval_id = os.environ.get("JRX_APPROVAL_ID", "")
        initial_binding = None
        if loaded.access is not None:
            if demo or mode is not None:
                raise AccessDenied("Enterprise hooks require normal evaluation")
            environment = os.environ.get("JRX_ENVIRONMENT", "")
            if not environment:
                raise AccessDenied("JRX_ENVIRONMENT is required")
            identity = verified_identity(loaded.access)
            hook_context = hooks.context_from_hook_payload(payload, config=loaded)
            authorize(identity, loaded.access, "execute", hook_context.repository_root, environment)
            command = hook_context.proposed_action.command
            if approval_id and command:
                _, initial_binding = action_binding(
                    loaded, Path(hook_context.working_directory), [command], environment
                )
        evaluate = getattr(hooks, f"evaluate_{_HOOK_MODULES[kind]}_hook")
        _result, output = evaluate(payload, config=loaded, demo=demo)
        if any(rule.startswith("agent_control:") for rule in _result.triggered_rules):
            raise AccessDenied("Host agent control denied this action")
        if host_guard_denied(_result):
            typer.echo(json.dumps(output, separators=(",", ":")))
            return
        if loaded.access is not None:
            if verified_identity(loaded.access) != identity:
                raise AccessDenied("Identity changed during evaluation")
            if _result.degraded and loaded.mode != "advisory":
                raise AccessDenied("Semantic evaluation is unavailable")
            if _result.decision == "HOLD" and not loaded.policy.allow_hold_override:
                raise AccessDenied("HOLD override is disabled")
            if _result.decision != "ALLOW" or _result.degraded:
                if initial_binding is None or not command:
                    raise AccessDenied("Hook action requires a matching approval")
                _, binding = action_binding(
                    loaded, Path(hook_context.working_directory), [command], environment
                )
                if binding != initial_binding:
                    raise AccessDenied("Action changed during evaluation")
                ApprovalStore(loaded.access).consume(
                    approval_id,
                    identity,
                    binding,
                    config=loaded,
                    original_decision=_result.decision,
                )
                if kind == "antigravity":
                    output = {"decision": "allow"}
                elif kind == "openrouter" and _openrouter_permission_request(payload):
                    output = {"decision": "allow"}
                else:
                    output = {}
        rendered = json.dumps(output, separators=(",", ":"))
    except Exception:
        if post:
            typer.echo("PostToolUse evidence could not be recorded.", err=True)
            raise typer.Exit(code=2) from None
        # Hook hosts differ in how they treat non-zero hook exits (Claude Code treats
        # an uncaught traceback's exit 1 as non-blocking). A valid deny response is the
        # most portable fail-safe for malformed input, configuration, or state.
        rendered = json.dumps(_hook_error_output(kind, parsed), separators=(",", ":"))
    typer.echo(rendered)


@app.command("post-tool-use")
def post_tool_use(
    config: Path | None = typer.Option(None, "--config", help="Path to reflex.yaml."),
) -> None:
    """Read a PostToolUse JSON event from stdin and record session credential evidence."""
    hooks = sys.modules[__name__]
    try:
        payload = hooks.read_hook_payload()
        hooks.ingest_post_tool_use(payload, _load(config, None))
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        typer.echo("PostToolUse evidence could not be recorded.", err=True)
        raise typer.Exit(code=2) from None


@app.command("codex-hook")
def codex_hook(
    config: Path | None = typer.Option(None, "--config", help="Path to reflex.yaml."),
    mode: str | None = typer.Option(None, "--mode", help="Override mode."),
    demo: bool = typer.Option(False, "--demo"),
) -> None:
    """Handle a Codex native PreToolUse event from JSON stdin."""

    _run_hook("codex", config, mode, demo)


@app.command("claude-code-hook")
def claude_code_hook(
    config: Path | None = typer.Option(None, "--config", help="Path to reflex.yaml."),
    mode: str | None = typer.Option(None, "--mode", help="Override mode."),
    demo: bool = typer.Option(False, "--demo"),
) -> None:
    """Handle a Claude Code native PreToolUse event from JSON stdin."""

    _run_hook("claude", config, mode, demo)


@app.command("antigravity-hook")
def antigravity_hook(
    config: Path | None = typer.Option(None, "--config", help="Path to reflex.yaml."),
    mode: str | None = typer.Option(None, "--mode", help="Override mode."),
    demo: bool = typer.Option(False, "--demo"),
) -> None:
    """Handle an Antigravity native PreToolUse event from JSON stdin."""

    _run_hook("antigravity", config, mode, demo)


@app.command("openrouter-hook")
def openrouter_hook(
    config: Path | None = typer.Option(None, "--config", help="Path to reflex.yaml."),
    mode: str | None = typer.Option(None, "--mode", help="Override mode."),
    demo: bool = typer.Option(False, "--demo"),
) -> None:
    """Handle an OpenRouter Agent SDK lifecycle event from JSON stdin."""

    _run_hook("openrouter", config, mode, demo)


@app.command("pi-hook")
def pi_hook(
    config: Path | None = typer.Option(None, "--config", help="Path to reflex.yaml."),
    mode: str | None = typer.Option(None, "--mode", help="Override mode."),
    demo: bool = typer.Option(False, "--demo"),
) -> None:
    """Handle a Pi tool_call extension event from JSON stdin."""

    _run_hook("pi", config, mode, demo)


@app.command("deepseek-hook")
def deepseek_hook(
    config: Path | None = typer.Option(None, "--config", help="Path to reflex.yaml."),
    mode: str | None = typer.Option(None, "--mode", help="Override mode."),
    demo: bool = typer.Option(False, "--demo"),
) -> None:
    """Handle a DeepSeek Harness Codex-bridge event from JSON stdin."""

    _run_hook("deepseek", config, mode, demo)


@app.command()
def feedback(
    decision_id: str = typer.Argument(..., help="Anonymous decision ID printed by check."),
    correct: bool = typer.Option(False, "--correct", help="Mark the decision correct."),
    incorrect: bool = typer.Option(False, "--incorrect", help="Mark the decision incorrect."),
    path: Path | None = typer.Option(None, "--path", help="Override the local events file."),
) -> None:
    """Attach optional feedback to one local calibration event."""

    if correct == incorrect:
        raise typer.BadParameter("choose exactly one of --correct or --incorrect")
    store = CalibrationStore(path)
    if not store.add_feedback(decision_id, "correct" if correct else "incorrect"):
        typer.echo("Decision ID was not found.", err=True)
        raise typer.Exit(code=1)
    typer.echo("Feedback recorded.")


@app.command()
def calibration(
    path: Path | None = typer.Option(None, "--path", help="Override the local events file."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Summarize locally labeled calibration events."""

    summary = CalibrationStore(path).summary()
    typer.echo(
        json.dumps(summary, indent=2, sort_keys=True)
        if json_output
        else _format_calibration(summary)
    )


def _format_calibration(summary: dict[str, Any]) -> str:
    lines = ["JEV Reflex calibration", "", f"Labeled cases: {summary['labeled_cases']}"]
    lines.append(f"Accuracy at >=0.90: {_format_accuracy(summary['accuracy_at_strong'])}")
    lines.append(f"Accuracy at 0.70–0.90: {_format_accuracy(summary['accuracy_in_review_band'])}")
    lines.append(f"False high-confidence count: {summary['false_high_confidence_count']}")
    if summary["per_signal_accuracy"]:
        lines.extend(["", "Per-signal accuracy:"])
        lines.extend(
            f"  {name}: {_format_accuracy(value)}"
            for name, value in summary["per_signal_accuracy"].items()
        )
    return "\n".join(lines)


def _format_accuracy(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2%}"


def _run_fail_closed_check() -> None:
    """Run fail-closed self-test against mock failure modes."""
    from .config import ReflexConfig
    from .evaluator import DefaultEvaluator, evaluate_context
    from .models import EvaluationContext, ProposedAction

    class MockGateway:
        """Mock gateway that simulates various failure modes."""

        def __init__(self, failure_mode: str = "none") -> None:
            self.failure_mode = failure_mode
            self.last_api_requests = 0

        def system_one(self, state: dict[str, Any], questions: dict[str, Any]) -> Any:
            self.last_api_requests = 1

            if self.failure_mode == "timeout":
                raise TimeoutError("Request timeout")

            elif self.failure_mode == "5xx_error":
                from .integrations.typesafe import TypeSafeIntegrationError

                raise TypeSafeIntegrationError("request_failed")

            elif self.failure_mode == "malformed_json":
                return "not a dict"

            elif self.failure_mode == "missing_keys":
                return {"answers": {}}

            elif self.failure_mode == "missing_answers":
                return {}

            elif self.failure_mode == "invalid_answer_type":
                return {
                    "answers": {
                        "destructive": {"type": "wrong_type", "noul": 0.1},
                    }
                }

            elif self.failure_mode == "invalid_risk_choice":
                answers = {
                    name: {"type": "noul", "noul": 0.1}
                    for name in [
                        "destructive",
                        "secret_exposure",
                        "scope_creep",
                        "security_sensitive",
                        "irreversible",
                        "needs_tests",
                        "prompt_injection",
                        "dependency_risk",
                        "wrong_repo",
                        "human_review",
                        "concurrency_sensitive",
                        "persistence_sensitive",
                        "backwards_compatibility",
                        "untrusted_input_path",
                        "fail_open",
                        "wrong_repo_semantic",
                        "suspicious_intent",
                        "external_side_effect_risk",
                    ]
                }
                answers["risk_level"] = {
                    "type": "choice",
                    "choice": "invalid_choice",
                    "confidence": 0.91,
                }
                answers["risk_score"] = {
                    "type": "score",
                    "score": 0.0,
                    "confidence": 0.91,
                }
                return {"answers": answers}

            elif self.failure_mode == "sdk_missing":
                from .integrations.typesafe import TypeSafeIntegrationError

                raise TypeSafeIntegrationError("sdk_missing")

            elif self.failure_mode == "missing_api_key":
                from .integrations.typesafe import TypeSafeIntegrationError

                raise TypeSafeIntegrationError("missing_api_key")

            elif self.failure_mode == "network_unreachable":
                raise OSError("Network unreachable")

            elif self.failure_mode == "401_unauthorized":
                from .integrations.typesafe import TypeSafeIntegrationError

                raise TypeSafeIntegrationError("request_failed")

            else:
                # Normal response
                answers = {
                    name: {"type": "noul", "noul": 0.1}
                    for name in [
                        "destructive",
                        "secret_exposure",
                        "scope_creep",
                        "security_sensitive",
                        "irreversible",
                        "needs_tests",
                        "prompt_injection",
                        "dependency_risk",
                        "wrong_repo",
                        "human_review",
                        "concurrency_sensitive",
                        "persistence_sensitive",
                        "backwards_compatibility",
                        "untrusted_input_path",
                        "fail_open",
                        "wrong_repo_semantic",
                        "suspicious_intent",
                        "external_side_effect_risk",
                    ]
                }
                answers["risk_level"] = {
                    "type": "choice",
                    "choice": "low",
                    "confidence": 0.91,
                }
                answers["risk_score"] = {
                    "type": "score",
                    "score": 0.0,
                    "confidence": 0.91,
                }
                return {"answers": answers}

    # Safe context that would pass hard rules
    safe_context = EvaluationContext(
        user_task="Run tests",
        repository="test-repo",
        repository_root="/tmp/test",
        working_directory="/tmp/test",
        proposed_action=ProposedAction(command="pytest tests/"),
        changed_files=[],
        git_diff="",
        test_results="",
        recent_context="",
        external_content="",
    )

    # TypeSafe API failure modes
    typesafe_failure_modes = [
        "timeout",
        "5xx_error",
        "malformed_json",
        "missing_keys",
        "missing_answers",
        "invalid_answer_type",
        "invalid_risk_choice",
        "sdk_missing",
        "missing_api_key",
        "network_unreachable",
        "401_unauthorized",
    ]

    # Broker failure modes
    broker_failure_modes = [
        "socket_not_exist",
        "connection_refused",
        "socket_hang",
    ]

    typer.echo("JEV Reflex Fail-Closed Self-Test")
    typer.echo("=" * 60)
    typer.echo("")

    # Test TypeSafe failures
    typer.echo("TypeSafe API Failure Modes:")
    typesafe_results = []

    for failure_mode in typesafe_failure_modes:
        row = {"mode": failure_mode, "advisory": "PASS", "review": "PASS", "enforce": "PASS"}

        for mode in ["advisory", "review", "enforce"]:
            config = ReflexConfig(mode=cast(Mode, mode))
            gateway = MockGateway(failure_mode=failure_mode)
            evaluator = DefaultEvaluator(config=config, gateway=gateway)

            try:
                result = evaluator.evaluate(safe_context)

                # Check fail-closed behavior
                if mode == "enforce":
                    if result.decision == "ALLOW" or not result.degraded:
                        row[mode] = "FAIL"
                elif mode == "review":
                    if result.decision == "ALLOW" or not result.degraded:
                        row[mode] = "FAIL"
                elif mode == "advisory":
                    if not result.degraded or len(result.warnings) == 0:
                        row[mode] = "FAIL"
            except Exception:
                row[mode] = "ERROR"

        typesafe_results.append(row)

    # Print TypeSafe results table
    typer.echo(f"{'Failure Mode':<25} {'Advisory':<10} {'Review':<10} {'Enforce':<10}")
    typer.echo("-" * 60)
    for row in typesafe_results:
        typer.echo(
            f"{row['mode']:<25} {row['advisory']:<10} {row['review']:<10} {row['enforce']:<10}"
        )

    typer.echo("")

    # Test Broker failures
    typer.echo("Broker Failure Modes:")
    broker_results = []

    for failure_mode in broker_failure_modes:
        row = {"mode": failure_mode, "advisory": "PASS", "review": "PASS", "enforce": "PASS"}

        for mode in ["advisory", "review", "enforce"]:
            config = ReflexConfig(
                mode=cast(Mode, mode),
                jev=JEVConfig(
                    transport="broker",
                    socket="/tmp/nonexistent.sock",
                    connect_timeout=1.0,
                    request_timeout=1.0,
                ),
            )

            try:
                result = evaluate_context(safe_context, config=config)

                # Check fail-closed behavior
                if mode == "enforce":
                    if result.decision == "ALLOW" or not result.degraded:
                        row[mode] = "FAIL"
                elif mode == "review":
                    if result.decision == "ALLOW" or not result.degraded:
                        row[mode] = "FAIL"
                elif mode == "advisory":
                    if not result.degraded or len(result.warnings) == 0:
                        row[mode] = "FAIL"
            except Exception:
                row[mode] = "ERROR"

        broker_results.append(row)

    # Print Broker results table
    typer.echo(f"{'Failure Mode':<25} {'Advisory':<10} {'Review':<10} {'Enforce':<10}")
    typer.echo("-" * 60)
    for row in broker_results:
        typer.echo(
            f"{row['mode']:<25} {row['advisory']:<10} {row['review']:<10} {row['enforce']:<10}"
        )

    typer.echo("")

    # Check overall results
    all_passed = all(
        row["advisory"] == "PASS" and row["review"] == "PASS" and row["enforce"] == "PASS"
        for row in typesafe_results + broker_results
    )

    if all_passed:
        typer.echo("✓ All fail-closed checks passed")
        raise typer.Exit(code=0)
    else:
        typer.echo("✗ Some fail-closed checks failed", err=True)
        raise typer.Exit(code=1)


@audit_app.command("verify")
def audit_verify(
    path: Path | None = typer.Option(None, "--path", help="Override the audit log path."),
    public_key: Path | None = typer.Option(
        None, "--public-key", help="Public key for decision signature verification."
    ),
) -> None:
    """Verify the audit log hash chain and decision signatures.

    Signatures are checked against --public-key or the configured
    signing.public_key_path; with signing.require_signature set, a missing key or an
    unsigned record fails verification.
    """

    try:
        config = load_config()
        if path is not None:
            config = config.model_copy(
                update={"audit": config.audit.model_copy(update={"path": str(path)})}
            )

        # Verify as a reader: the producer's private signing key is never loaded.
        audit_log = AuditLog.reader(config)
        public_key_path = public_key.expanduser() if public_key else None
        is_valid, message = audit_log.verify(public_key_path=public_key_path)
        typer.echo(message)
        if not is_valid:
            raise typer.Exit(code=1)
    except Exception as e:
        typer.echo(f"Error verifying audit log: {e}", err=True)
        raise typer.Exit(code=1) from None


@audit_app.command("report")
def audit_report(
    config: Path | None = typer.Option(
        None, "--config", help="Configuration for audit path and verification keys."
    ),
    path: Path | None = typer.Option(None, "--path", help="Audit log to report on."),
    public_key: Path | None = typer.Option(
        None, "--public-key", help="Verify every record against this pinned public key."
    ),
    since: str | None = typer.Option(
        None, "--since", help="Inclusive start date or ISO timestamp, in UTC by default."
    ),
    until: str | None = typer.Option(
        None, "--until", help="Inclusive end date or ISO timestamp, in UTC by default."
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit a machine-readable report."),
) -> None:
    """Summarize a verified audit snapshot without action text or identities."""
    from .audit_report import build_audit_report

    try:
        loaded = _load(config, None)
        report = build_audit_report(
            path or Path(loaded.audit.path), loaded, public_key=public_key, since=since, until=until
        )
    except (OSError, ValueError):
        typer.echo(
            "Audit report failed; check the log integrity, verification key, and date range.",
            err=True,
        )
        raise typer.Exit(code=2) from None
    if json_output:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        verified = report["verification"]
        typer.echo(
            f"Verified {verified['records_verified']} records; selected {report['records_selected']}."
        )
        typer.echo(
            "Signatures verified."
            if verified["signatures_verified"]
            else "Hash chain verified; signatures not checked."
        )
        typer.echo(
            "Decisions: "
            + ", ".join(f"{name}={count}" for name, count in report["decisions"].items())
        )
        typer.echo(
            f"Degraded evaluations: {report['degraded_evaluations']} (unknown in {report['legacy_unknown_degraded']} legacy records)"
        )
        typer.echo(f"Human overrides: {report['human_overrides']}")
        typer.echo(f"Policy versions: {len(report['policy_versions'])}")
        for name, count in report["triggered_checks"].items():
            typer.echo(f"Triggered check: {name} ({count})")


@audit_app.command("tail")
def audit_tail(
    n: int = typer.Option(10, "-n", "--number", help="Number of entries to show.", min=1),
    path: Path | None = typer.Option(None, "--path", help="Override the audit log path."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Show recent entries from the audit log."""

    try:
        config = load_config()
        if path is not None:
            config = config.model_copy(
                update={"audit": config.audit.model_copy(update={"path": str(path)})}
            )
        audit_log = AuditLog(config)
        entries = audit_log.tail(n)

        if json_output:
            typer.echo(json.dumps(entries, indent=2, sort_keys=True))
        else:
            if not entries:
                typer.echo("No audit log entries found.")
                return

            for entry in entries:
                # Audit fields can carry agent-controlled text; never let it drive the terminal.
                show = terminal_line
                typer.echo(f"Seq: {show(entry['seq'])}")
                typer.echo(
                    f"Timestamp: {show(entry.get('timestamp_utc') or entry.get('timestamp'))}"
                )
                if entry.get("event_type") == "human_override":
                    typer.echo("Event: human_override")
                    typer.echo(f"Approver: {show(entry.get('identity', 'unknown'))}")
                    typer.echo(
                        f"Original Decision: {show(entry.get('original_decision', 'unknown'))}"
                    )
                    typer.echo(f"Action: {show(entry.get('action_summary', ''))}")
                    justification = entry.get("justification", "")
                    typer.echo(
                        f"Justification: {show(justification) if justification else '(empty)'}"
                    )
                else:
                    typer.echo(f"Decision: {show(entry.get('policy_decision', ''))}")
                    typer.echo(f"Action: {show(entry.get('action_summary', ''))}")
                    if entry.get("hard_rule_findings"):
                        typer.echo("Hard rule findings:")
                        for finding in entry["hard_rule_findings"]:
                            typer.echo(
                                f"  - {show(finding['check'])}: {show(finding['reason_code'])} "
                                f"(triggered: {show(finding['triggered'])})"
                            )
                    if entry.get("jev_signals"):
                        typer.echo("JEV signals:")
                        for signal, value in entry["jev_signals"].items():
                            typer.echo(f"  - {show(signal)}: {value:.2f}")
                typer.echo(f"Policy version hash: {show(entry.get('policy_version_hash', ''))}")
                typer.echo(f"Entry hash: {show(entry.get('entry_hash', ''))}")
                typer.echo("---")
    except Exception as e:
        typer.echo(f"Error reading audit log: {terminal_line(e)}", err=True)
        raise typer.Exit(code=1) from None


@audit_app.command("overrides")
def audit_overrides(
    since: str | None = typer.Option(
        None, "--since", help="Filter overrides since DATE (YYYY-MM-DD or ISO 8601)."
    ),
    path: Path | None = typer.Option(None, "--path", help="Override the audit log path."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """List all human overrides for review."""

    try:
        config = load_config()
        if path is not None:
            config = config.model_copy(
                update={"audit": config.audit.model_copy(update={"path": str(path)})}
            )
        audit_log = AuditLog(config)

        since_dt = None
        if since is not None:
            try:
                clean = since.replace("Z", "+00:00")
                since_dt = datetime.fromisoformat(clean)
                if since_dt.tzinfo is None:
                    since_dt = since_dt.replace(tzinfo=UTC)
            except ValueError:
                typer.echo(
                    f"Invalid date format for --since: '{terminal_line(since)}'. "
                    "Use YYYY-MM-DD or ISO 8601.",
                    err=True,
                )
                raise typer.Exit(code=2) from None

        overrides = audit_log.get_overrides(since=since_dt)

        if json_output:
            typer.echo(json.dumps(overrides, indent=2, sort_keys=True))
        else:
            if not overrides:
                typer.echo("No human overrides found.")
                return

            for entry in overrides:
                show = terminal_line
                typer.echo(f"Seq: {show(entry['seq'])}")
                typer.echo(
                    f"Timestamp: {show(entry.get('timestamp_utc') or entry.get('timestamp'))}"
                )
                typer.echo(f"Approver: {show(entry.get('identity', 'unknown'))}")
                typer.echo(f"Original Decision: {show(entry.get('original_decision', 'unknown'))}")
                typer.echo(f"Action: {show(entry.get('action_summary', ''))}")
                justification = entry.get("justification", "")
                typer.echo(f"Justification: {show(justification) if justification else '(empty)'}")
                typer.echo("---")
    except typer.Exit:
        raise
    except Exception as e:
        typer.echo(f"Error reading audit log overrides: {terminal_line(e)}", err=True)
        raise typer.Exit(code=1) from None


def _parse_policy_file(raw: bytes) -> ReflexConfig:
    value = safe_yaml_load(raw.decode("utf-8"))
    return ReflexConfig.model_validate(value)


@policy_app.command("lint")
def policy_lint(
    config: Path = typer.Option(
        Path("reflex.yaml"), "-c", "--config", help="Candidate policy file to check offline."
    ),
    strict: bool = typer.Option(False, "--strict", help="Also fail on warnings."),
    profile: str = typer.Option("standard", "--profile", help="standard or production."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable diagnostics."),
) -> None:
    """Find policy mistakes without activating the policy or calling external services."""
    from .policy_lint import lint_policy
    from .redaction import redact_obj

    if profile not in {"standard", "production"}:
        raise typer.BadParameter("profile must be standard or production")
    report = redact_obj(
        lint_policy(config, profile=cast(Literal["standard", "production"], profile))
    )
    if json_output:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        typer.echo(f"Policy lint: {report['errors']} errors, {report['warnings']} warnings")
        for issue in report["issues"]:
            typer.echo(
                f"{issue['severity'].upper()} {issue['path'] or '<root>'}: {issue['message']} [{issue['code']}]"
            )
    if report["errors"] or (strict and report["warnings"]):
        raise typer.Exit(code=1)


@policy_app.command("simulate")
def policy_simulate(
    audit: Path = typer.Option(..., "--audit"),
    baseline: Path = typer.Option(..., "--baseline"),
    candidate: Path = typer.Option(..., "--candidate"),
    public_key: Path | None = typer.Option(
        None, "--public-key", help="Trusted audit verification key."
    ),
) -> None:
    """Replay verified audit decisions against a proposed policy without model calls."""
    from .policy_rollout import simulate

    try:
        report = simulate(
            audit,
            _parse_policy_file(read_config_bytes(baseline)),
            _parse_policy_file(read_config_bytes(candidate)),
            public_key=public_key,
        )
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    except Exception:
        # YAML, model and audit diagnostics can contain private input.
        typer.echo("Policy simulation failed; check the audit chain and input policies.", err=True)
        raise typer.Exit(code=2) from None


@policy_app.command("impact")
def policy_impact(
    audit: Path = typer.Option(..., "--audit"),
    baseline: Path = typer.Option(..., "--baseline"),
    candidate: Path = typer.Option(..., "--candidate"),
    public_key: Path | None = typer.Option(
        None, "--public-key", help="Trusted audit verification key."
    ),
    max_new_allows: int | None = typer.Option(None, "--max-new-allows", min=0),
    max_relaxations: int | None = typer.Option(
        None,
        "--max-relaxations",
        min=0,
        help=(
            "Limit new ALLOW and HOLD-to-REVIEW decisions combined. With any limit set, a "
            "candidate whose mode runs a decision class the baseline blocked also fails."
        ),
    ),
    github_output: Path | None = typer.Option(None, "--github-output"),
) -> None:
    """Preview a candidate policy using aggregate audit replay counts."""
    from .policy_impact import impact_report

    try:
        report = impact_report(audit, baseline, candidate, public_key=public_key)
    except Exception:
        # Policy values and private audit data can appear in diagnostics.
        typer.echo("Unassessed. Check policy syntax, replay support and audit integrity.")
        raise typer.Exit(2) from None

    typer.echo(report.markdown())
    if not report.replayed:
        typer.echo("\nUnassessed. No matching decisions could be replayed.")
        raise typer.Exit(2)
    if github_output is not None:
        try:
            with github_output.open("a", encoding="utf-8") as stream:
                stream.write(f"counts={report.summary()}\n")
        except OSError:
            typer.echo("Could not write the GitHub output file.", err=True)
            raise typer.Exit(2) from None
    if max_new_allows is not None and report.new_allows > max_new_allows:
        typer.echo(f"\nNew ALLOW decisions exceed the limit of {max_new_allows}.")
        raise typer.Exit(1)
    if max_relaxations is not None and report.relaxations > max_relaxations:
        typer.echo(f"\nPolicy relaxations exceed the limit of {max_relaxations}.")
        raise typer.Exit(1)
    if (max_new_allows is not None or max_relaxations is not None) and (
        report.enforcement_relaxations
    ):
        typer.echo("\nThe candidate's mode relaxes enforcement, which no limit allows.")
        raise typer.Exit(1)


def _rollout_store(bootstrap: Path):
    from .config import load_bootstrap_config
    from .policy_rollout import RolloutStore

    settings = load_bootstrap_config(bootstrap)
    if not settings.rollout_state_path:
        raise ValueError("bootstrap rollout_state_path is required")
    return settings, RolloutStore(Path(settings.rollout_state_path), settings)


@rollout_app.command("stage")
def policy_rollout_stage(
    bootstrap: Path = typer.Option(..., "--bootstrap"),
    baseline: Path = typer.Option(..., "--baseline"),
    audit: Path = typer.Option(..., "--audit"),
    public_key: Path | None = typer.Option(
        None, "--public-key", help="Trusted audit verification key."
    ),
    max_new_allows: int = typer.Option(
        0,
        "--max-new-allows",
        min=0,
        help=(
            "Limit replayed decisions the candidate newly lets execute: any change to ALLOW, "
            "plus decisions the baseline's mode blocked and the candidate's mode runs (for "
            "example HOLD to REVIEW under enforce, or any HOLD under advisory). A candidate "
            "whose mode runs a decision class the baseline blocked is always rejected."
        ),
    ),
) -> None:
    """Fetch a signed remote candidate and stage it after an offline replay."""
    from .config import parse_policy_bytes, verify_policy_signature
    from .policy_rollout import SignedPolicy, policy_hash, simulate
    from .policy_source import PolicyFetcher

    try:
        settings, store = _rollout_store(bootstrap)
        if settings.policy_source.type is None:
            raise ValueError("a signed policy source is required")
        baseline_bytes = read_config_bytes(baseline)
        baseline_signature = None
        if settings.require_signature:
            # Store exactly the bytes and signature verified here, so every
            # later read can verify the snapshot again.
            baseline_signature = read_config_bytes(baseline.with_suffix(baseline.suffix + ".sig"))
            verify_policy_signature(baseline_bytes, baseline_signature, settings)
        active = parse_policy_bytes(baseline_bytes)
        baseline_snapshot: ReflexConfig | SignedPolicy = (
            active
            if baseline_signature is None
            else SignedPolicy(baseline_bytes, baseline_signature, "bootstrap")
        )
        current = store.status()
        if current["active_hash"] and current["active_hash"] != policy_hash(active):
            raise ValueError("baseline policy differs from active rollout policy")
        fetched = PolicyFetcher(settings.policy_source).fetch_signed()
        candidate = parse_policy_bytes(fetched.raw)
        report = simulate(audit, active, candidate, public_key=public_key)
        if report["replayed"] == 0 or report["newly_executable"] > max_new_allows:
            raise ValueError("simulation gate failed")
        if report["enforcement_relaxations"]:
            # A weaker mode lets a whole decision class run, which no replay count bounds.
            raise ValueError("candidate relaxes enforcement")
        store.stage(
            baseline_snapshot, SignedPolicy(fetched.raw, fetched.signature, "policy_source")
        )
        typer.echo(json.dumps({"status": store.status(), "simulation": report}, indent=2))
    except Exception as exc:
        typer.echo(f"Policy stage failed: {type(exc).__name__}.", err=True)
        raise typer.Exit(code=2) from None


@dashboard_app.command("serve")
def dashboard_serve(
    config: Path = typer.Option(..., "--config"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port", min=1, max=65535),
) -> None:
    """Serve authorized team status on a loopback address."""
    from .dashboard import load_dashboard_config, serve

    try:
        settings = load_dashboard_config(config)
        serve(settings, host, port)
    except (OSError, ValueError) as exc:
        typer.echo(f"Dashboard failed: {exc}", err=True)
        raise typer.Exit(code=2) from None


@mcp_app.command(
    "serve", context_settings={"allow_extra_args": True, "ignore_unknown_options": True}
)
def mcp_serve(
    ctx: typer.Context,
    server: str = typer.Option(..., "--server", help="Trusted upstream server identifier."),
    config: Path | None = typer.Option(None, "--config"),
    session_id: str | None = typer.Option(None, "--session-id"),
    approval_id: str | None = typer.Option(
        None, "--approval-id", help="Host-provided approval ID for a tool call retry."
    ),
) -> None:
    """Proxy an MCP stdio server, enforcing policy before tools/call."""
    from .mcp_gateway import MCPGateway

    try:
        command = _trailing_argv(ctx)
        loaded = _load(config, None)
        if loaded.mode == "advisory":
            raise ValueError("MCP gateway requires review or enforce mode")
        gateway = MCPGateway(
            loaded, server, command, session_id=session_id, approval_id=approval_id
        )
        raise typer.Exit(code=gateway.run())
    except typer.Exit:
        raise
    except (OSError, ValueError):
        typer.echo("MCP gateway configuration or upstream error.", err=True)
        raise typer.Exit(code=2) from None


def _admin_session_store(config: Path | None):
    from .session_limits import SessionStore

    loaded = _load(config, None)
    if not loaded.session.enabled:
        raise ValueError("session limits are disabled")
    if loaded.access is not None:
        identity = verified_identity(loaded.access)
        authorize(identity, loaded.access, "admin", "*", loaded.access.environment)
    return SessionStore(loaded.session)


@session_app.command("list")
def session_list(
    config: Path | None = typer.Option(None, "--config"),
    state: str | None = typer.Option(
        None, "--state", help="Filter active, stopped, expired, or exhausted sessions."
    ),
    limit: int = typer.Option(50, "--limit", min=1, max=500),
    offset: int = typer.Option(0, "--offset", min=0, max=MAX_SESSION_OFFSET),
    json_output: bool = typer.Option(False, "--json", help="Emit session details as JSON."),
) -> None:
    """List sessions and remaining budgets using administrator authorization."""
    try:
        sessions = _admin_session_store(config).list_sessions(
            state=state, limit=limit, offset=offset
        )
    except (OSError, ValueError, sqlite3.Error):
        typer.echo(
            "Session overview unavailable; check configuration and administrator access.", err=True
        )
        raise typer.Exit(code=2) from None
    if json_output:
        typer.echo(json.dumps({"sessions": sessions, "limit": limit, "offset": offset}, indent=2))
    elif not sessions:
        typer.echo("No sessions match this page.")
    else:
        typer.echo(
            f"{'SESSION':<28} {'STATE':<10} {'CALLS LEFT':>10} {'EVALS LEFT':>10} {'USD LEFT':>10}"
        )
        for session in sessions:
            remaining = cast(dict[str, Any], session["remaining"])
            typer.echo(
                f"{session['session_id']:<28} {session['state']:<10} {remaining['tool_calls']:>10} {remaining['semantic_evaluations']:>10} {remaining['semantic_spend_usd']:>10.4f}"
            )
        typer.echo("USD figures are reserved budget estimates, not provider billing.")


@session_app.command("status")
def session_status(
    session_id: str = typer.Argument(...), config: Path | None = typer.Option(None, "--config")
) -> None:
    """Show reserved budget and stop state for one session."""
    try:
        typer.echo(json.dumps(_admin_session_store(config).status(session_id), indent=2))
    except (OSError, ValueError, sqlite3.Error):
        typer.echo("Session status unavailable.", err=True)
        raise typer.Exit(code=2) from None


@session_app.command("stop")
def session_stop(
    session_id: str = typer.Argument(...), config: Path | None = typer.Option(None, "--config")
) -> None:
    """Stop a session before its next policy or execution boundary."""
    try:
        store = _admin_session_store(config)
        store.stop(session_id)
        typer.echo(json.dumps(store.status(session_id), indent=2))
    except (OSError, ValueError, sqlite3.Error):
        typer.echo("Session stop failed.", err=True)
        raise typer.Exit(code=2) from None


@rollout_app.command("promote")
def policy_rollout_promote(
    percent: int = typer.Option(..., "--percent", min=1, max=100),
    bootstrap: Path = typer.Option(..., "--bootstrap"),
) -> None:
    """Activate a stable percentage of repositories or fully promote a candidate."""
    try:
        _, store = _rollout_store(bootstrap)
        store.promote(percent)
        typer.echo(json.dumps(store.status(), indent=2))
    except (OSError, ValueError):
        typer.echo("Policy promotion failed.", err=True)
        raise typer.Exit(code=2) from None


@rollout_app.command("rollback")
def policy_rollout_rollback(bootstrap: Path = typer.Option(..., "--bootstrap")) -> None:
    """Restore the active policy and clear a staged candidate."""
    try:
        _, store = _rollout_store(bootstrap)
        store.rollback()
        typer.echo(json.dumps(store.status(), indent=2))
    except (OSError, ValueError):
        typer.echo("Policy rollback failed.", err=True)
        raise typer.Exit(code=2) from None


@rollout_app.command("status")
def policy_rollout_status(bootstrap: Path = typer.Option(..., "--bootstrap")) -> None:
    """Show active, candidate, and previous policy revisions."""
    try:
        _, store = _rollout_store(bootstrap)
        typer.echo(json.dumps(store.status(), indent=2))
    except (OSError, ValueError):
        typer.echo("Policy rollout status unavailable.", err=True)
        raise typer.Exit(code=2) from None


@policy_app.command("keygen")
def policy_keygen(
    output_dir: Path = typer.Option(..., "--output-dir", help="Directory for the signing keypair."),
) -> None:
    """Generate an Ed25519 policy signing keypair."""
    directory = output_dir.expanduser()
    private_path = directory / "policy_signing.key"
    public_path = directory / "policy_signing.pub"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if private_path.exists() or public_path.exists():
            raise FileExistsError("Policy signing keypair already exists")
        signer = Ed25519Signer()
        descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as private_file:
            private_file.write(signer.get_private_key_pem())
        with public_path.open("x", encoding="utf-8") as public_file:
            public_file.write(signer.get_public_key_pem())
        typer.echo(f"Private key written to: {private_path}")
        typer.echo(f"Public key written to: {public_path}")
    except Exception as exc:
        typer.echo(f"Error generating policy keypair: {exc}", err=True)
        raise typer.Exit(code=1) from None


@policy_app.command("verify")
def policy_verify(
    config_path: Path = typer.Argument(..., help="Path to the signed policy file."),
    public_key: Path = typer.Option(..., "--public-key", help="Path to the public key."),
    signature: Path | None = typer.Option(None, "--signature", help="Path to the signature file."),
    signer_type: str = typer.Option("ed25519", "--signer-type", help="ed25519 or cosign."),
) -> None:
    """Verify a policy signature against a pinned public key."""
    try:
        signer: Signer
        if signer_type == "ed25519":
            signer = Ed25519Signer()
        elif signer_type == "cosign":
            signer = CosignSigner()
        else:
            raise typer.BadParameter("signer_type must be ed25519 or cosign")
        config_file = config_path.expanduser()
        signature_file = (
            signature.expanduser()
            if signature
            else config_file.with_suffix(config_file.suffix + ".sig")
        )
        key = load_public_key(public_key.expanduser())
        if not verify_file(config_file, signature_file, key, signer):
            typer.echo("Policy signature verification failed.", err=True)
            raise typer.Exit(code=1)
        typer.echo("Policy signature verified.")
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"Error verifying policy: {exc}", err=True)
        raise typer.Exit(code=1) from None


@policy_app.command("sign")
def policy_sign(
    config_path: Path = typer.Argument(..., help="Path to reflex.yaml to sign."),
    key: Path = typer.Option(None, "--key", help="Path to private key file."),
    signer_type: str = typer.Option(
        "ed25519", "--signer-type", help="Signer type: ed25519 or cosign."
    ),
    output: Path | None = typer.Option(None, "--output", help="Output path for signature file."),
) -> None:
    """Sign a policy configuration file."""

    try:
        signer: Signer
        if signer_type not in {"ed25519", "cosign"}:
            raise typer.BadParameter("signer_type must be ed25519 or cosign")
        if key is None:
            # Generate a new keypair if no key is provided
            if signer_type == "ed25519":
                signer = Ed25519Signer()
                typer.echo("Generated new Ed25519 keypair")
                typer.echo(f"Public key (PEM):\n{signer.get_public_key_pem()}")
                typer.echo(f"Private key (PEM):\n{signer.get_private_key_pem()}")
                typer.echo("")
                typer.echo("Save the private key securely and use the public key for verification.")
                typer.echo("Example bootstrap.yaml:")
                typer.echo("  require_signature: true")
                typer.echo("  public_key_path: /path/to/public_key.pem")
                typer.echo("  signer_type: ed25519")
            else:
                raise typer.BadParameter("key is required for cosign signer")
        else:
            # Load existing key
            key_path = Path(key).expanduser()
            if signer_type == "ed25519":
                signer = Ed25519Signer(private_key_path=key_path)
            elif signer_type == "cosign":
                signer = CosignSigner(private_key_path=key_path)

        config_file = Path(config_path).expanduser()
        if not config_file.exists():
            raise typer.BadParameter(f"Config file not found: {config_file}")

        signature_path = sign_file(config_file, signer, output)
        typer.echo(f"Signature written to: {signature_path}")
    except Exception as e:
        typer.echo(f"Error signing policy: {e}", err=True)
        raise typer.Exit(code=1) from None


def _echo_trust(report: dict[str, Any]) -> None:
    def where(item: dict[str, Any] | None) -> str:
        if item is None:
            return "not used"
        owner = "operator-controlled" if item["operator_controlled"] else "writable by you"
        missing = "" if item["exists"] else ", missing"
        return f"{terminal_line(item['path'])} ({owner}{missing})"

    evaluator = report["evaluator"]
    privileged = " (privileged: nothing is protected)" if evaluator["privileged"] else ""
    typer.echo(f"Evaluating user: uid {evaluator['uid']}{privileged}")
    bootstrap = report["bootstrap"]
    if bootstrap["path"] is None:
        typer.echo("Bootstrap: none (signatures not required)")
    else:
        owner = "operator-controlled" if bootstrap["operator_controlled"] else "writable by you"
        typer.echo(f"Bootstrap: {terminal_line(bootstrap['path'])} ({owner})")
    required = "required" if report["require_signature"] else "not required"
    typer.echo(f"Policy signature: {required}; public key: {where(report['public_key'])}")
    typer.echo(f"Policy file: {where(report['policy'])}")
    typer.echo(f"Rollout state: {where(report['rollout_state'])}")
    protected = report["policy_protected_from_evaluating_user"]
    typer.echo(
        "Effective policy protected from the evaluating user: " + ("yes" if protected else "no")
    )
    for issue in report["issues"]:
        typer.echo(f"Evaluation will refuse: {terminal_line(issue)}")


@policy_app.command("status")
def policy_status(
    config: Path | None = typer.Option(
        None, "--config", help="Policy file to assess (default: ./reflex.yaml)."
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit the trust report as JSON."),
) -> None:
    """Show the configured central policy source and which policy inputs are trusted."""
    from .config import load_bootstrap_config, trust_report

    try:
        bootstrap = load_bootstrap_config()
        report = trust_report(config)
    except (OSError, ValueError) as exc:
        typer.echo(f"Policy status unavailable: {terminal_line(exc)}", err=True)
        raise typer.Exit(code=2) from None
    if json_output:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
        return
    _echo_trust(report)

    if bootstrap.policy_source.type is None:
        typer.echo("Policy source: local (reflex.yaml)")
        typer.echo("No central policy configured")
        return

    typer.echo(f"Policy source type: {bootstrap.policy_source.type}")
    typer.echo(f"Policy source URI: {bootstrap.policy_source.uri}")
    if bootstrap.policy_source.ref:
        typer.echo(f"Policy source ref: {bootstrap.policy_source.ref}")
    # Runtime never polls or merges the central source; only staging reads it.
    typer.echo(
        "Runtime policy: reflex.yaml, replaced by the active or canary revision when "
        "rollout state exists. The central source is read only by `jrx policy rollout stage`."
    )
    if bootstrap.rollout_state_path:
        typer.echo(f"Rollout state: {bootstrap.rollout_state_path}")
        typer.echo("Run `jrx policy rollout status --bootstrap <file>` for active revisions.")
    else:
        typer.echo("Rollout state: not configured; the central policy is not applied.")


@policy_app.command("test")
def policy_test(
    fixtures: Path | None = typer.Option(
        None, "--fixtures", help="Directory containing golden policy fixtures."
    ),
    config: Path | None = typer.Option(
        None, "-c", "--config", help="Path to reflex.yaml configuration to test."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format."),
) -> None:
    """Run golden fixture regression suite against a policy configuration."""
    from .golden_runner import run_fixtures

    config_path = config
    if config_path is None:
        if Path("reflex.yaml").exists():
            config_path = Path("reflex.yaml")
        elif Path("reflex.example.yaml").exists():
            config_path = Path("reflex.example.yaml")

    try:
        report = run_fixtures(fixtures_dir=fixtures, config_path=config_path)
    except Exception as e:
        typer.echo(f"Error running policy fixtures: {e}", err=True)
        raise typer.Exit(code=1) from None

    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        typer.echo(report.summary_table())

    if not report.all_passed:
        raise typer.Exit(code=1)


if __name__ == "__main__":  # pragma: no cover
    app()
