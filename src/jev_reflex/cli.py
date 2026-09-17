"""Typer command-line interface for checks, wrappers, hooks, and calibration."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import typer

from .adapters.antigravity import antigravity_hook_error, evaluate_antigravity_hook
from .adapters.claude_code import (
    _hook_error as claude_hook_error,
)
from .adapters.claude_code import (
    evaluate_claude_code_hook,
)
from .adapters.codex import _hook_error as codex_hook_error
from .adapters.codex import evaluate_codex_hook
from .adapters.deepseek import deepseek_hook_error, evaluate_deepseek_hook
from .adapters.generic import read_hook_payload
from .adapters.openrouter import evaluate_openrouter_hook, openrouter_hook_error
from .adapters.pi import evaluate_pi_hook, pi_hook_error
from .broker_cli import app as broker_app
from .calibration import CalibrationStore
from .config import JEVConfig, Mode, ReflexConfig, load_config
from .context import RepositoryContextProvider
from .evaluator import DefaultEvaluator, DemoEvaluator, evaluate_context
from .formatters import format_compare, format_human, format_json, format_stability
from .models import EvaluationContext, EvaluationResult, ProposedAction
from .policy import execution_allowed
from .stability import StabilityRunner

app = typer.Typer(
    name="jev-reflex",
    help="Deterministic execution control for probabilistic coding agents.",
    no_args_is_help=True,
    add_completion=False,
)
benchmark_app = typer.Typer(name="benchmark", help="Run offline or live benchmark suites.")
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(broker_app, name="broker")


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

    if transport not in {"direct", "broker"}:
        raise typer.BadParameter("transport must be direct or broker")
    try:
        loaded = load_config(config)
        loaded.jev.transport = transport
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
    except (OSError, RuntimeError, ValueError):
        typer.echo("Benchmark input/output error; check case names and output path.", err=True)
        raise typer.Exit(2) from None


def _validated_mode(value: str | None) -> Mode | None:
    if value is None:
        return None
    if value not in {"advisory", "review", "enforce"}:
        raise typer.BadParameter("mode must be advisory, review, or enforce")
    return value  # type: ignore[return-value]


def _load(path: Path | None, mode: str | None) -> ReflexConfig:
    return load_config(path, mode_override=_validated_mode(mode))


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
    if config.mode == "review" and result.decision != "ALLOW":
        return 2
    if config.mode == "enforce" and (result.decision == "HOLD" or result.degraded):
        return 2
    return 0


def _read_diff(enabled: bool) -> str:
    if not enabled:
        return ""
    try:
        return sys.stdin.read()
    except OSError as exc:
        raise typer.BadParameter("could not read stdin diff") from exc


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
) -> None:
    """Analyze proposed commands without executing them."""

    try:
        loaded = _load(config, mode)
        if transport is not None:
            if transport not in {"direct", "broker"}:
                raise typer.BadParameter("transport must be direct or broker")
            loaded.jev.transport = transport
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
    except (OSError, RuntimeError, ValueError):
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


@app.command("exec", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
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
) -> None:
    """Evaluate and, when the configured mode permits it, execute one argv list."""

    try:
        argv = _resolve_exec_argv(command, _trailing_argv(ctx))
        loaded = _load(config, mode)
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
    except (OSError, RuntimeError, ValueError):
        typer.echo("Configuration, input, or command error. No action was executed.", err=True)
        raise typer.Exit(code=2) from None

    _emit_result(result, json_output=json_output)
    if not execution_allowed(result.decision, mode=loaded.mode, degraded=result.degraded):
        typer.echo("Execution skipped by JEV Reflex policy.", err=True)
        raise typer.Exit(code=2)

    try:
        completed = subprocess.run(
            argv,
            cwd=str(_provider(loaded, cwd).working_directory),
            check=False,
            shell=False,
        )
    except OSError:
        typer.echo("Command could not be started.", err=True)
        raise typer.Exit(code=127) from None
    raise typer.Exit(code=completed.returncode)


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

            def evaluate_once(value: EvaluationContext) -> EvaluationResult:
                return evaluate_context(value, config=single_config, use_jev=False)
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
        rows: list[dict[str, Any]] = []
        for case_path in files:
            with case_path.open("r", encoding="utf-8") as handle:
                case = json.load(handle)
            if not isinstance(case, dict) or not isinstance(case.get("command"), str):
                raise ValueError("benchmark case must contain a command")
            context = _build_context(
                config=single_config,
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


def _run_hook(kind: str, config_path: Path | None, mode: str | None, demo: bool) -> None:
    try:
        payload = read_hook_payload()
        loaded = _load(config_path, mode)
        if kind == "codex":
            _result, output = evaluate_codex_hook(payload, config=loaded, demo=demo)
        elif kind == "claude":
            _result, output = evaluate_claude_code_hook(payload, config=loaded, demo=demo)
        elif kind == "antigravity":
            _result, output = evaluate_antigravity_hook(payload, config=loaded, demo=demo)
        elif kind == "openrouter":
            _result, output = evaluate_openrouter_hook(payload, config=loaded, demo=demo)
        elif kind == "pi":
            _result, output = evaluate_pi_hook(payload, config=loaded, demo=demo)
        else:
            _result, output = evaluate_deepseek_hook(payload, config=loaded, demo=demo)
    except Exception:
        # Hook hosts differ in how they treat non-zero hook exits. A valid deny response
        # is the most portable fail-safe for malformed input/configuration.
        output = {
            "codex": codex_hook_error,
            "claude": claude_hook_error,
            "antigravity": antigravity_hook_error,
            "openrouter": openrouter_hook_error,
            "pi": pi_hook_error,
            "deepseek": deepseek_hook_error,
        }[kind]()
    typer.echo(json.dumps(output, separators=(",", ":")))


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


if __name__ == "__main__":  # pragma: no cover
    app()
