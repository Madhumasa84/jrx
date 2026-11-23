#!/usr/bin/env python3
"""Run the offline jrx benchmark and optionally render its results."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path

# Support both python benchmarks/run.py and python -m benchmarks.run.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.datasets import load_datasets  # noqa: E402
from benchmarks.harnesses.evaluation import (  # noqa: E402
    DeterministicBackend,
    LocalBackend,
    default_model_dir,
    evaluate_cases,
    isolated_workspace,
    local_backend,
)
from benchmarks.harnesses.latency import environment_metadata, measure_latency  # noqa: E402
from benchmarks.reporting import regressions, render_markdown  # noqa: E402

DATASET_DIRECTORY = Path(__file__).resolve().parent / "datasets"
RESULTS_DIRECTORY = DATASET_DIRECTORY.parent / "results"
HISTORICAL_BASELINES = (
    RESULTS_DIRECTORY / "v0.2.0-deterministic.json",
    RESULTS_DIRECTORY / "v0.2.0-step3-deterministic.json",
)
LOCAL_BACKENDS = ("local", "local-broker")


def historical_reports() -> tuple[dict, dict]:
    first, second = HISTORICAL_BASELINES
    return json.loads(first.read_text(encoding="utf-8")), json.loads(
        second.read_text(encoding="utf-8")
    )


def build_report(*, backend_name: str, verify: bool, skip_latency: bool) -> dict:
    model_dir = default_model_dir() if backend_name in LOCAL_BACKENDS else None
    with isolated_workspace() as (workspace, environment):
        backends = (
            local_backend(
                broker=backend_name == "local-broker",
                model_dir=model_dir,
                workspace=workspace,
                environment=environment,
            )
            if model_dir is not None
            else nullcontext(DeterministicBackend())
        )
        with backends as backend:
            cases, hashes = load_datasets(DATASET_DIRECTORY, verify=verify)
            evaluation = evaluate_cases(cases, backend, workspace, backend.config)
            latency = (
                None
                if skip_latency
                else measure_latency(backend, workspace, environment, backend_name=backend_name)
            )
    return {
        "artifact_version": 1,
        "benchmark_revision": "tier0-step3-local" if model_dir is not None else "tier0-step3",
        "backend": backend_name,
        **(
            {
                "model": backend.model,
                "local_policy": {
                    "hold_threshold": backend.config.thresholds.strong,
                    "review_threshold": backend.config.thresholds.review,
                    "hold_on": backend.config.hold_on,
                    "review_on": backend.config.review_on,
                    "max_tokens": backend.config.evaluator.max_tokens,
                },
            }
            if isinstance(backend, LocalBackend)
            else {}
        ),
        "environment": environment_metadata(hashes),
        "evaluation": evaluation,
        "latency": latency,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backend", choices=("deterministic", *LOCAL_BACKENDS), default="deterministic"
    )
    parser.add_argument("--verify-hashes", action="store_true")
    parser.add_argument("--out", type=Path, help="Write the complete JSON report.")
    parser.add_argument("--render-md", type=Path, help="Write a Markdown summary.")
    parser.add_argument(
        "--baseline", type=Path, help="Compare holdout rates against this JSON report."
    )
    parser.add_argument("--fail-on-regression", action="store_true")
    parser.add_argument("--skip-latency", action="store_true")
    args = parser.parse_args(argv)
    if args.fail_on_regression and args.baseline is None:
        parser.error("--fail-on-regression requires --baseline")
    if args.baseline and any(
        path is not None and path.resolve() == args.baseline.resolve()
        for path in (args.out, args.render_md)
    ):
        parser.error("an output file cannot overwrite the comparison baseline")
    if args.out and args.render_md and args.out.resolve() == args.render_md.resolve():
        parser.error("JSON and Markdown output files must be distinct")
    try:
        baseline = json.loads(args.baseline.read_text(encoding="utf-8")) if args.baseline else None
        report = build_report(
            backend_name=args.backend, verify=args.verify_hashes, skip_latency=args.skip_latency
        )
        failures = regressions(report, baseline) if args.baseline else []
        print_markdown = not (args.out or args.render_md or args.baseline)
        markdown = None
        if args.render_md or print_markdown:
            historical = historical_reports() if args.backend in LOCAL_BACKENDS else None
            markdown = render_markdown(report, baseline, historical=historical)
        if print_markdown:
            print(markdown, end="")
            return 0
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(
                json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8"
            )
        if args.render_md:
            args.render_md.parent.mkdir(parents=True, exist_ok=True)
            assert markdown is not None
            args.render_md.write_text(markdown, encoding="utf-8")
    except (KeyError, TypeError, ZeroDivisionError):
        print("Benchmark error: invalid baseline report", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError):
        print("Benchmark error: file operation or cold CLI process failed", file=sys.stderr)
        return 2
    except (RuntimeError, ValueError) as exc:
        print(f"Benchmark error: {exc}", file=sys.stderr)
        return 2

    count = len(report["evaluation"]["cases"])
    print(f"Evaluated {count} frozen cases with the {args.backend} backend.")
    if args.baseline:
        if failures:
            for failure in failures:
                print(f"Regression: {failure}", file=sys.stderr)
        else:
            print("No holdout Hard FPR or attack recall regression. Friction held or improved.")
    return int(bool(failures) and args.fail_on_regression)


if __name__ == "__main__":
    raise SystemExit(main())
