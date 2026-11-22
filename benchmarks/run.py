#!/usr/bin/env python3
"""Run the offline deterministic benchmark and optionally render its results."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Support both python benchmarks/run.py and python -m benchmarks.run.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.datasets import load_datasets  # noqa: E402
from benchmarks.harnesses.evaluation import (  # noqa: E402
    DeterministicBackend,
    evaluate_cases,
    isolated_workspace,
)
from benchmarks.harnesses.latency import environment_metadata, measure_latency  # noqa: E402
from benchmarks.reporting import regressions, render_markdown  # noqa: E402

DATASET_DIRECTORY = Path(__file__).resolve().parent / "datasets"


def build_report(*, backend_name: str, verify: bool, skip_latency: bool) -> dict:
    cases, hashes = load_datasets(DATASET_DIRECTORY, verify=verify)
    backend = DeterministicBackend()
    with isolated_workspace() as (workspace, environment):
        evaluation = evaluate_cases(cases, backend, workspace, backend.config)
        latency = None if skip_latency else measure_latency(backend, workspace, environment)
    return {
        "artifact_version": 1,
        "benchmark_revision": "tier0-step3",
        "backend": backend_name,
        "environment": environment_metadata(hashes),
        "evaluation": evaluation,
        "latency": latency,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("deterministic",), default="deterministic")
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
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(
                json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8"
            )
        if args.render_md:
            args.render_md.parent.mkdir(parents=True, exist_ok=True)
            args.render_md.write_text(render_markdown(report, baseline), encoding="utf-8")
    except (KeyError, TypeError, ZeroDivisionError):
        print("Benchmark error: invalid baseline report", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError):
        print("Benchmark error: file operation or cold CLI process failed", file=sys.stderr)
        return 2
    except (RuntimeError, ValueError) as exc:
        print(f"Benchmark error: {exc}", file=sys.stderr)
        return 2

    if not (args.out or args.render_md or args.baseline):
        print(render_markdown(report), end="")
        return 0

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
