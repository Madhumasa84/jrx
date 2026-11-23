"""Measure warm evaluation and a fresh jrx process on the same git status input."""

from __future__ import annotations

import math
import os
import platform
import subprocess
import sysconfig
from collections.abc import Callable
from pathlib import Path
from time import perf_counter_ns

from benchmarks.harnesses.evaluation import EvaluatorBackend, LocalBackend
from jev_reflex import __version__
from jev_reflex.models import EvaluationContext, ProposedAction

WARMUPS = 10
ITERATIONS = 100


def environment_metadata(hashes: dict[str, str]) -> dict[str, object]:
    return {
        "os": platform.system(),
        "python_version": platform.python_version(),
        "cpu_logical_count": os.cpu_count(),
        "jrx_version": __version__,
        "dataset_sha256": hashes,
        "redaction": "built-in regex",
    }


def _measure(action: Callable[[], None]) -> dict[str, float]:
    for _ in range(WARMUPS):
        action()
    samples = []
    for _ in range(ITERATIONS):
        start = perf_counter_ns()
        action()
        samples.append((perf_counter_ns() - start) / 1_000_000)
    samples.sort()
    return {
        f"p{percentile}_ms": samples[math.ceil(percentile * ITERATIONS / 100) - 1]
        for percentile in (50, 95, 99)
    }


def _broker_peak_rss_mb(pid: int | None) -> float | None:
    if pid is None or platform.system() != "Linux":
        return None
    try:
        with Path(f"/proc/{pid}/status").open(encoding="utf-8") as status:
            for line in status:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) / 1024
    except (OSError, ValueError):
        pass
    return None


def measure_latency(
    backend: EvaluatorBackend,
    workspace: Path,
    environment: dict[str, str],
    *,
    backend_name: str = "deterministic",
) -> dict:
    import resource

    if Path("/etc/jrx/bootstrap.yaml").exists():
        raise ValueError("cold CLI timing requires default system bootstrap settings")

    launcher = Path(sysconfig.get_path("scripts")) / "jrx"
    if not launcher.is_file():
        raise ValueError("install the jrx console script in the current Python environment")

    context = EvaluationContext(
        repository=workspace.name,
        repository_root=str(workspace),
        working_directory=str(workspace),
        proposed_action=ProposedAction(command="git status"),
    )

    def warm_check() -> None:
        decision = backend.evaluate(context)
        if backend_name == "deterministic" and decision != "ALLOW":
            raise RuntimeError("warm latency control did not return ALLOW")

    def cold_check() -> None:
        completed = subprocess.run(
            [str(launcher), "check", "--no-jev", "--command", "git status"],
            cwd=workspace,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if (
            completed.returncode != 0
            or b"\n  ALLOW\n" not in completed.stdout
            or b"\nSource: none\n" not in completed.stdout
        ):
            raise RuntimeError("cold latency control did not return a normal offline ALLOW")

    # Linux reports KiB and macOS reports bytes. The runner owns the child process set.
    rss_divisor = 1024**2 if platform.system() == "Darwin" else 1024
    warm = _measure(warm_check)
    warm_peak_rss = (
        _broker_peak_rss_mb(backend.broker_pid)
        if isinstance(backend, LocalBackend) and backend_name == "local-broker"
        else resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / rss_divisor
    )
    cold = _measure(cold_check)
    cold["peak_rss_mb"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / rss_divisor
    return {
        "warmups_per_mode": WARMUPS,
        "timed_iterations_per_mode": ITERATIONS,
        ("warm_broker" if backend_name == "local-broker" else "warm_in_process"): {
            **warm,
            "peak_rss_mb": warm_peak_rss,
        },
        "cold_cli": cold,
    }
