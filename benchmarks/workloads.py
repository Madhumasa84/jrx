"""Score labeled agent workloads by what each host would do, not only by policy labels.

Each record is one host hook event (an inert, recorded tool call) with an independent
label saying whether the action was risky (should not run unattended). The event runs
through the same pipeline the hooks use (payload normalization, evaluation and the
``host_verdict`` mapping) for every mode and backend, and the result is reported as
what the host does: ``proceed`` (runs unattended), ``ask`` (a user decides) or ``deny``
(prevented). Risky actions that are only flagged for review are counted apart from
risky actions that are prevented.

Development records tune nothing here and are scored freely. Holdout records are scored
only when ``eval/workloads/manifest.json`` pins their bytes, every record is labeled by
an independent labeler from an authorized source, and acceptance thresholds were
registered (and hash-pinned) before scoring. See ``eval/workloads/README.md``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmarks.harnesses.evaluation import (
    default_model_dir,
    isolated_workspace,
    local_backend,
    rate,
)
from jev_reflex.adapters.generic import context_from_hook_payload
from jev_reflex.adapters.harness import host_verdict
from jev_reflex.config import ReflexConfig
from jev_reflex.evaluator import evaluate_context

ROOT = Path(__file__).resolve().parents[1]
WORKLOADS = ROOT / "eval" / "workloads"
SCHEMA = "jrx.workload.v1"
MODES = ("advisory", "review", "enforce")
# adapter -> (provider key for payload normalization, whether the host can ask)
ADAPTERS = {
    "claude": ("claude", True),
    "antigravity": ("antigravity", True),
    "openrouter-permission": (None, True),
    "codex": ("codex", False),
    "deepseek": (None, False),
    "openrouter-pre": (None, False),
    "pi": (None, False),
}
SPLITS = ("development", "holdout")


class WorkloadError(ValueError):
    """The workload, manifest or thresholds do not meet the evaluation protocol."""


@dataclass(frozen=True)
class Record:
    id: str
    split: str
    adapter: str
    event: dict[str, Any]
    risky: bool
    independent: bool
    authorized: bool
    source: str


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_records(path: Path, split: str) -> list[Record]:
    records = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        data = json.loads(line)
        where = f"{path.name}:{number}"
        try:
            labeling, provenance = data["labeling"], data["provenance"]
            record = Record(
                id=str(data["id"]),
                split=data["split"],
                adapter=data["adapter"],
                event=dict(data["event"]),
                risky=data["label"]["risky"],
                independent=labeling["independent"],
                authorized=provenance["authorized"],
                source=provenance["source"],
            )
        except (KeyError, TypeError) as exc:
            raise WorkloadError(f"{where}: missing or invalid field {exc}") from None
        if data.get("schema") != SCHEMA:
            raise WorkloadError(f"{where}: schema must be {SCHEMA}")
        if record.split != split:
            raise WorkloadError(f"{where}: {record.split} record in the {split} split")
        if record.adapter not in ADAPTERS:
            raise WorkloadError(f"{where}: unknown adapter {record.adapter!r}")
        if not isinstance(record.risky, bool):
            raise WorkloadError(f"{where}: label.risky must be true or false")
        if split == "holdout" and not (
            record.independent is True
            and record.authorized is True
            and record.source != "synthetic"
        ):
            raise WorkloadError(
                f"{where}: holdout records need an independent labeler and an authorized, "
                "non-synthetic source"
            )
        records.append(record)
    return records


def load_manifest(root: Path = WORKLOADS) -> dict[str, Any]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for split in SPLITS:
        for entry in manifest[split]:
            actual = _sha256(root / entry["path"])
            if actual != entry["sha256"]:
                raise WorkloadError(f"{entry['path']} does not match its pinned SHA-256")
    return manifest


def load_registered_thresholds(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    pinned = manifest.get("thresholds")
    if not pinned:
        raise WorkloadError("the manifest pins no acceptance thresholds")
    path = root / pinned["path"]
    if _sha256(path) != pinned["sha256"]:
        raise WorkloadError("thresholds changed after they were pinned in the manifest")
    thresholds = json.loads(path.read_text(encoding="utf-8"))
    if thresholds.get("status") != "registered" or not thresholds.get("registered_by"):
        raise WorkloadError(
            "acceptance thresholds are not registered; register them (status, registered_by, "
            "registered_at) and pin their hash before scoring the holdout"
        )
    return thresholds


@contextmanager
def _backends(names: list[str], workspace: Path, environment: dict[str, str]) -> Iterator[dict]:
    """Yield the semantic evaluator for each backend (None: deterministic rules only)."""
    available: dict[str, Any] = {}
    gaps: list[str] = []
    if "deterministic" in names:
        available["deterministic"] = None
    if "model-assisted" not in names:
        yield {"backends": available, "gaps": gaps}
        return
    model_dir = default_model_dir()
    if not model_dir.exists():
        gaps.append(f"model-assisted backend not run: no local model at {model_dir}")
        yield {"backends": available, "gaps": gaps}
        return
    with local_backend(
        broker=False, model_dir=model_dir, workspace=workspace, environment=environment
    ) as backend:
        available["model-assisted"] = backend
        yield {"backends": available, "gaps": gaps}


def _event_for(record: Record, workspace: Path) -> dict[str, Any]:
    event = dict(record.event)
    if record.adapter == "antigravity":
        event["workspacePaths"] = [str(workspace)]
    else:
        event["cwd"] = str(workspace)
    if record.adapter.startswith("openrouter"):
        event["hookName"] = (
            "PermissionRequest" if record.adapter.endswith("permission") else "PreToolUse"
        )
    return event


def _verdict(record: Record, config: ReflexConfig, workspace: Path, backend: Any) -> str:
    provider_key, can_ask = ADAPTERS[record.adapter]
    try:
        context = context_from_hook_payload(
            _event_for(record, workspace), config=config, provider_key=provider_key
        )
    except ValueError:
        return "deny"  # the hook answers malformed input with its deny response
    if backend is None:
        result = evaluate_context(context, config=config, use_jev=False)
    else:
        result = evaluate_context(
            context,
            config=backend.config.model_copy(update={"mode": config.mode}),
            semantic_evaluator=backend.evaluator,
        )
    return host_verdict(result, config, can_ask=can_ask)


def score(records: list[Record], *, modes: list[str], backend_names: list[str]) -> dict:
    strata: list[dict[str, Any]] = []
    with isolated_workspace() as (workspace, environment):
        with _backends(backend_names, workspace, environment) as loaded:
            for backend_name, backend in loaded["backends"].items():
                for mode in modes:
                    config = ReflexConfig(mode=mode)
                    for adapter in sorted({record.adapter for record in records}):
                        rows = [r for r in records if r.adapter == adapter]
                        outcomes: dict[bool, list[str]] = {True: [], False: []}
                        latencies: list[float] = []
                        for record in rows:
                            started = time.perf_counter()
                            outcome = _verdict(record, config, workspace, backend)
                            latencies.append((time.perf_counter() - started) * 1000)
                            outcomes[record.risky].append(outcome)
                        strata.append(_stratum(adapter, mode, backend_name, outcomes, latencies))
            gaps = loaded["gaps"]
    return {"strata": strata, "evidence_gaps": gaps}


def _stratum(
    adapter: str, mode: str, backend: str, outcomes: dict[bool, list[str]], latencies: list[float]
) -> dict[str, Any]:
    risky, benign = outcomes[True], outcomes[False]
    ordered = sorted(latencies)
    return {
        "adapter": adapter,
        "mode": mode,
        "backend": backend,
        # Risky: proceeded = allowed to run unattended; asked = flagged, a user decides;
        # denied = prevented. Only "denied" is prevention.
        "risky_proceeded": rate(risky.count("proceed"), len(risky)),
        "risky_asked": rate(risky.count("ask"), len(risky)),
        "risky_denied": rate(risky.count("deny"), len(risky)),
        "benign_denied": rate(benign.count("deny"), len(benign)),
        "benign_asked": rate(benign.count("ask"), len(benign)),
        "latency_ms": {
            "p50": round(statistics.median(ordered), 3) if ordered else None,
            "p95": round(ordered[max(0, -(-95 * len(ordered) // 100) - 1)], 3) if ordered else None,
            "n": len(ordered),
        },
    }


def acceptance(report: dict, thresholds: dict) -> list[dict[str, Any]]:
    """Compare each stratum the thresholds apply to; refuse verdicts on small samples."""
    limits, minimum = thresholds["limits"], thresholds["minimum_samples"]
    results = []
    for stratum in report["strata"]:
        if stratum["mode"] not in thresholds["applies_to"]["modes"]:
            continue
        n_risky, n_benign = stratum["risky_denied"]["total"], stratum["benign_denied"]["total"]
        if n_risky < minimum["risky"] or n_benign < minimum["benign"]:
            results.append({**_key(stratum), "verdict": "insufficient sample"})
            continue
        failures = [
            name
            for name, measured, limit in (
                (
                    "risky_proceeded",
                    stratum["risky_proceeded"]["rate"],
                    limits["risky_proceeded_max"],
                ),
                ("benign_denied", stratum["benign_denied"]["rate"], limits["benign_denied_max"]),
                ("benign_asked", stratum["benign_asked"]["rate"], limits["benign_asked_max"]),
                (
                    "latency_p95_ms",
                    stratum["latency_ms"]["p95"],
                    limits["latency_p95_ms_max"][stratum["backend"]],
                ),
            )
            if measured is not None and measured > limit
        ]
        results.append(
            {**_key(stratum), "verdict": "fail" if failures else "pass", "failed": failures}
        )
    return results


def _key(stratum: dict) -> dict[str, str]:
    return {name: stratum[name] for name in ("adapter", "mode", "backend")}


def run(split: str, *, modes: list[str], backend_names: list[str], root: Path = WORKLOADS) -> dict:
    manifest = load_manifest(root)
    entries = manifest[split]
    thresholds = load_registered_thresholds(root, manifest) if split == "holdout" else None
    report: dict[str, Any] = {
        "split": split,
        "manifest_sha256": _sha256(root / "manifest.json"),
        "files": entries,
    }
    if not entries:
        report.update(strata=[], records=0, evidence_gaps=[f"no {split} records are pinned"])
        return report
    records = [r for entry in entries for r in load_records(root / entry["path"], split)]
    report.update(score(records, modes=modes, backend_names=backend_names), records=len(records))
    if thresholds is not None:
        report["acceptance"] = acceptance(report, thresholds)
    return report


def self_test() -> int:
    """Check the protocol files and score the development split deterministically."""
    report = run("development", modes=list(MODES), backend_names=["deterministic"])
    assert report["records"] > 0 and report["strata"], "no development records were scored"
    for stratum in report["strata"]:
        total = stratum["risky_denied"]["total"] + stratum["benign_denied"]["total"]
        assert total > 0, stratum
    try:
        run("holdout", modes=["enforce"], backend_names=["deterministic"])
        holdout = "holdout scored"
    except WorkloadError as exc:
        holdout = f"holdout refused: {exc}"
    print(
        json.dumps(
            {
                "development_records": report["records"],
                "development_strata": len(report["strata"]),
                "holdout": holdout,
                "evidence_gap": "no independently labeled, authorized holdout workload exists yet",
            },
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", choices=SPLITS, default="development")
    parser.add_argument("--modes", default=",".join(MODES))
    parser.add_argument(
        "--backend", choices=("deterministic", "model-assisted", "both"), default="deterministic"
    )
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    backends = ["deterministic", "model-assisted"] if args.backend == "both" else [args.backend]
    try:
        report = run(args.split, modes=args.modes.split(","), backend_names=backends)
    except WorkloadError as exc:
        print(f"workload evaluation refused: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
