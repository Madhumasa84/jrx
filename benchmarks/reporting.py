"""Render benchmark results and compare outcomes against a frozen baseline."""

from __future__ import annotations

from fractions import Fraction

from benchmarks.harnesses.evaluation import Rate

ATTACK_LABELS = {
    "ASI01": "Goal hijack",
    "ASI02": "Tool misuse",
    "ASI03": "Privilege and secret abuse",
    "ASI04": "Supply chain",
    "ASI05": "Unexpected code execution",
    "ASI06": "Context and memory poisoning",
}
LATENCY_MODES = (
    ("Warm in-process", "warm_in_process"),
    ("Warm broker", "warm_broker"),
    ("Cold CLI", "cold_cli"),
)


def _gate_rates(report: dict) -> dict[str, Rate]:
    metrics = report["evaluation"]["splits"]["eval"]
    attack = metrics["attack"]
    return {
        "Hard FPR": metrics["benign"]["hard_fpr"],
        "Friction Rate": metrics["benign"]["friction"],
        "Overall attack recall": attack["overall"]["intervention"],
        "OWASP ASI01–ASI06 recall": attack["owasp_asi"]["intervention"],
        "Bypass recall": attack["bypass_obfuscation"]["intervention"],
        **{
            f"{category} recall": attack["clean_by_asi"][category]["intervention"]
            for category in ATTACK_LABELS
        },
    }


def regressions(report: dict, baseline: dict) -> list[str]:
    if (
        report["artifact_version"] != baseline["artifact_version"]
        or report["backend"] != baseline["backend"]
        or report["environment"]["dataset_sha256"] != baseline["environment"]["dataset_sha256"]
    ):
        raise ValueError("baseline requires the same artifact version, backend, and dataset hashes")
    reference = _gate_rates(baseline)
    failures = []
    for name, value in _gate_rates(report).items():
        prior = reference[name]
        if value["total"] != prior["total"]:
            raise ValueError(f"baseline cohort size mismatch for {name}")
        old = Fraction(prior["count"], prior["total"])
        new = Fraction(value["count"], value["total"])
        if not 0 <= old <= 1:
            raise ValueError(f"invalid baseline rate for {name}")
        regressed = new > old if name in {"Hard FPR", "Friction Rate"} else new < old
        if regressed:
            failures.append(
                f"{name} changed from {prior['count']}/{prior['total']} "
                f"to {value['count']}/{value['total']}"
            )
    return failures


def _rate_cell(value: Rate) -> str:
    interval = value["wilson_95"]
    if value["rate"] is None or interval is None:
        return "—"
    return (
        f"{value['rate']:.2%} ({value['count']}/{value['total']}) "
        f"[{interval[0]:.2%}, {interval[1]:.2%}]"
    )


def _comparison(records: tuple[tuple[str, dict], ...]) -> list[str]:
    names = [name for name, _ in records]
    reports = [report for _, report in records]
    rates = [_gate_rates(report) for report in reports]
    holdouts = [report["evaluation"]["splits"]["eval"] for report in reports]

    def row(label: str, cells: list[str]) -> str:
        return "| " + " | ".join([label, *cells]) + " |"

    lines = [
        "## Frozen eval holdout comparison",
        "",
        (
            "Both revisions evaluated the same frozen cases. Recall is REVIEW or HOLD."
            if len(records) == 2
            else "Each run evaluated the same frozen cases. Recall is REVIEW or HOLD."
        ),
        "Individual rates include two-sided Wilson 95% intervals.",
        "",
        row("Metric", names),
        row("---", ["---"] * len(reports)),
    ]
    for metric in (
        "Hard FPR",
        "Friction Rate",
        "Overall attack recall",
        "OWASP ASI01–ASI06 recall",
        *(f"{category} recall" for category in ATTACK_LABELS),
        "Bypass recall",
    ):
        label = f"Benign {metric}" if metric in {"Hard FPR", "Friction Rate"} else metric
        lines.append(row(label, [_rate_cell(run_rates[metric]) for run_rates in rates]))
    for label, mode in LATENCY_MODES:
        cells = []
        for report in reports:
            timing = (report["latency"] or {}).get(mode)
            cells.append(
                f"{timing['p50_ms']:.3f} / {timing['p95_ms']:.3f} ms" if timing is not None else "—"
            )
        if mode != "warm_broker" or any(cell != "—" for cell in cells):
            lines.append(row(f"{label} p50 / p95", cells))
    lines.append("")
    for name, metrics in zip(names, holdouts, strict=True):
        misses = ", ".join(
            f"`{row['family']}` ({row['count']})" for row in metrics["issues"]["misses"][:3]
        )
        lines.extend([f"**{name} top missed families** — {misses or 'none'}.", ""])
    return lines


def _revision(report: dict) -> str:
    if report.get("benchmark_revision") == "tier0-step3":
        return "Step 3 Hardened Tier-0"
    return f"v{report['environment']['jrx_version']}"


def render_markdown(
    report: dict, baseline: dict | None = None, *, historical: tuple[dict, dict] | None = None
) -> str:
    environment = report["environment"]
    metrics = report["evaluation"]["splits"]["eval"]
    benign, attack, issues = (metrics[name] for name in ("benign", "attack", "issues"))
    comparison = ()
    backend = report["backend"]
    command = (
        "python -B -m benchmarks.run --backend deterministic --verify-hashes "
        "--out benchmarks/results/v0.2.0-step3-deterministic.json --render-md benchmarks/RESULTS.md "
        "--baseline benchmarks/results/v0.2.0-deterministic.json"
    )
    title = f"jrx {_revision(report)} deterministic benchmark"
    description = (
        "This benchmark measures **Tier-0 deterministic rules only**, with no semantic model."
    )
    if model := report.get("model"):
        model_name = model["id"].rsplit("/", 1)[-1]
        label = f"Step 3 + local ONNX ({model_name})"
        title = f"jrx {label} benchmark"
        transport = (
            "a warm Unix socket broker" if backend == "local-broker" else "in-process inference"
        )
        description = (
            f"This benchmark measures Tier-0 rules plus CPU ONNX through {transport}.\n"
            f"Model `{model['id']}` has verified SHA-256 `{model['sha256']}`."
        )
        if policy := report.get("local_policy"):
            description += (
                f"\nThe local policy uses a {policy['review_threshold']:.2f} review threshold "
                f"and a {policy['hold_threshold']:.2f} hold threshold."
            )
        output = (
            "v0.3.0-local-broker-coba68m.json"
            if backend == "local-broker"
            else "v0.3.0-local-coba68m.json"
        )
        command = (
            "jrx model pull\n"
            f"python -m benchmarks.run --backend {backend} --verify-hashes "
            f"--out benchmarks/results/{output} --render-md benchmarks/RESULTS.md"
        )
        if historical is not None:
            if any(
                prior["environment"]["dataset_sha256"] != environment["dataset_sha256"]
                for prior in historical
            ):
                raise ValueError("historical comparison requires matching dataset hashes")
            comparison = (
                ("v0.2.0 deterministic", historical[0]),
                ("Step 3 deterministic", historical[1]),
                (label, report),
            )
    elif baseline is not None:
        comparison = ((f"{_revision(baseline)} Baseline", baseline), (_revision(report), report))
    lines = [
        f"# {title}",
        "",
        description,
        "The benchmark covers single-step pre-execution classification of synthetic cases.",
        "Session taint and integrity pinning are measured by the integration tests.",
        "The out-of-scope OWASP categories are **ASI07** (Insecure Inter-Agent Communication),",
        "**ASI08** (Cascading Failures), **ASI09** (Human-Agent Trust Exploitation), and",
        "**ASI10** (Rogue Agents).",
        "",
        "## Reproduce",
        "",
        "Run from the repository root with jrx installed in the active Python environment.",
        "",
        "```sh",
        command,
        "```",
        "",
        *(_comparison(comparison) if comparison else []),
        "## Current eval holdout details",
        "",
        "Rates show the observed fraction and its two-sided Wilson 95% confidence interval.",
        "Attack recall is the intervention rate (REVIEW or HOLD). Strict block counts HOLD only.",
        "",
        "| Metric | Rate [95% CI] |",
        "| --- | --- |",
        f"| Benign Hard FPR | {_rate_cell(benign['hard_fpr'])} |",
        f"| Benign Friction Rate | {_rate_cell(benign['friction'])} |",
        "",
        "| Attack cohort | Recall [95% CI] | Strict block [95% CI] | Below expected minimum [95% CI] |",
        "| --- | --- | --- | --- |",
    ]
    for label, rates in [
        ("All attacks", attack["overall"]),
        ("OWASP ASI01–ASI06", attack["owasp_asi"]),
        *(
            (f"{category} {label}", attack["clean_by_asi"][category])
            for category, label in ATTACK_LABELS.items()
        ),
        ("Obfuscation bypass", attack["bypass_obfuscation"]),
    ]:
        lines.append(
            f"| {label} | {_rate_cell(rates['intervention'])} "
            f"| {_rate_cell(rates['strict_block'])} "
            f"| {_rate_cell(rates['below_expected_minimum'])} |"
        )

    delta = attack["clean_vs_obfuscated_recall_delta"]
    if delta["newcombe_95"] is not None:
        lower, upper = delta["newcombe_95"]
        lines.extend(
            [
                "",
                f"Clean minus obfuscated recall was **{delta['clean_minus_obfuscated'] * 100:+.2f} pp** "
                f"(Newcombe 95% interval [{lower * 100:+.2f}, {upper * 100:+.2f}] pp).",
                "The suites contain different cases and attack mixes, so this unpaired difference",
                "combines obfuscation with other differences between the suites.",
            ]
        )
    lines.extend(
        [
            "",
            "## Top known misses & false positives",
            "",
            "Families are ordered by count, with ties broken alphabetically. The tables show up to",
            "three families per outcome and up to three case IDs per family.",
            "",
            "| Outcome | Family | Count | Sample case IDs |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for title, issue in (
        ("Attack ALLOW", "misses"),
        ("Attack below expected minimum", "below_expected_minimum"),
        ("Benign HOLD", "benign_holds"),
        ("Benign REVIEW", "benign_reviews"),
    ):
        for group in issues[issue][:3]:
            ids = ", ".join(f"`{case_id}`" for case_id in group["sample_ids"])
            lines.append(f"| {title} | {group['family']} | {group['count']} | {ids} |")

    lines.extend(["", "## Latency", ""])
    latency = report["latency"]
    if latency is None:
        lines.append("Latency measurement was skipped for this run.")
    else:
        lines.extend(
            [
                f"Each mode ran {latency['warmups_per_mode']} warm-ups and "
                f"{latency['timed_iterations_per_mode']} timed iterations of the git status check.",
                "",
                "| Mode | p50 (ms) | p95 (ms) | p99 (ms) | Peak RSS (MiB) |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for label, mode in LATENCY_MODES:
            if mode not in latency:
                continue
            timing = latency[mode]
            if mode == "cold_cli":
                label = "Cold jrx CLI"
            peak_rss = timing["peak_rss_mb"]
            rss_cell = f"{peak_rss:.2f}" if peak_rss is not None else "—"
            lines.append(
                f"| {label} | {timing['p50_ms']:.3f} | {timing['p95_ms']:.3f} "
                f"| {timing['p99_ms']:.3f} | {rss_cell} |"
            )
        lines.extend(
            [
                "",
                "Warm broker peak RSS is the server high-water mark when available from procfs."
                if backend == "local-broker"
                else "Warm peak RSS covers the runner process, including imports and loaded fixtures.",
                "Cold peak RSS is the child-process high-water mark, including warm-ups.",
            ]
        )
    lines.extend(
        [
            "",
            f"Environment: {environment['os']}, Python {environment['python_version']}, "
            f"{environment['cpu_logical_count']} logical CPUs, {environment['redaction']} redaction.",
            "The raw JSON includes dataset hashes, per-case decisions, all family counts and",
            "intervals, and the dev split. See the [benchmark guide](README.md) for scope and methodology.",
            "",
        ]
    )
    return "\n".join(lines)
