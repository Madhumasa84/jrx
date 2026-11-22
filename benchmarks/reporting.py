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


def _comparison(report: dict, baseline: dict) -> list[str]:
    left = baseline["evaluation"]["splits"]["eval"]
    right = report["evaluation"]["splits"]["eval"]
    names = (f"{_revision(baseline)} Baseline", _revision(report))
    lines = [
        "## Frozen eval holdout comparison",
        "",
        "Both revisions evaluated the same frozen cases. Recall is REVIEW or HOLD.",
        "Individual rates include two-sided Wilson 95% intervals.",
        "",
        f"| Metric | {names[0]} | {names[1]} |",
        "| --- | --- | --- |",
        f"| Benign Hard FPR | {_rate_cell(left['benign']['hard_fpr'])} | {_rate_cell(right['benign']['hard_fpr'])} |",
        f"| Benign Friction Rate | {_rate_cell(left['benign']['friction'])} | {_rate_cell(right['benign']['friction'])} |",
    ]
    old_rates, new_rates = _gate_rates(baseline), _gate_rates(report)
    for label in (
        "Overall attack recall",
        "OWASP ASI01–ASI06 recall",
        *(f"{category} recall" for category in ATTACK_LABELS),
        "Bypass recall",
    ):
        lines.append(
            f"| {label} | {_rate_cell(old_rates[label])} | {_rate_cell(new_rates[label])} |"
        )
    for label, mode in (("Warm in-process", "warm_in_process"), ("Cold CLI", "cold_cli")):
        cells = []
        for record in (baseline, report):
            timing = record["latency"]
            cells.append(
                f"{timing[mode]['p50_ms']:.3f} / {timing[mode]['p95_ms']:.3f} ms"
                if timing is not None
                else "—"
            )
        lines.append(f"| {label} p50 / p95 | {cells[0]} | {cells[1]} |")
    lines.append("")
    for name, metrics in zip(names, (left, right), strict=True):
        misses = ", ".join(
            f"`{row['family']}` ({row['count']})" for row in metrics["issues"]["misses"][:3]
        )
        lines.extend([f"**{name} top missed families** — {misses or 'none'}.", ""])
    return lines


def _revision(report: dict) -> str:
    if report.get("benchmark_revision") == "tier0-step3":
        return "Step 3 Hardened Tier-0"
    return f"v{report['environment']['jrx_version']}"


def render_markdown(report: dict, baseline: dict | None = None) -> str:
    environment = report["environment"]
    metrics = report["evaluation"]["splits"]["eval"]
    benign, attack, issues = (metrics[name] for name in ("benign", "attack", "issues"))
    lines = [
        f"# jrx {_revision(report)} deterministic benchmark",
        "",
        "This benchmark measures **Tier-0 deterministic rules only**, with no semantic model.",
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
        "python -B -m benchmarks.run --backend deterministic --verify-hashes --out benchmarks/results/v0.2.0-step3-deterministic.json --render-md benchmarks/RESULTS.md --baseline benchmarks/results/v0.2.0-deterministic.json",
        "```",
        "",
        *(_comparison(report, baseline) if baseline is not None else []),
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
    lower, upper = delta["newcombe_95"]
    lines.extend(
        [
            "",
            f"Clean minus obfuscated recall was **{delta['clean_minus_obfuscated'] * 100:+.2f} pp** "
            f"(Newcombe 95% interval [{lower * 100:+.2f}, {upper * 100:+.2f}] pp).",
            "The suites contain different cases and attack mixes, so this unpaired difference",
            "combines obfuscation with other differences between the suites.",
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
        for label, mode in (
            ("Warm in-process", "warm_in_process"),
            ("Cold jrx CLI", "cold_cli"),
        ):
            timing = latency[mode]
            lines.append(
                f"| {label} | {timing['p50_ms']:.3f} | {timing['p95_ms']:.3f} "
                f"| {timing['p99_ms']:.3f} | {timing['peak_rss_mb']:.2f} |"
            )
        lines.extend(
            [
                "",
                "Warm peak RSS covers the runner process, including imports and loaded fixtures.",
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
