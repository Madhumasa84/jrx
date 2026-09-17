"""Human-readable and JSON-safe terminal presentation."""

from __future__ import annotations

import json
from typing import Any

from .evaluator import JUDGMENT_NAMES
from .models import EvaluationResult
from .redaction import redact_text
from .stability.metrics import StabilityReport


def _bar(probability: float, width: int = 20) -> str:
    count = max(0, min(width, round(probability * width)))
    return "█" * count or "·"


def format_human(result: EvaluationResult, *, title: str = "JEV Reflex") -> str:
    action = redact_text(result.action) if result.action else "(not specified)"
    lines = [title, "", "Action:", f"  {action}", ""]
    lines.extend(["HARD RULES", ""])
    label_width = (
        max(len(finding.check) for finding in result.deterministic_findings)
        if result.deterministic_findings
        else 1
    )
    for finding in result.deterministic_findings:
        state = "TRIGGERED" if finding.triggered else "clear"
        suffix = f" ({finding.reason_code})" if finding.triggered else ""
        lines.append(f"  {finding.check:<{label_width}}  {state}{suffix}")

    lines.extend(["", "JEV SIGNALS"])
    label_width = max(len(name) for name in JUDGMENT_NAMES)
    for name in JUDGMENT_NAMES:
        probability = result.signals.get(name, 0.0)
        lines.append(f"  {name:<{label_width}}  {probability:0.2f}  {_bar(probability)}")

    lines.extend(
        [
            "",
            "Source: "
            + (
                "LIVE JEV VIA BROKER"
                if result.semantic_source == "broker/live" and not result.degraded
                else result.semantic_source
            ),
            f"Samples: {result.samples}"
            + (f" (aggregation: {result.aggregation})" if result.aggregation else ""),
            f"Estimated JEV requests: {result.samples if result.semantic_source in {'jev', 'broker/live'} else 0}",
            "",
            "POLICY",
        ]
    )
    if result.triggered_rules or result.reasons:
        for reason in result.triggered_rules or result.reasons:
            lines.append(f"  {reason}")
    else:
        lines.append("  no policy rule matched")
    lines.extend(["", "FINAL", f"  Risk: {result.risk.choice.upper()}", f"  {result.decision}"])
    if result.warnings:
        lines.extend(["", "WARNINGS"])
        for warning in result.warnings:
            lines.append(f"  {redact_text(warning)}")
    lines.extend(["", f"Decision ID: {result.decision_id}"])
    return "\n".join(lines)


def format_json(result: EvaluationResult) -> str:
    return json.dumps(result.to_public_dict(), indent=2, sort_keys=True)


def hook_context(result: EvaluationResult) -> str:
    """Return a concise, non-secret explanation for agent hook context."""

    parts = [result.reason_summary()]
    if result.semantic_source == "broker/live" and not result.degraded:
        parts.append("LIVE JEV VIA BROKER.")
    elif result.degraded:
        parts.append("Semantic evaluation unavailable; degraded fail-safe result.")
    if result.risk.choice:
        parts.append(f"Risk level: {result.risk.choice}.")
    return redact_text(" ".join(parts))


def format_compare(
    deterministic: EvaluationResult,
    with_jev: EvaluationResult,
    *,
    json_output: bool = False,
) -> str:
    value = {
        "deterministic_only": deterministic.to_public_dict(),
        "with_jev": with_jev.to_public_dict(),
        "decision_changed": deterministic.decision != with_jev.decision,
    }
    if json_output:
        return json.dumps(value, indent=2, sort_keys=True)
    lines = [
        "JEV Reflex comparison",
        "",
        f"Deterministic checks only: {deterministic.decision}",
        f"Deterministic + JEV:       {with_jev.decision}",
    ]
    if deterministic.decision != with_jev.decision:
        lines.extend(["", "Semantic contribution:"])
        for rule in with_jev.triggered_rules:
            if rule not in deterministic.triggered_rules:
                lines.append(f"  {rule}")
        for name, probability in with_jev.signals.items():
            if probability >= 0.70 and deterministic.signals.get(name, 0.0) < 0.70:
                lines.append(f"  {name} probability = {probability:.2f}")
    lines.extend(["", "JEV does not own the final decision; policy code does."])
    return "\n".join(lines)


def format_stability(report: StabilityReport, *, json_output: bool = False) -> str:
    if json_output:
        return json.dumps(report.to_dict(), indent=2, sort_keys=True)
    lines = [
        "Decision Stability",
        "",
        f"Runs: {report.runs}",
        "",
        f"ALLOW:  {report.decisions['ALLOW']}",
        f"REVIEW: {report.decisions['REVIEW']}",
        f"HOLD:   {report.decisions['HOLD']}",
        "",
        f"Dominant decision: {report.dominant_decision}",
        f"Decision consistency: {report.decision_consistency:.1%}",
        f"Decision flip rate: {report.decision_flip_rate:.1%}",
        f"Decision flips: {report.runs - max(report.decisions.values())} / {report.runs}",
        f"Degraded runs: {report.degraded_runs}",
        "",
        "Signal statistics:",
    ]
    for name, stats in report.signals.items():
        lines.extend(
            [
                f"  {name}",
                f"    mean: {stats.mean:.3f}  std: {stats.std:.3f}",
                f"    min:  {stats.min:.3f}  max: {stats.max:.3f}",
                f"    threshold: {stats.threshold:.2f}  crossings: "
                f"{stats.threshold_crossings} / {report.runs} ({stats.threshold_crossing_rate:.1%})",
            ]
        )
    lines.append(
        f"High-confidence disagreement rate: {report.high_confidence_disagreement_rate:.1%}"
    )
    return "\n".join(lines)


def schema_example() -> dict[str, Any]:
    """Expose a small schema-shaped sample for tests and documentation tooling."""

    return {
        "decision": "ALLOW",
        "risk": {"choice": "low"},
        "signals": {name: 0.0 for name in JUDGMENT_NAMES},
        "triggered_rules": [],
    }
