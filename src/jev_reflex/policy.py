"""Pure deterministic policy decisions over local findings and JEV probabilities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .config import ReflexConfig
from .models import Decision, DeterministicFinding, RiskChoice


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    triggered_rules: tuple[str, ...]
    reasons: tuple[str, ...]


def _probability(signals: Mapping[str, float], name: str) -> float:
    """Read one semantic signal, including the backwards-compatible aliases."""

    value = float(signals.get(name, 0.0))
    if name == "wrong_repo":
        value = max(value, float(signals.get("wrong_repo_semantic", 0.0)))
    return value


def _boundary_rule(name: str, threshold_name: str, threshold: float) -> str:
    return f"BOUNDARY_UNCERTAIN: {name} near {threshold_name} threshold {threshold:.2f}"


class DeterministicPolicyEngine:
    """Apply explicit policy; this class performs no network calls or random work."""

    def decide(
        self,
        deterministic_findings: Sequence[DeterministicFinding],
        jev_signals: Mapping[str, float],
        *,
        risk_choice: RiskChoice = "low",
        risk_confidence: float | None = None,
        config: ReflexConfig,
        degraded: bool = False,
    ) -> PolicyDecision:
        strong = config.thresholds.strong
        review = config.thresholds.review
        triggered: list[str] = []
        reasons: list[str] = []

        # Local hard checks always outrank semantic probabilities, including in
        # conservative boundary mode.
        for finding in deterministic_findings:
            if finding.triggered and finding.blocking:
                rule = f"{finding.check}:{finding.reason_code}"
                triggered.append(rule)
                reasons.append(f"hard deterministic rule: {rule}")
        if triggered:
            if _probability(jev_signals, "human_review") >= strong:
                review_rule = f"human_review >= {strong:.2f}"
                triggered.append(review_rule)
                reasons.append("human review strongly recommended")
            return PolicyDecision(
                "HOLD", tuple(dict.fromkeys(triggered)), tuple(dict.fromkeys(reasons))
            )

        # Non-blocking medium/high local findings still require attention when
        # JEV is disabled or unavailable. They cannot silently become ALLOW just
        # because there is no semantic risk classification to attach to them.
        for finding in deterministic_findings:
            if finding.triggered and finding.severity in {"medium", "high"}:
                rule = f"{finding.check}:{finding.reason_code}"
                triggered.append(rule)
                reasons.append(f"deterministic review finding: {rule}")

        boundary_uncertain: list[str] = []
        if config.stability_policy.mode == "conservative":
            margin = config.stability.boundary_margin
            if margin > 0:
                for name, value in jev_signals.items():
                    probability = float(value)
                    if abs(probability - strong) <= margin:
                        boundary_uncertain.append(_boundary_rule(name, "hold", strong))
                    elif abs(probability - review) <= margin:
                        boundary_uncertain.append(_boundary_rule(name, "review", review))
                triggered.extend(boundary_uncertain)
                reasons.extend(
                    f"semantic probability is near a policy boundary: {rule}"
                    for rule in boundary_uncertain
                )

        semantic_hold: list[str] = []
        for name in config.hold_on:
            probability = _probability(jev_signals, name)
            near_hold = (
                config.stability_policy.mode == "conservative"
                and config.stability.boundary_margin > 0
                and abs(probability - strong) <= config.stability.boundary_margin
            )
            if probability >= strong and not near_hold:
                semantic_hold.append(f"{name} >= {strong:.2f}")

        if semantic_hold:
            reasons.extend(f"hard semantic rule: {rule}" for rule in semantic_hold)
            triggered.extend(semantic_hold)
            return PolicyDecision(
                "HOLD", tuple(dict.fromkeys(triggered)), tuple(dict.fromkeys(reasons))
            )

        # Signals in the uncertainty/review band are intentionally handled by
        # ordinary code, never by a model-generated final decision.
        for name, value in jev_signals.items():
            probability = float(value)
            if review <= probability < strong:
                rule = f"{name} between {review:.2f} and {strong:.2f}"
                triggered.append(rule)
                reasons.append(f"review signal: {rule}")
            elif name in config.review_on and probability >= strong:
                rule = f"{name} >= {strong:.2f}"
                triggered.append(rule)
                reasons.append(f"strong review signal: {rule}")
            elif probability >= strong and name not in config.hold_on:
                rule = f"{name} >= {strong:.2f} (strong non-hold signal)"
                triggered.append(rule)
                reasons.append(f"strong semantic signal requires review: {name}")

        if risk_choice in {"medium", "high"}:
            triggered.append(f"risk_level == {risk_choice}")
            reasons.append(f"overall risk is {risk_choice}")

        if risk_confidence is not None and risk_confidence < review:
            rule = f"risk_confidence < {review:.2f}"
            triggered.append(rule)
            reasons.append("JEV risk classification is uncertain")

        if float(jev_signals.get("human_review", 0.0)) >= strong:
            rule = f"human_review >= {strong:.2f}"
            triggered.append(rule)
            reasons.append("human review strongly recommended")

        if config.mode == "review":
            triggered.append("mode == review")
            reasons.append("review-only mode is enabled")

        if degraded:
            triggered.append("evaluation_unavailable")
            reasons.append("JEV evaluation was unavailable; fail-safe review is required")

        if triggered:
            return PolicyDecision(
                "REVIEW", tuple(dict.fromkeys(triggered)), tuple(dict.fromkeys(reasons))
            )
        return PolicyDecision("ALLOW", (), ())


def decide(
    deterministic_findings: Sequence[DeterministicFinding],
    jev_signals: Mapping[str, float],
    config: ReflexConfig,
    *,
    risk_choice: RiskChoice = "low",
    risk_confidence: float | None = None,
    degraded: bool = False,
) -> PolicyDecision:
    """Pure function used by the evaluator, stability runner, and benchmarks."""

    return DeterministicPolicyEngine().decide(
        deterministic_findings,
        jev_signals,
        risk_choice=risk_choice,
        risk_confidence=risk_confidence,
        config=config,
        degraded=degraded,
    )


class Policy(DeterministicPolicyEngine):
    """Compatibility facade for the original ``Policy().decide(signals, ...)`` API."""

    def decide(
        self,
        signals_or_findings: Mapping[str, float] | Sequence[DeterministicFinding] = (),
        jev_signals: Mapping[str, float] | None = None,
        *,
        risk_choice: RiskChoice = "low",
        risk_confidence: float | None = None,
        config: ReflexConfig,
        deterministic_findings: Sequence[DeterministicFinding] = (),
        degraded: bool = False,
    ) -> PolicyDecision:
        if isinstance(signals_or_findings, Mapping):
            findings = deterministic_findings
            signals = signals_or_findings
        else:
            findings = signals_or_findings
            signals = jev_signals or {}
        return super().decide(
            findings,
            signals,
            risk_choice=risk_choice,
            risk_confidence=risk_confidence,
            config=config,
            degraded=degraded,
        )


# Public descriptive name for new integrations; ``Policy`` remains the original
# compatibility facade.
PolicyEngine = DeterministicPolicyEngine


def execution_allowed(decision: Decision, *, mode: str, degraded: bool = False) -> bool:
    """Return whether the requested CLI mode permits the side effect."""

    if mode == "advisory":
        return True
    if degraded:
        # A missing or malformed judge cannot silently pass an execution boundary.
        return False
    if mode == "review":
        return decision == "ALLOW"
    # Enforce mode blocks HOLD while allowing a non-degraded REVIEW to reach the
    # agent's normal permission system.
    return decision != "HOLD"
