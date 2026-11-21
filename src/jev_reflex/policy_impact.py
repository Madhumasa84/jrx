"""Aggregate policy replay results for sharing with reviewers."""

from dataclasses import dataclass
from pathlib import Path

from .config import ReflexConfig
from .policy_lint import lint_policy
from .policy_rollout import simulate
from .serialization import MAX_CONFIG_BYTES, safe_yaml_load


@dataclass(frozen=True)
class PolicyImpactReport:
    total: int
    replayed: int
    new_allows: int
    new_holds: int
    skipped_legacy: int
    skipped_policy_mismatch: int
    skipped_decision_mismatch: int
    changes: dict[str, int]

    def summary(self) -> str:
        return (
            f"{self.replayed}/{self.total} replayed, "
            f"{self.new_allows} new ALLOW, {self.new_holds} new HOLD"
        )

    def markdown(self) -> str:
        lines = [
            "### JRX policy impact",
            "",
            f"Replayed {self.replayed} of {self.total} policy decisions.",
            f"Skipped: {self.skipped_legacy} legacy, "
            f"{self.skipped_policy_mismatch} baseline mismatch, "
            f"{self.skipped_decision_mismatch} decision mismatch.",
            "",
            "| Decision change | Count |",
            "|---|---:|",
        ]
        lines.extend(
            f"| {transition.replace('_to_', ' → ')} | {count} |"
            for transition, count in self.changes.items()
        )
        return "\n".join(lines)


def _read_policy(path: Path) -> ReflexConfig:
    with path.open("rb") as stream:
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    data = safe_yaml_load(raw)
    if lint_policy(raw)["errors"]:
        raise ValueError("Invalid policy")
    return ReflexConfig.model_validate(data)


def impact_report(audit: Path, baseline: Path, candidate: Path) -> PolicyImpactReport:
    report = simulate(audit, _read_policy(baseline), _read_policy(candidate))
    return PolicyImpactReport(
        total=report["total"],
        replayed=report["replayed"],
        new_allows=report["new_allows"],
        new_holds=report["new_holds"],
        skipped_legacy=report["skipped_legacy"],
        skipped_policy_mismatch=report["skipped_policy_mismatch"],
        skipped_decision_mismatch=report["skipped_decision_mismatch"],
        changes=report["changes"],
    )
