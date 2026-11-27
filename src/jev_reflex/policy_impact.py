"""Aggregate policy replay results for sharing with reviewers."""

from dataclasses import dataclass
from importlib import import_module
from pathlib import Path

from .config import ReflexConfig
from .policy_lint import lint_policy
from .policy_rollout import simulate
from .serialization import read_config_bytes, safe_yaml_load


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
    # Decision classes the candidate's mode runs and the baseline's blocked. A mode
    # downgrade relaxes these even when every replayed label stays the same.
    enforcement_relaxations: tuple[str, ...] = ()

    @property
    def relaxations(self) -> int:
        return self.new_allows + self.changes.get("HOLD_to_REVIEW", 0)

    def summary(self) -> str:
        # At most 15 characters per count keeps even the prefixed failure
        # status under 140 characters; the "enforcement relaxed" marker takes
        # 21 of them, so counts get 10 when it is shown. The Markdown report
        # has exact counts.
        digits = 10 if self.enforcement_relaxations else 15

        def count(value: int) -> str:
            return str(value) if value < 10**digits else f"1e{digits}+"

        parts = [
            f"{count(self.replayed)}/{count(self.total)} replayed",
            f"{count(self.new_allows)} new ALLOW",
        ]
        if hold_review := self.changes.get("HOLD_to_REVIEW", 0):
            parts.append(f"{count(hold_review)} HOLD->REVIEW")
        parts.append(f"{count(self.new_holds)} new HOLD")
        if self.enforcement_relaxations:
            parts.append("enforcement relaxed")
        return ", ".join(parts)

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
        if self.enforcement_relaxations:
            lines += [
                "",
                "The candidate's mode lets these decisions run where the baseline blocked "
                "them: " + ", ".join(self.enforcement_relaxations) + ".",
            ]
        return "\n".join(lines)


def _read_policy(path: Path) -> ReflexConfig:
    raw = read_config_bytes(path)
    data = safe_yaml_load(raw)
    if lint_policy(raw)["errors"]:
        raise ValueError("Invalid policy")
    return ReflexConfig.model_validate(data)


def impact_report(
    audit: Path, baseline: Path, candidate: Path, *, public_key: Path | None = None
) -> PolicyImpactReport:
    # Load parser dependencies before reading either policy. Replay can then
    # validate schemas without opening package files under the input boundary.
    import_module("._yaml_loader", __package__)
    import_module("jsonschema")
    report = simulate(audit, _read_policy(baseline), _read_policy(candidate), public_key=public_key)
    return PolicyImpactReport(
        total=report["total"],
        replayed=report["replayed"],
        new_allows=report["new_allows"],
        new_holds=report["new_holds"],
        skipped_legacy=report["skipped_legacy"],
        skipped_policy_mismatch=report["skipped_policy_mismatch"],
        skipped_decision_mismatch=report["skipped_decision_mismatch"],
        changes=report["changes"],
        enforcement_relaxations=tuple(report["enforcement_relaxations"]),
    )
