"""Golden fixture runner for policy regression testing.

Loads YAML fixtures from a directory, runs each through the demo evaluator
and deterministic policy engine, and compares actual vs expected decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .config import ReflexConfig, load_config
from .evaluator import DemoEvaluator, DemoSemanticEvaluator, evaluate_context
from .models import EvaluationContext, ProposedAction, RiskInfo, SemanticSignals

_PKG_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "policy_golden"
_REPO_FIXTURES = (
    Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "policy_golden"
)
DEFAULT_FIXTURES_DIR = _PKG_FIXTURES if _PKG_FIXTURES.exists() else _REPO_FIXTURES


class MockSemanticEvaluator:
    """Mock semantic evaluator for testing exact signal values at thresholds."""

    def __init__(
        self,
        mocked_signals: dict[str, float],
        fallback: DemoSemanticEvaluator,
        config: ReflexConfig,
    ) -> None:
        self.mocked_signals = mocked_signals
        self.fallback = fallback
        self.config = config

    def evaluate(self, context: EvaluationContext) -> SemanticSignals:
        base = self.fallback.evaluate(context)
        signals = dict(base.probabilities)
        signals.update(self.mocked_signals)

        strong = self.config.thresholds.strong
        review = self.config.thresholds.review

        if any(
            signals.get(name, 0.0) >= strong
            for name in ("destructive", "secret_exposure", "prompt_injection", "fail_open")
        ):
            risk_choice = "high"
            score = 2.0
        elif max(signals.values(), default=0.0) >= review:
            risk_choice = "medium"
            score = 1.0
        else:
            risk_choice = "low"
            score = 0.0

        return SemanticSignals(
            probabilities=signals,
            risk=RiskInfo(choice=risk_choice, score=score, confidence=0.95),
            source="demo",
        )


@dataclass(frozen=True)
class FixtureCase:
    """A single golden fixture test case loaded from YAML."""

    name: str
    category: str
    description: str
    context: EvaluationContext
    expected_decision: str
    mocked_jev_signals: dict[str, float] | None = None
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FixtureCase:
        """Parse a YAML fixture dict into a FixtureCase."""

        ctx_data = data.get("context", {})
        context = EvaluationContext(
            repository=ctx_data.get("repository", "test-repo"),
            repository_root=ctx_data.get("repository_root", "/test/repo"),
            working_directory=ctx_data.get("working_directory", "/test/repo"),
            user_task=ctx_data.get("task", ""),
            proposed_action=ProposedAction(command=ctx_data.get("command", "")),
            external_content=ctx_data.get("external_content", ""),
            recent_context=ctx_data.get("recent_context", ""),
            changed_files=ctx_data.get("changed_files", []),
            git_diff=ctx_data.get("git_diff", ""),
        )
        mocked = data.get("mocked_jev_signals") or data.get("signals")
        mocked_signals = {str(k): float(v) for k, v in mocked.items()} if mocked else None
        return cls(
            name=data["name"],
            category=data.get("category", "unknown"),
            description=data.get("description", ""),
            context=context,
            expected_decision=data["expected_decision"],
            mocked_jev_signals=mocked_signals,
            notes=data.get("notes", ""),
        )


@dataclass
class FixtureResult:
    """Result of running a single fixture case."""

    name: str
    category: str
    expected: str
    actual: str
    passed: bool
    triggered_rules: list[str] = field(default_factory=list)
    signals: dict[str, float] = field(default_factory=dict)

    def diff_summary(self) -> str:
        if self.passed:
            return ""
        return f"expected {self.expected} != actual {self.actual}"


@dataclass
class RunReport:
    """Summary of a full fixture suite run."""

    results: list[FixtureResult]
    config_path: str | None
    total: int
    passed: int
    failed: int
    failures: list[FixtureResult]

    @property
    def all_passed(self) -> bool:
        return self.failed == 0

    def summary_table(self) -> str:
        """Format a human-readable pass/fail table."""

        lines: list[str] = []
        header = f"{'Case':<35s} {'Category':<20s} {'Expected':<10s} {'Actual':<10s} {'Status':<8s} {'Diff'}"
        lines.append(header)
        lines.append("-" * 110)
        for r in self.results:
            status = "✓ PASS" if r.passed else "✗ FAIL"
            diff = "" if r.passed else r.diff_summary()
            lines.append(
                f"{r.name:<35s} {r.category:<20s} {r.expected:<10s} {r.actual:<10s} {status:<8s} {diff}"
            )
        lines.append("-" * 110)
        lines.append(f"Total: {self.total}  Passed: {self.passed}  Failed: {self.failed}")
        if self.failures:
            lines.append("")
            lines.append("Failures:")
            for f in self.failures:
                lines.append(f"  ✗ {f.name}: {f.diff_summary()}")
                if f.triggered_rules:
                    lines.append(f"    triggered rules: {', '.join(f.triggered_rules)}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "all_passed": self.all_passed,
            "config_path": self.config_path,
            "results": [
                {
                    "name": r.name,
                    "category": r.category,
                    "expected": r.expected,
                    "actual": r.actual,
                    "passed": r.passed,
                    "diff": r.diff_summary(),
                    "triggered_rules": r.triggered_rules,
                }
                for r in self.results
            ],
        }


def load_fixtures(fixtures_dir: Path | None = None) -> list[FixtureCase]:
    """Load all YAML fixtures from a directory, sorted by filename."""

    directory = fixtures_dir or DEFAULT_FIXTURES_DIR
    if not directory.is_dir():
        raise FileNotFoundError(f"Fixtures directory not found: {directory}")

    cases: list[FixtureCase] = []
    for path in sorted(directory.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if data is None:
            continue
        if isinstance(data, list):
            for item in data:
                cases.append(FixtureCase.from_dict(item))
        else:
            cases.append(FixtureCase.from_dict(data))
    if not cases:
        raise FileNotFoundError(f"No YAML fixture files found in: {directory}")
    return cases


def run_fixtures(
    fixtures_dir: Path | None = None,
    config: ReflexConfig | None = None,
    config_path: Path | None = None,
) -> RunReport:
    """Run all fixture cases and return the results report."""

    if config is None:
        config = load_config(config_path) if config_path else ReflexConfig()
    demo_evaluator = DemoEvaluator(config)
    cases = load_fixtures(fixtures_dir)

    results: list[FixtureResult] = []
    for case in cases:
        if case.mocked_jev_signals is not None:
            mock_semantic = MockSemanticEvaluator(
                case.mocked_jev_signals,
                fallback=demo_evaluator.semantic,
                config=config,
            )
            result = evaluate_context(
                case.context,
                config=config,
                semantic_evaluator=mock_semantic,
                samples=config.jev.samples,
                aggregation=config.jev.aggregation,
                skip_jev_on_hard=False,
            )
        else:
            result = demo_evaluator.evaluate(case.context)
        passed = result.decision == case.expected_decision
        results.append(
            FixtureResult(
                name=case.name,
                category=case.category,
                expected=case.expected_decision,
                actual=result.decision,
                passed=passed,
                triggered_rules=list(result.triggered_rules),
                signals={k: round(v, 4) for k, v in result.signals.items() if v > 0.05},
            )
        )

    failures = [r for r in results if not r.passed]
    return RunReport(
        results=results,
        config_path=str(config_path) if config_path else None,
        total=len(results),
        passed=len(results) - len(failures),
        failed=len(failures),
        failures=failures,
    )
