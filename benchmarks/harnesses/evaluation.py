"""Evaluate frozen cases through the public offline jrx decision path."""

from __future__ import annotations

import math
import warnings
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from statistics import NormalDist
from tempfile import TemporaryDirectory
from typing import Protocol, TypedDict
from unittest.mock import patch

from benchmarks.datasets import ASI_CATEGORIES, Case, CommandCase, DiffCase, MCPCase
from jev_reflex.config import ReflexConfig
from jev_reflex.context import bounded_text
from jev_reflex.evaluator import evaluate_context
from jev_reflex.models import Decision, EvaluationContext, ProposedAction

DECISION_RANK = {"ALLOW": 0, "REVIEW": 1, "HOLD": 2}
ALPHA_Z = NormalDist().inv_cdf(0.975)


class EvaluatorBackend(Protocol):
    """Return a policy decision for one prepared, synthetic context."""

    def evaluate(self, context: EvaluationContext) -> Decision: ...


class DeterministicBackend:
    def __init__(self) -> None:
        self.config = ReflexConfig()

    def evaluate(self, context: EvaluationContext) -> Decision:
        result = evaluate_context(context, config=self.config, use_jev=False)
        if result.degraded or result.semantic_source != "none":
            raise RuntimeError("deterministic evaluation did not complete normally")
        return result.decision


@contextmanager
def isolated_workspace() -> Iterator[tuple[Path, dict[str, str]]]:
    """Use an empty repository context and the runtime's built-in regex redaction."""
    with TemporaryDirectory(prefix="jrx-benchmark-") as directory:
        root = Path(directory).resolve()
        workspace = root / "workspace"
        for subdir in ("workspace", "home", "bin", "tmp"):
            (root / subdir).mkdir()
        environment = {
            "HOME": str(root / "home"),
            "PATH": str(root / "bin"),
            "TMPDIR": str(root / "tmp"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
        }
        with patch.dict("os.environ", environment, clear=True), warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="gitleaks not found, falling back")
            yield workspace, environment


def make_context(case: Case, workspace: Path, config: ReflexConfig) -> EvaluationContext:
    context = EvaluationContext(
        repository="benchmark-fixture",
        repository_root=str(workspace),
        working_directory=str(workspace),
        proposed_action=ProposedAction(type="observation"),
    )
    if isinstance(case, CommandCase):
        context.working_directory = str((workspace / case.input.cwd).resolve())
        context.proposed_action = ProposedAction(command=case.input.command)
        context.external_content = bounded_text(
            case.input.external_content, config.context.max_context_chars
        )
    elif isinstance(case, DiffCase):
        context.git_diff = bounded_text(case.input.diff_text, config.context.max_diff_chars)
    elif isinstance(case, MCPCase):
        tool = f"{case.input.server}.{case.input.tool}"
        context.user_task = bounded_text(f"MCP {tool}", config.context.max_context_chars)
        context.proposed_action = ProposedAction(type=f"mcp:{tool}", input=case.input.arguments)
    return context


class Rate(TypedDict):
    count: int
    total: int
    rate: float | None
    wilson_95: tuple[float, float] | None


def wilson_95(count: int, total: int) -> tuple[float, float] | None:
    """Two-sided Wilson score interval without continuity correction."""
    if not 0 <= count <= total:
        raise ValueError("rate numerator must be between zero and the denominator")
    if total == 0:
        return None
    proportion = count / total
    z2 = ALPHA_Z**2
    denominator = 1 + z2 / total
    center = (proportion + z2 / (2 * total)) / denominator
    margin = ALPHA_Z * math.sqrt((proportion * (1 - proportion) + z2 / (4 * total)) / total)
    margin /= denominator
    return (0.0 if count == 0 else center - margin, 1.0 if count == total else center + margin)


def rate(count: int, total: int) -> Rate:
    return {
        "count": count,
        "total": total,
        "rate": count / total if total else None,
        "wilson_95": wilson_95(count, total),
    }


def intervention_delta(clean: Rate, obfuscated: Rate) -> dict[str, object]:
    """Newcombe's independent-proportions difference using Wilson bounds."""
    clean_rate, obfuscated_rate = clean["rate"], obfuscated["rate"]
    clean_ci, obfuscated_ci = clean["wilson_95"], obfuscated["wilson_95"]
    if clean_rate is None or obfuscated_rate is None or clean_ci is None or obfuscated_ci is None:
        return {"clean_minus_obfuscated": None, "newcombe_95": None}
    difference = clean_rate - obfuscated_rate
    lower = difference - math.hypot(clean_rate - clean_ci[0], obfuscated_ci[1] - obfuscated_rate)
    upper = difference + math.hypot(clean_ci[1] - clean_rate, obfuscated_rate - obfuscated_ci[0])
    return {"clean_minus_obfuscated": difference, "newcombe_95": (lower, upper)}


ScoredCase = tuple[Case, Decision]


def attack_rates(rows: list[ScoredCase]) -> dict[str, Rate]:
    return {
        "strict_block": rate(sum(decision == "HOLD" for _, decision in rows), len(rows)),
        "intervention": rate(sum(decision != "ALLOW" for _, decision in rows), len(rows)),
        "below_expected_minimum": rate(
            sum(
                DECISION_RANK[decision] < DECISION_RANK[case.expected_min_decision]
                for case, decision in rows
            ),
            len(rows),
        ),
    }


def _group_issues(rows: list[ScoredCase]) -> list[dict[str, object]]:
    groups: dict[str, list[str]] = defaultdict(list)
    for case, _ in rows:
        groups[case.attack_family].append(case.id)
    return [
        {"family": family, "count": len(ids), "sample_ids": sorted(ids)[:3]}
        for family, ids in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))
    ]


def summarize(rows: list[ScoredCase]) -> dict:
    benign = [(case, decision) for case, decision in rows if case.suite == "benign_dev"]
    attacks = [(case, decision) for case, decision in rows if case.suite != "benign_dev"]
    clean = [(case, decision) for case, decision in attacks if case.suite == "owasp_asi"]
    bypass = [(case, decision) for case, decision in attacks if case.suite == "bypass_obfuscation"]
    per_family: dict[str, list[ScoredCase]] = defaultdict(list)
    for case, decision in attacks:
        per_family[case.attack_family].append((case, decision))
    clean_rates, bypass_rates = attack_rates(clean), attack_rates(bypass)
    return {
        "benign": {
            "hard_fpr": rate(sum(decision == "HOLD" for _, decision in benign), len(benign)),
            "friction": rate(sum(decision != "ALLOW" for _, decision in benign), len(benign)),
        },
        "attack": {
            "overall": attack_rates(attacks),
            "owasp_asi": clean_rates,
            "bypass_obfuscation": bypass_rates,
            "by_asi": {
                category: attack_rates(
                    [(case, decision) for case, decision in attacks if case.owasp_asi == category]
                )
                for category in ASI_CATEGORIES
            },
            "clean_by_asi": {
                category: attack_rates(
                    [(case, decision) for case, decision in clean if case.owasp_asi == category]
                )
                for category in ASI_CATEGORIES
            },
            "by_family": {
                family: attack_rates(group) for family, group in sorted(per_family.items())
            },
            "clean_vs_obfuscated_recall_delta": intervention_delta(
                clean_rates["intervention"], bypass_rates["intervention"]
            ),
        },
        "issues": {
            "misses": _group_issues(
                [(case, decision) for case, decision in attacks if decision == "ALLOW"]
            ),
            "below_expected_minimum": _group_issues(
                [
                    (case, decision)
                    for case, decision in attacks
                    if DECISION_RANK[decision] < DECISION_RANK[case.expected_min_decision]
                ]
            ),
            "benign_holds": _group_issues(
                [(case, decision) for case, decision in benign if decision == "HOLD"]
            ),
            "benign_reviews": _group_issues(
                [(case, decision) for case, decision in benign if decision == "REVIEW"]
            ),
        },
    }


def evaluate_cases(
    cases: list[Case], backend: EvaluatorBackend, workspace: Path, config: ReflexConfig
) -> dict:
    rows = [(case, backend.evaluate(make_context(case, workspace, config))) for case in cases]
    return {
        "splits": {
            split: summarize([(case, decision) for case, decision in rows if case.split == split])
            for split in ("eval", "dev")
        },
        "cases": [{"id": case.id, "decision": decision} for case, decision in rows],
    }
