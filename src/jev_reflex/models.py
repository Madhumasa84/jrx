"""Public data contracts used by evaluators, policies, and adapters."""

from __future__ import annotations

import math
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .redaction import redact_obj, redact_text

Decision = Literal["ALLOW", "REVIEW", "HOLD"]
RiskChoice = Literal["low", "medium", "high"]
FindingSeverity = Literal["low", "medium", "high"]


def _validate_probability(value: float) -> float:
    """Keep model output inside the range expected by the policy engine."""

    value = float(value)
    if not math.isfinite(value) or value < 0.0 or value > 1.0:
        raise ValueError("probability must be a finite number between 0 and 1")
    return value


class ProposedAction(BaseModel):
    """A tool action in a form that does not require shell reparsing."""

    model_config = ConfigDict(extra="forbid")

    type: str = "shell_command"
    command: str | None = None
    argv: list[str] = Field(default_factory=list)
    input: Any = None
    description: str | None = None

    @field_validator("argv", mode="before")
    @classmethod
    def _coerce_argv(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list | tuple):
            raise ValueError("argv must be a list")
        return [str(item) for item in value]

    def display(self) -> str:
        """Return a compact display value; callers redact it before showing it."""

        if self.argv:
            # Import lazily so the model remains usable in minimal embedding contexts.
            import shlex

            return shlex.join(self.argv)
        if self.command:
            return self.command
        if self.input is not None:
            return f"{self.type} action"
        return self.type


class EvaluationContext(BaseModel):
    """Small, explicit state passed to an evaluator."""

    model_config = ConfigDict(extra="forbid")

    user_task: str = ""
    repository: str = ""
    repository_root: str = ""
    working_directory: str = ""
    proposed_action: ProposedAction
    changed_files: list[str] = Field(default_factory=list)
    git_diff: str = ""
    test_results: str = ""
    recent_context: str = ""
    external_content: str = ""

    @field_validator("changed_files", mode="before")
    @classmethod
    def _coerce_changed_files(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list | tuple):
            raise ValueError("changed_files must be a list")
        return [str(item) for item in value]

    def to_jev_state(self) -> dict[str, Any]:
        """Return the intentionally narrow state schema sent to System One."""

        return {
            "user_task": self.user_task,
            "repository": self.repository,
            "repository_root": self.repository_root,
            "working_directory": self.working_directory,
            "proposed_action": self.proposed_action.model_dump(mode="json"),
            "changed_files": list(self.changed_files),
            "git_diff": self.git_diff,
            "test_results": self.test_results,
            "recent_context": self.recent_context,
            "external_content": self.external_content,
        }


class RiskInfo(BaseModel):
    """Structured risk output from the choice and score primitives."""

    model_config = ConfigDict(extra="forbid")

    choice: RiskChoice
    score: float | None = None
    confidence: float | None = None

    @field_validator("score")
    @classmethod
    def _validate_score(cls, value: float | None) -> float | None:
        if value is None:
            return None
        value = float(value)
        if not math.isfinite(value) or value < 0.0 or value > 2.0:
            raise ValueError("risk score must be between 0 and 2")
        return value

    @field_validator("confidence")
    @classmethod
    def _validate_confidence(cls, value: float | None) -> float | None:
        if value is None:
            return None
        return _validate_probability(value)


class DeterministicFinding(BaseModel):
    """A reproducible local check result with no model reasoning attached."""

    model_config = ConfigDict(extra="forbid")

    check: str
    triggered: bool
    severity: FindingSeverity
    reason_code: str
    blocking: bool = False


class SemanticSignals(BaseModel):
    """JEV or offline semantic output before deterministic policy is applied."""

    model_config = ConfigDict(extra="forbid")

    probabilities: dict[str, float] = Field(default_factory=dict)
    risk: RiskInfo
    source: Literal["jev", "demo", "none", "broker/live", "broker/unavailable"] = "jev"
    degraded: bool = False
    warnings: list[str] = Field(default_factory=list)

    @field_validator("probabilities")
    @classmethod
    def _validate_probabilities(cls, value: dict[str, float]) -> dict[str, float]:
        return {
            str(name): _validate_probability(probability) for name, probability in value.items()
        }


class EvaluationResult(BaseModel):
    """Safe-to-display result of a probabilistic evaluation and policy pass."""

    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    decision: Decision
    risk: RiskInfo
    signals: dict[str, float] = Field(default_factory=dict)
    triggered_rules: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    deterministic_findings: list[DeterministicFinding] = Field(default_factory=list)
    semantic_source: Literal["jev", "demo", "none", "broker/live", "broker/unavailable"] = "jev"
    samples: int = Field(default=1, ge=1)
    aggregation: Literal["median", "mean", "max"] | None = None
    degraded: bool = False
    action: str | None = None

    @field_validator("signals")
    @classmethod
    def _validate_signals(cls, value: dict[str, float]) -> dict[str, float]:
        return {
            str(name): _validate_probability(probability) for name, probability in value.items()
        }

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize only the public decision contract, never raw evaluator state."""

        value = redact_obj(self.model_dump(mode="json", exclude_none=True))
        return value if isinstance(value, dict) else {}

    def reason_summary(self) -> str:
        """Produce a short reason suitable for a hook permission message."""

        parts = self.triggered_rules or self.reasons or self.warnings
        if not parts:
            return f"JEV Reflex decision: {self.decision}."
        return redact_text(f"JEV Reflex decision: {self.decision}. " + "; ".join(parts[:4]))
