"""Configuration loading and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

Mode = Literal["advisory", "review", "enforce"]

DEFAULT_HOLD_ON = [
    "destructive",
    "secret_exposure",
    "irreversible",
    "prompt_injection",
    "wrong_repo",
    "wrong_repo_semantic",
    "fail_open",
]

DEFAULT_REVIEW_ON = [
    "security_sensitive",
    "concurrency_sensitive",
    "persistence_sensitive",
    "backwards_compatibility",
    "human_review",
]


class ThresholdConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    strong: float = 0.90
    review: float = 0.70
    # ``hold`` is the clearer name in the new configuration; ``strong`` remains
    # for compatibility with the first release.
    hold: float | None = None

    @model_validator(mode="after")
    def _validate_thresholds(self) -> ThresholdConfig:
        if self.hold is not None:
            self.strong = self.hold
        if not 0.0 <= self.review <= 1.0:
            raise ValueError("review threshold must be between 0 and 1")
        if not 0.0 <= self.strong <= 1.0:
            raise ValueError("strong threshold must be between 0 and 1")
        if self.strong <= self.review:
            raise ValueError("strong threshold must be greater than review threshold")
        return self


class ContextConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    include_git_diff: bool = True
    include_changed_files: bool = True
    include_tests: bool = True
    max_diff_chars: int = 30_000
    max_context_chars: int = 50_000

    @model_validator(mode="after")
    def _validate_sizes(self) -> ContextConfig:
        if self.max_diff_chars < 1 or self.max_context_chars < 1:
            raise ValueError("context size limits must be positive")
        return self


class PrivacyConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    redact_secrets: bool = True
    store_requests: bool = False


class CalibrationConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    path: str | None = None


class JEVConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    samples: int = 1
    aggregation: Literal["median", "mean", "max"] = "median"
    transport: Literal["direct", "broker"] = "direct"
    socket: str = "~/.jev-reflex/reflex.sock"
    connect_timeout: float = Field(default=1.0, gt=0, le=10)
    request_timeout: float = Field(default=25.0, gt=0, le=300)
    api_timeout: float = Field(default=20.0, gt=0, le=240)

    @model_validator(mode="after")
    def _validate_samples(self) -> JEVConfig:
        if self.samples < 1 or self.samples > 1_000:
            raise ValueError("JEV samples must be between 1 and 1000")
        return self


class StabilityConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    boundary_margin: float = 0.0

    @model_validator(mode="after")
    def _validate_boundary_margin(self) -> StabilityConfig:
        if not 0.0 <= self.boundary_margin <= 0.5:
            raise ValueError("boundary margin must be between 0 and 0.5")
        return self


class StabilityPolicyConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    mode: Literal["strict", "conservative", "majority"] = "strict"


class ReflexConfig(BaseModel):
    """Validated user configuration. Untrusted evaluated state never changes this object."""

    model_config = ConfigDict(extra="ignore")

    mode: Mode = "advisory"
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    hold_on: list[str] = Field(default_factory=lambda: list(DEFAULT_HOLD_ON))
    review_on: list[str] = Field(default_factory=lambda: list(DEFAULT_REVIEW_ON))
    context: ContextConfig = Field(default_factory=ContextConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)
    calibration: CalibrationConfig = Field(default_factory=CalibrationConfig)
    jev: JEVConfig = Field(default_factory=JEVConfig)
    stability: StabilityConfig = Field(default_factory=StabilityConfig)
    stability_policy: StabilityPolicyConfig = Field(default_factory=StabilityPolicyConfig)

    @model_validator(mode="after")
    def _normalize_rule_names(self) -> ReflexConfig:
        self.hold_on = [str(name) for name in self.hold_on]
        self.review_on = [str(name) for name in self.review_on]
        return self


def load_config(path: Path | None = None, *, mode_override: Mode | None = None) -> ReflexConfig:
    """Load ``reflex.yaml`` when present, otherwise return safe defaults."""

    config_path = path or Path("reflex.yaml")
    data: object = {}
    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle)
        except yaml.YAMLError:
            raise ValueError("configuration YAML is invalid") from None
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ValueError("configuration root must be a YAML mapping")
        data = loaded

    config = ReflexConfig.model_validate(data)
    if mode_override is not None:
        config = config.model_copy(update={"mode": mode_override})
    return config
