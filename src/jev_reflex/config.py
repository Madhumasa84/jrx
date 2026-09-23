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


class AuditConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    path: str = "~/.jev-reflex/audit.log"
    rotate_mb: int = 100

    @model_validator(mode="after")
    def _validate_rotate_mb(self) -> AuditConfig:
        if self.rotate_mb < 1:
            raise ValueError("rotate_mb must be at least 1")
        return self


class SigningConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    require_signature: bool = False
    public_key_path: str | None = None
    private_key_path: str | None = None
    signer_type: str = "ed25519"  # "ed25519" or "cosign"


class PolicySourceConfig(BaseModel):
    """Configuration for fetching policy from a remote source."""

    model_config = ConfigDict(extra="ignore")

    type: Literal["git", "https", "local"] | None = None
    uri: str | None = None
    ref: str | None = None  # Git branch/ref
    poll_interval_seconds: int = 300  # Default 5 minutes
    pinned_signature_pubkey: str | None = None  # Public key for signature verification

    @model_validator(mode="after")
    def _validate_policy_source(self) -> PolicySourceConfig:
        if self.type is None:
            return self
        if self.uri is None:
            raise ValueError("policy_source.uri is required when policy_source.type is set")
        if self.type == "git" and self.ref is None:
            raise ValueError("policy_source.ref is required when policy_source.type is 'git'")
        if self.poll_interval_seconds < 10:
            raise ValueError("policy_source.poll_interval_seconds must be at least 10")
        if self.type is not None and self.pinned_signature_pubkey is None:
            raise ValueError("policy_source.pinned_signature_pubkey is required for remote policy")
        return self


class BootstrapConfig(BaseModel):
    """Bootstrap configuration for signature verification requirements."""

    model_config = ConfigDict(extra="ignore")

    require_signature: bool = False
    public_key_path: str | None = None
    signer_type: str = "ed25519"
    policy_source: PolicySourceConfig = Field(default_factory=PolicySourceConfig)
    rollout_state_path: str | None = None


class CalibrationConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    path: str | None = None


class BrokerTLSConfig(BaseModel):
    """Configuration for broker TLS transport."""

    model_config = ConfigDict(extra="ignore")

    listen_addr: str = "0.0.0.0:8443"
    cert_path: str
    key_path: str
    client_ca_path: str

    @model_validator(mode="after")
    def _validate_tls_paths(self) -> BrokerTLSConfig:
        if not self.cert_path:
            raise ValueError("broker_tls.cert_path is required")
        if not self.key_path:
            raise ValueError("broker_tls.key_path is required")
        if not self.client_ca_path:
            raise ValueError("broker_tls.client_ca_path is required")
        return self


class LoggingConfig(BaseModel):
    """Configuration for structured logging."""

    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    sink: Literal["stdout", "syslog", "webhook-url"] = "stdout"
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    webhook_url: str | None = None
    syslog_ident: str = "jrx"

    @model_validator(mode="after")
    def _validate_logging_config(self) -> LoggingConfig:
        if self.sink == "webhook-url" and not self.webhook_url:
            raise ValueError("webhook_url is required when sink='webhook-url'")
        return self


class RoleRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str
    actions: list[Literal["execute", "review", "view", "admin"]]
    repositories: list[str]
    environments: list[str]


class AccessConfig(BaseModel):
    """OIDC identity and scoped authorization for enterprise execution."""

    model_config = ConfigDict(extra="forbid")

    issuer: str
    audience: str
    jwks_uri: str
    environment: str
    roles_claim: str = "roles"
    rules: list[RoleRule]
    approval_db: str = "~/.jev-reflex/approvals.sqlite3"
    approval_ttl_seconds: int = 900
    production_environments: list[str] = Field(default_factory=lambda: ["production"])

    @model_validator(mode="after")
    def _validate_access(self) -> AccessConfig:
        if not self.issuer.startswith("https://") or not self.jwks_uri.startswith("https://"):
            raise ValueError("access issuer and jwks_uri must use HTTPS")
        if (
            not self.audience
            or not self.environment
            or not self.rules
            or not 1 <= self.approval_ttl_seconds <= 86400
        ):
            raise ValueError("access requires an audience, rules, and a valid approval TTL")
        return self


class JEVConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    samples: int = 1
    aggregation: Literal["median", "mean", "max"] = "median"
    transport: Literal["direct", "broker", "broker-tls"] = "direct"
    socket: str = "~/.jev-reflex/reflex.sock"
    connect_timeout: float = Field(default=1.0, gt=0, le=10)
    request_timeout: float = Field(default=25.0, gt=0, le=300)
    api_timeout: float = Field(default=20.0, gt=0, le=240)
    broker_tls: BrokerTLSConfig | None = None

    @model_validator(mode="after")
    def _validate_jev_config(self) -> JEVConfig:
        if self.samples < 1 or self.samples > 1_000:
            raise ValueError("JEV samples must be between 1 and 1000")
        if self.transport == "broker-tls" and self.broker_tls is None:
            raise ValueError("broker_tls configuration is required when transport='broker-tls'")
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


class PolicyConfig(BaseModel):
    """Execution policy controls and override options."""

    model_config = ConfigDict(extra="ignore")

    allow_hold_override: bool = False


class MCPToolRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: str
    name: str
    effect: Literal["read", "write", "destructive"]


class MCPGatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tools: list[MCPToolRule] = Field(default_factory=list)
    use_jev: bool = True
    timeout_seconds: float = Field(default=30.0, gt=0, le=3600)
    max_message_bytes: int = Field(default=1_048_576, ge=1024, le=16_777_216)


class SessionLimitsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    path: str = "~/.jev-reflex/sessions.sqlite3"
    max_tool_calls: int = Field(default=1000, ge=1)
    max_semantic_evaluations: int = Field(default=1000, ge=1)
    max_semantic_spend_usd: float = Field(default=10.0, gt=0, allow_inf_nan=False)
    reserved_cost_per_evaluation_usd: float = Field(default=0.01, gt=0, allow_inf_nan=False)
    max_elapsed_seconds: int = Field(default=3600, ge=1)
    max_execution_seconds: int = Field(default=300, ge=1)
    max_risky_attempts: int = Field(default=10, ge=1)


class ReflexConfig(BaseModel):
    """Validated user configuration. Untrusted evaluated state never changes this object."""

    model_config = ConfigDict(extra="ignore")

    mode: Mode = "advisory"
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    hold_on: list[str] = Field(default_factory=lambda: list(DEFAULT_HOLD_ON))
    review_on: list[str] = Field(default_factory=lambda: list(DEFAULT_REVIEW_ON))
    context: ContextConfig = Field(default_factory=ContextConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    signing: SigningConfig = Field(default_factory=SigningConfig)
    calibration: CalibrationConfig = Field(default_factory=CalibrationConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    access: AccessConfig | None = None
    mcp: MCPGatewayConfig = Field(default_factory=MCPGatewayConfig)
    session: SessionLimitsConfig = Field(default_factory=SessionLimitsConfig)
    jev: JEVConfig = Field(default_factory=JEVConfig)
    stability: StabilityConfig = Field(default_factory=StabilityConfig)
    stability_policy: StabilityPolicyConfig = Field(default_factory=StabilityPolicyConfig)

    @model_validator(mode="after")
    def _normalize_rule_names(self) -> ReflexConfig:
        self.hold_on = [str(name) for name in self.hold_on]
        self.review_on = [str(name) for name in self.review_on]
        return self


def load_config(
    path: Path | None = None, *, mode_override: Mode | None = None, scope: str | None = None
) -> ReflexConfig:
    """Load config, defaulting only when the implicit ``reflex.yaml`` is absent."""

    config_path = path if path is not None else Path("reflex.yaml")
    data: object = {}
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)
    except FileNotFoundError:
        if path is not None:
            raise FileNotFoundError(f"Configuration file not found: {config_path}") from None
    except yaml.YAMLError:
        raise ValueError("configuration YAML is invalid") from None
    else:
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ValueError("configuration root must be a YAML mapping")
        data = loaded

    config = ReflexConfig.model_validate(data)

    # Check if signature verification is required by bootstrap config
    bootstrap = load_bootstrap_config()
    if bootstrap.require_signature:
        _verify_config_signature(config_path, bootstrap)

    if bootstrap.rollout_state_path:
        from .policy_rollout import RolloutStore

        selected = RolloutStore(Path(bootstrap.rollout_state_path)).select(
            scope or str(config_path.parent.resolve())
        )
        if selected is not None:
            config = selected

    if mode_override is not None:
        config = config.model_copy(update={"mode": mode_override})

    return config


def _verify_config_signature(config_path: Path, bootstrap: BootstrapConfig) -> None:
    """Verify the configuration file signature.

    Args:
        config_path: Path to the configuration file.
        bootstrap: Bootstrap configuration with signature requirements.

    Raises:
        ValueError: If signature verification fails or signature is missing.
    """
    from .signing import Ed25519Signer, load_public_key, verify_file

    signature_path = config_path.with_suffix(config_path.suffix + ".sig")

    if not signature_path.exists():
        raise ValueError(
            f"Signature verification required but signature file not found: {signature_path}"
        )

    if bootstrap.public_key_path is None:
        raise ValueError(
            "Signature verification required but public_key_path not specified in bootstrap config"
        )

    public_key_path = Path(bootstrap.public_key_path).expanduser()
    public_key = load_public_key(public_key_path)

    # Create appropriate signer
    if bootstrap.signer_type == "ed25519":
        signer = Ed25519Signer()
    elif bootstrap.signer_type == "cosign":
        raise ValueError(
            "Cosign signature verification is not yet implemented. "
            "Please use ed25519 signer for now."
        )
    else:
        raise ValueError(f"Unsupported signer type: {bootstrap.signer_type}")

    # Verify the signature
    if not verify_file(config_path, signature_path, public_key, signer):
        raise ValueError(f"Signature verification failed for configuration file: {config_path}")


def load_bootstrap_config(path: Path | None = None) -> BootstrapConfig:
    """Load bootstrap configuration for signature verification.

    Args:
        path: Path to bootstrap config file. Defaults to standard locations.

    Returns:
        BootstrapConfig instance.
    """
    if path is None:
        # Check standard locations
        for candidate in [
            Path("/etc/jrx/bootstrap.yaml"),
            Path.home() / ".jev-reflex" / "bootstrap.yaml",
        ]:
            if candidate.exists():
                path = candidate
                break
        else:
            # No bootstrap config found, return defaults
            return BootstrapConfig()

    if not path.exists():
        return BootstrapConfig()

    try:
        with path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)
    except yaml.YAMLError:
        raise ValueError("bootstrap configuration YAML is invalid") from None

    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise ValueError("bootstrap configuration root must be a YAML mapping")

    return BootstrapConfig.model_validate(loaded)
