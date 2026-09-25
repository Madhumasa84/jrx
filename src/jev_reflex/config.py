"""Configuration loading and validation."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from jsonschema import Draft202012Validator
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
    argument_schema: dict[str, Any] | None = None
    expected_input_schema_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    argument_constraints: dict[str, list[str | int | float | bool | None]] = Field(
        default_factory=dict
    )

    @model_validator(mode="after")
    def _validate_argument_policy(self) -> MCPToolRule:
        if self.argument_schema is not None:

            def validate_refs(schema: object) -> None:
                if isinstance(schema, Mapping):
                    for key, value in schema.items():
                        if key in {"$ref", "$dynamicRef", "$recursiveRef"} and (
                            not isinstance(value, str) or not value.startswith("#")
                        ):
                            raise ValueError("MCP argument schemas cannot use remote references")
                        validate_refs(value)
                elif isinstance(schema, list):
                    for item in schema:
                        validate_refs(item)

            validate_refs(self.argument_schema)
            try:
                Draft202012Validator.check_schema(self.argument_schema)
            except Exception as exc:
                raise ValueError("MCP argument_schema is not a valid JSON Schema") from exc
        for pointer, allowed_values in self.argument_constraints.items():
            if not pointer.startswith("/") or not allowed_values:
                raise ValueError("MCP argument constraints need a JSON Pointer and allowed values")
            if re.search(r"~(?![01])", pointer):
                raise ValueError("MCP argument constraint has an invalid JSON Pointer escape")
        return self


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


class SandboxConfig(BaseModel):
    """Resource limits and OCI settings for isolated command execution."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    image: str | None = None
    proxy_image: str | None = None
    docker_binary: str = "docker"
    runtime: str | None = None
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_private_networks: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=lambda: [443])
    memory_limit: str = "1g"
    cpus: float = Field(default=2.0, gt=0, le=64, allow_inf_nan=False)
    pids_limit: int = Field(default=256, ge=16, le=65_536)
    tmp_size: str = "256m"
    max_execution_seconds: int = Field(default=300, ge=1, le=86_400)

    @model_validator(mode="after")
    def _validate_sandbox(self) -> SandboxConfig:
        if self.enabled and not self.image:
            raise ValueError("sandbox.image is required when sandbox.enabled is true")
        if self.allowed_hosts and not self.enabled:
            raise ValueError("sandbox.enabled is required when sandbox.allowed_hosts is set")
        if self.allowed_hosts and not self.proxy_image:
            raise ValueError("sandbox.proxy_image is required when sandbox.allowed_hosts is set")
        for name, value in (
            ("image", self.image),
            ("proxy_image", self.proxy_image),
            ("runtime", self.runtime),
        ):
            if value is not None and (
                not value.strip()
                or value.startswith("-")
                or any(char.isspace() or ord(char) < 32 for char in value)
            ):
                raise ValueError(f"sandbox.{name} must be a non-empty token")
        if (
            not self.docker_binary.strip()
            or self.docker_binary.startswith("-")
            or any(char.isspace() or ord(char) < 32 for char in self.docker_binary)
        ):
            raise ValueError("sandbox.docker_binary must be a non-empty executable token")
        for name, value in (("memory_limit", self.memory_limit), ("tmp_size", self.tmp_size)):
            if not re.fullmatch(r"[1-9][0-9]*[bBkKmMgG]", value):
                raise ValueError(f"sandbox.{name} must be a positive Docker size, such as 512m")
        canonical_hosts: list[str] = []
        for host in self.allowed_hosts:
            if not host or any(char in host for char in "/:@*?#"):
                raise ValueError(
                    "sandbox.allowed_hosts must contain exact hostnames without wildcards"
                )
            try:
                canonical = host.rstrip(".").encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise ValueError("sandbox.allowed_hosts contains an invalid hostname") from exc
            try:
                ipaddress.ip_address(canonical)
            except ValueError:
                pass
            else:
                raise ValueError(
                    "sandbox.allowed_hosts must contain DNS hostnames, not IP addresses"
                )
            if len(canonical) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in canonical.split(".")
            ):
                raise ValueError("sandbox.allowed_hosts contains an invalid hostname")
            canonical_hosts.append(canonical)
        if len(canonical_hosts) != len(set(canonical_hosts)):
            raise ValueError("sandbox.allowed_hosts contains duplicate hostnames")
        self.allowed_hosts = canonical_hosts

        private_networks: list[str] = []
        for value in self.allowed_private_networks:
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise ValueError(
                    "sandbox.allowed_private_networks must use strict CIDR notation"
                ) from exc
            first, last = network.network_address, network.broadcast_address
            if (
                not first.is_private
                or not last.is_private
                or first.is_global
                or last.is_global
                or first.is_loopback
                or last.is_loopback
                or first.is_link_local
                or last.is_link_local
                or first.is_multicast
                or last.is_multicast
                or first.is_reserved
                or last.is_reserved
            ):
                raise ValueError("sandbox.allowed_private_networks may contain private CIDRs only")
            private_networks.append(str(network))
        if len(private_networks) != len(set(private_networks)):
            raise ValueError("sandbox.allowed_private_networks contains duplicates")
        self.allowed_private_networks = private_networks
        if not self.allowed_ports or len(self.allowed_ports) != len(set(self.allowed_ports)):
            raise ValueError("sandbox.allowed_ports must contain unique permitted ports")
        if any(port < 1 or port > 65_535 for port in self.allowed_ports):
            raise ValueError("sandbox.allowed_ports must be between 1 and 65535")
        return self


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
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
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
    bootstrap = load_bootstrap_config()
    raw = b""
    try:
        raw = config_path.read_bytes()
    except FileNotFoundError:
        if path is not None:
            raise FileNotFoundError(f"Configuration file not found: {config_path}") from None
    if bootstrap.require_signature:
        _verify_config_signature(config_path, bootstrap, data=raw)
    try:
        loaded = yaml.safe_load(raw.decode("utf-8"))
    except yaml.YAMLError:
        raise ValueError("configuration YAML is invalid") from None
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise ValueError("configuration root must be a YAML mapping")
    config = ReflexConfig.model_validate(loaded)

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


def _verify_config_signature(
    config_path: Path, bootstrap: BootstrapConfig, *, data: bytes | None = None
) -> None:
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
    if not verify_file(config_path, signature_path, public_key, signer, data=data):
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
