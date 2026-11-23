"""Offline production controls shared by policy lint, doctor, and policy loading."""

from __future__ import annotations

import re

from .config import ReflexConfig, parse_local_base_url

OIDC_PLACEHOLDER = "https://idp.example.com"
CHECKOUT_PLACEHOLDER = "/path/to/production-checkout"
IMAGE_PLACEHOLDER = "runner/worker@sha256:" + "0" * 64


def _configured_oidc_url(value: str) -> bool:
    try:
        url = parse_local_base_url(value, allow_non_loopback_http=False)
    except ValueError:
        return False
    return url.scheme == "https" and url.hostname != "idp.example.com"


def _pinned_image(value: str | None) -> bool:
    if not value:
        return False
    digest = re.fullmatch(r"[^@]+@sha256:([0-9a-f]{64})", value)
    return digest is not None and digest[1] != "0" * 64


def production_issues(config: ReflexConfig) -> list[dict[str, str]]:
    """Report production weaknesses using field names and fixed messages only."""
    issues = []

    def require(condition: bool, code: str, path: str, message: str) -> None:
        if not condition:
            issues.append({"severity": "error", "code": code, "path": path, "message": message})

    require(config.mode == "enforce", "production_mode", "mode", "Use enforce mode.")
    require(
        config.audit.enabled, "production_audit_disabled", "audit.enabled", "Enable audit logging."
    )
    require(
        config.audit.fail_closed,
        "production_audit_fail_open",
        "audit.fail_closed",
        "Require audit writes before execution.",
    )
    require(
        bool(config.audit.path.strip()),
        "production_audit_path",
        "audit.path",
        "Set an audit log path.",
    )
    require(
        config.policy.strict_review,
        "production_strict_review",
        "policy.strict_review",
        "Require authenticated approval for REVIEW.",
    )
    require(
        not config.policy.allow_hold_override
        or bool((config.policy.hold_override_exception or "").strip()),
        "production_hold_override",
        "policy.allow_hold_override",
        "Disable HOLD overrides or document the exception in policy.hold_override_exception.",
    )
    require(
        config.session.enabled,
        "production_session_disabled",
        "session.enabled",
        "Enable bounded sessions.",
    )
    require(
        config.session.pin_protected_files,
        "production_protected_file_drift",
        "session.pin_protected_files",
        "Pin protected files across session actions.",
    )
    require(
        config.session.track_secret_taint,
        "production_secret_taint",
        "session.track_secret_taint",
        "Track credentials seen in PostToolUse events.",
    )
    require(
        config.session.reserved_cost_per_evaluation_usd * config.jev.samples
        <= config.session.max_semantic_spend_usd
        and config.jev.samples <= config.session.max_semantic_evaluations,
        "production_session_budget",
        "session",
        "Budget for at least one complete semantic evaluation.",
    )
    require(
        not config.local_checks.protected_path_allowlist,
        "production_protected_path_exception",
        "local_checks.protected_path_allowlist",
        "Remove protected-file exceptions.",
    )
    access = config.access
    require(
        access is not None,
        "production_oidc_required",
        "access",
        "Configure OIDC identity and reviewer rules.",
    )
    if access is not None:
        for name in ("issuer", "jwks_uri"):
            require(
                _configured_oidc_url(getattr(access, name)),
                "production_oidc_endpoint",
                f"access.{name}",
                "Configure a non-placeholder HTTPS OIDC endpoint.",
            )
        require(
            bool(access.audience.strip() and access.roles_claim.strip()),
            "production_oidc_claims",
            "access",
            "Configure a non-empty OIDC audience and roles claim.",
        )
        require(
            access.environment in access.production_environments,
            "production_dual_review",
            "access.production_environments",
            "Require two independent reviewers in the configured environment.",
        )
        execute: set[str] = set()
        review: set[str] = set()
        for rule in access.rules:
            if not rule.role.strip() or not {"*", access.environment}.intersection(
                rule.environments
            ):
                continue
            if "execute" in rule.actions:
                execute.update(rule.repositories)
            if "review" in rule.actions:
                review.update(rule.repositories)
        require(
            bool(execute)
            and CHECKOUT_PLACEHOLDER not in (execute | review)
            and all(repo.strip() for repo in execute | review)
            and ("*" in review or execute <= review),
            "production_review_scope",
            "access.rules",
            "Configure OIDC execute and review rules covering each production checkout.",
        )
    require(
        config.sandbox.enabled,
        "production_sandbox_disabled",
        "sandbox.enabled",
        "Enable Docker isolation.",
    )
    require(
        _pinned_image(config.sandbox.image),
        "production_sandbox_image",
        "sandbox.image",
        "Pin the Docker image to a configured SHA-256 digest.",
    )
    if config.sandbox.allowed_hosts:
        require(
            _pinned_image(config.sandbox.proxy_image),
            "production_proxy_image",
            "sandbox.proxy_image",
            "Pin the egress proxy image to a configured SHA-256 digest.",
        )
    require(
        config.jev.transport in {"broker", "broker-tls"},
        "production_broker_required",
        "jev.transport",
        "Use the Host Broker transport.",
    )
    require(
        config.evaluator.require_semantic,
        "production_semantic_required",
        "evaluator.require_semantic",
        "Require live semantic evaluation without demo or deterministic-only mode.",
    )
    require(
        not config.evaluator.allow_non_loopback_http,
        "production_evaluator_http",
        "evaluator.allow_non_loopback_http",
        "Disallow non-loopback cleartext evaluator HTTP.",
    )
    require(
        config.privacy.redact_secrets,
        "production_redaction_disabled",
        "privacy.redact_secrets",
        "Enable secret redaction.",
    )
    return issues
