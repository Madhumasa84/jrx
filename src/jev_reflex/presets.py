"""Versioned policy defaults for new local evaluator users."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import yaml

from .config import LOCAL_HOLD_ON, LOCAL_HOLD_THRESHOLD, LOCAL_REVIEW_THRESHOLD, ReflexConfig
from .production import CHECKOUT_PLACEHOLDER, IMAGE_PLACEHOLDER, OIDC_PLACEHOLDER


def write_preset(preset: str, output: Path, *, force: bool) -> None:
    settings: dict[str, Any] = {
        "mode": "enforce",
        "evaluator": {"provider": "local"},
        "thresholds": {"review": 0.70, "hold": LOCAL_HOLD_THRESHOLD},
        "hold_on": list(LOCAL_HOLD_ON),
        "audit": {"enabled": True},
    }
    critical = {
        "tamper_guard": "enforce",
        "secret_pattern": "enforce",
        "known_destructive": "enforce",
    }
    header = ""
    if preset == "dev-safe":
        settings["thresholds"]["review"] = LOCAL_REVIEW_THRESHOLD
        settings["rule_modes"] = {**critical, "execution_risk": "advisory", "filesystem": "review"}
    elif preset == "strict-ci":
        settings["thresholds"]["hold"] = 0.90
        settings["rule_modes"] = {**critical, "execution_risk": "enforce", "git_risk": "enforce"}
    elif preset == "enterprise":
        settings["rule_modes"] = critical
        settings["jev"] = {"transport": "broker"}
        settings["access"] = {
            "issuer": "https://idp.example.com",
            "audience": "jrx",
            "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
            "environment": "production",
            "rules": [
                {
                    "role": "jrx-operator",
                    "actions": ["execute", "review"],
                    "repositories": ["example-org/example-repo"],
                    "environments": ["production"],
                }
            ],
        }
        settings["signing"] = {
            "require_signature": True,
            "signer_type": "ed25519",
            "private_key_path": "~/.jev-reflex/audit-signing/policy_signing.key",
            "public_key_path": "~/.jev-reflex/audit-signing/policy_signing.pub",
        }
    elif preset == "production":
        header = (
            "# Replace the OIDC issuer and JWKS URI with your trusted provider URLs.\n"
            "# Replace the checkout placeholder with the canonical host Git root.\n"
            "# Replace the sandbox image and zero digest with your preloaded worker image.\n"
            "# Keep this policy and its state on the trusted runner host.\n"
        )
        settings.update(
            profile="production",
            policy={"strict_review": True, "allow_hold_override": False},
            rule_modes=critical,
            audit={"enabled": True, "fail_closed": True},
            session={
                "enabled": True,
                "max_tool_calls": 200,
                "max_semantic_evaluations": 200,
                "max_semantic_spend_usd": 2.0,
                "reserved_cost_per_evaluation_usd": 0.01,
                "max_elapsed_seconds": 1800,
                "max_execution_seconds": 120,
                "max_risky_attempts": 5,
                "pin_protected_files": True,
                "track_secret_taint": True,
            },
            access={
                "issuer": OIDC_PLACEHOLDER,
                "audience": "jrx",
                "jwks_uri": f"{OIDC_PLACEHOLDER}/.well-known/jwks.json",
                "environment": "production",
                "production_environments": ["production"],
                "rules": [
                    {
                        "role": role,
                        "actions": [action],
                        "repositories": [CHECKOUT_PLACEHOLDER],
                        "environments": ["production"],
                    }
                    for role, action in (("jrx-operator", "execute"), ("jrx-reviewer", "review"))
                ],
            },
            sandbox={"enabled": True, "image": IMAGE_PLACEHOLDER},
            jev={"transport": "broker"},
            evaluator={
                "provider": "local",
                "require_semantic": True,
                "allow_non_loopback_http": False,
            },
        )
    else:
        raise ValueError("preset must be dev-safe, strict-ci, enterprise, or production")

    ReflexConfig.model_validate(settings)
    contents = header + yaml.safe_dump(settings, sort_keys=False)
    with NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=output.parent, prefix=".reflex-init-", delete=False
    ) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(contents)
            handle.close()
            if force:
                temporary.replace(output)
            else:
                os.link(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
