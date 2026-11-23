"""Versioned policy defaults for new local evaluator users."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import yaml

from .config import LOCAL_HOLD_ON, LOCAL_HOLD_THRESHOLD, LOCAL_REVIEW_THRESHOLD, ReflexConfig


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
    else:
        raise ValueError("preset must be dev-safe, strict-ci, or enterprise")

    ReflexConfig.model_validate(settings)
    contents = yaml.safe_dump(settings, sort_keys=False)
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
