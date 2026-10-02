"""Shared optional control gate for CLI, hooks and MCP evaluation."""

from __future__ import annotations

import os

from .action_scope import describe_action
from .agent_state import ControlError, digest
from .authority import AuthorityStore
from .config import ReflexConfig
from .enterprise import verified_identity
from .intent import IntentStore
from .models import DeterministicFinding, EvaluationContext


def policy_revision(config: ReflexConfig) -> str:
    return digest(config.model_dump(mode="json"))


def host_subject(config: ReflexConfig) -> str:
    if config.access is not None:
        return verified_identity(config.access).subject
    subject = os.environ.get("JRX_AGENT_ID", "")
    if not subject:
        raise ControlError("trusted host agent identity is required")
    return subject


def apply_controls(
    context: EvaluationContext,
    config: ReflexConfig,
    decision: str,
    scope_creep: float,
    session_id: str | None = None,
    *,
    action_nonce: str | None = None,
) -> list[DeterministicFinding]:
    findings = []
    session_id = session_id if session_id is not None else os.environ.get("JRX_SESSION_ID", "")
    revision = policy_revision(config)
    for name, enabled in (
        ("intent", config.intent.enabled),
        ("authority", config.authority.enabled),
    ):
        if not enabled:
            continue
        try:
            if name == "intent":
                record = IntentStore(config.intent).evaluate(
                    session_id, context, revision, decision, scope_creep=scope_creep, config=config
                )
                if not record["allowed"]:
                    raise ControlError("intent envelope violation")
            else:
                classes, resources, _ = describe_action(context, config)
                AuthorityStore(config.authority).validate(
                    os.environ.get("JRX_AUTHORITY_LEASE_ID", ""),
                    subject=host_subject(config),
                    session_id=session_id,
                    repository=context.repository_root,
                    environment=config.authority.environment,
                    policy_revision=revision,
                    capabilities=classes,
                    resources=resources,
                    nonce=action_nonce
                    if action_nonce is not None
                    else os.environ.get("JRX_ACTION_NONCE", ""),
                )
        except (OSError, ValueError, RuntimeError):
            findings.append(
                DeterministicFinding(
                    check="agent_control",
                    triggered=True,
                    severity="high",
                    reason_code=f"{name.upper()}_DENIED",
                    blocking=True,
                )
            )
    return findings


def check_liveness(config: ReflexConfig) -> None:
    """Recheck stop/revocation immediately before launching or forwarding."""
    session = os.environ.get("JRX_SESSION_ID", "")
    if config.intent.enabled and IntentStore(config.intent).status(session)["stopped"]:
        raise ControlError("intent stopped")
    if config.authority.enabled:
        AuthorityStore(config.authority).check_live(
            os.environ.get("JRX_AUTHORITY_LEASE_ID", ""), host_subject(config), session
        )
