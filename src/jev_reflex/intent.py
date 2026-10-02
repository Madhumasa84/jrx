"""Optional persistent task envelopes and deterministic trajectory enforcement."""

from __future__ import annotations

import math
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from .action_scope import describe_action
from .agent_state import (
    AuthenticatedStore,
    ControlError,
    digest,
    identifier,
    resources_within,
)
from .config import IntentConfig, ReflexConfig
from .models import EvaluationContext
from .redaction import redact_text


class IntentStore(AuthenticatedStore):
    def __init__(self, config: IntentConfig) -> None:
        super().__init__(config.path, config.key_path, config.max_records)
        self.config = config

    def create(
        self,
        *,
        session_id: str,
        task: str,
        repository: str,
        policy_revision: str,
        scopes: list[str],
        capabilities: list[str],
        forbidden: list[str] | None = None,
        max_drift_score: float = 1.0,
    ) -> dict[str, Any]:
        from .agent_state import capabilities as validate_capabilities
        from .agent_state import scopes as validate_scopes

        identifier(session_id)
        if (
            not task
            or len(task) > 50000
            or not policy_revision
            or not math.isfinite(max_drift_score)
            or not 0 <= max_drift_score <= 1000
        ):
            raise ControlError("invalid intent envelope")
        forbidden = validate_capabilities(forbidden) if forbidden else []
        permitted = validate_capabilities(capabilities)
        if set(permitted) & set(forbidden):
            raise ControlError("intent capabilities conflict")
        envelope = dict(
            session_id=session_id,
            task_hash=digest(task),
            repository=str(Path(repository).resolve()),
            scopes=validate_scopes(scopes),
            capabilities=permitted,
            forbidden=forbidden,
            max_drift_score=max_drift_score,
            cumulative_drift=0.0,
            created_at=time.time(),
            policy_revision=policy_revision,
            stopped=False,
            action_count=0,
            last_action_id=None,
        )
        with self.transaction() as db:
            if len(self.ids(db, "intent")) >= self.config.max_sessions:
                raise ControlError("intent session limit reached")
            self.put(db, "intent", session_id, envelope, new=True)
        return envelope

    def _lineage(self, db: sqlite3.Connection, envelope: dict[str, Any]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        tip = envelope["last_action_id"]
        seen: set[str] = set()
        while tip is not None:
            if tip in seen or len(records) >= self.config.max_actions_per_session:
                raise ControlError("invalid intent lineage")
            seen.add(tip)
            record = self.get(db, "action", tip)
            if record["session_id"] != envelope["session_id"] or record["action_id"] != tip:
                raise ControlError("intent lineage binding mismatch")
            records.append(record)
            tip = record["parent_action_id"]
        if len(records) != envelope["action_count"]:
            raise ControlError("intent lineage count mismatch")
        return list(reversed(records))

    def evaluate(
        self,
        session_id: str,
        context: EvaluationContext,
        policy_revision: str,
        decision: str,
        *,
        scope_creep: float = 0.0,
        config: ReflexConfig | None = None,
    ) -> dict[str, Any]:
        identifier(session_id)
        if not math.isfinite(scope_creep) or not 0 <= scope_creep <= 1:
            raise ControlError("invalid drift evidence")
        classes, resources, fingerprint = describe_action(context, config)
        with self.transaction() as db:
            envelope = self.get(db, "intent", session_id)
            self._lineage(db, envelope)
            if envelope["action_count"] >= self.config.max_actions_per_session:
                raise ControlError("intent action storage limit reached")
            evidence = []
            if envelope["stopped"]:
                evidence.append("session_stopped")
            if digest(context.user_task) != envelope["task_hash"]:
                evidence.append("task_changed")
            if str(Path(context.repository_root).resolve()) != envelope["repository"]:
                evidence.append("repository_changed")
            if policy_revision != envelope["policy_revision"]:
                evidence.append("policy_changed")
            if not set(classes) <= set(envelope["capabilities"]) or set(classes) & set(
                envelope["forbidden"]
            ):
                evidence.append("capability_outside_intent")
            if not resources_within(envelope["repository"], resources, envelope["scopes"]):
                evidence.append("resource_outside_intent")
            drift = envelope["cumulative_drift"] + scope_creep
            if drift > envelope["max_drift_score"]:
                evidence.append("cumulative_drift")
            record = dict(
                action_id=uuid.uuid4().hex,
                parent_action_id=envelope["last_action_id"],
                session_id=session_id,
                fingerprint=fingerprint,
                capabilities=classes,
                resources=[redact_text(value) for value in resources],
                policy_decision=decision,
                evidence=evidence,
                scope_creep=scope_creep,
                cumulative_drift=drift,
                allowed=not evidence,
                created_at=time.time(),
            )
            self.put(db, "action", record["action_id"], record, new=True)
            envelope.update(
                last_action_id=record["action_id"],
                action_count=envelope["action_count"] + 1,
                cumulative_drift=drift,
            )
            self.put(db, "intent", session_id, envelope)
            return record

    def status(self, session_id: str) -> dict[str, Any]:
        with self.transaction() as db:
            envelope = self.get(db, "intent", identifier(session_id))
            self._lineage(db, envelope)
            return envelope

    def explain(self, session_id: str) -> list[dict[str, Any]]:
        with self.transaction() as db:
            return self._lineage(db, self.get(db, "intent", identifier(session_id)))

    def stop(self, session_id: str) -> None:
        with self.transaction() as db:
            envelope = self.get(db, "intent", identifier(session_id))
            envelope["stopped"] = True
            self.put(db, "intent", session_id, envelope)
