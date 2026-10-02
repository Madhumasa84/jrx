"""Host-issued authority leases with attenuation, ancestor validation and replay state."""

from __future__ import annotations

import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from .agent_state import AuthenticatedStore, ControlError, contained, identifier, resources_within
from .config import AuthorityConfig
from .redaction import redact_text


class AuthorityStore(AuthenticatedStore):
    def __init__(self, config: AuthorityConfig) -> None:
        super().__init__(config.path, config.key_path, config.max_records)
        self.config = config

    def _chain(self, db: sqlite3.Connection, lease_id: str) -> list[dict[str, Any]]:
        chain: list[dict[str, Any]] = []
        seen: set[str] = set()
        current: str | None = identifier(lease_id)
        now = time.time()
        while current is not None:
            if current in seen or len(chain) > self.config.max_depth:
                raise ControlError("delegation cycle or depth limit")
            seen.add(current)
            lease = self.get(db, "lease", current)
            if (
                lease["lease_id"] != current
                or lease["revoked"]
                or not lease["issued_at"] <= now < lease["expires_at"]
            ):
                raise ControlError("lease is revoked, expired or not yet valid")
            uses = [key for key in self.ids(db, "use") if key.startswith(current + ":")]
            if len(uses) != lease["use_count"]:
                raise ControlError("lease replay state count mismatch")
            for key in uses:
                use = self.get(db, "use", key)
                if use["lease_id"] != current:
                    raise ControlError("lease replay state binding mismatch")
            chain.append(lease)
            current = lease["parent_id"]
        for child, parent in zip(chain, chain[1:], strict=False):
            self._subset(child, parent)
        return chain

    @staticmethod
    def _subset(child: dict[str, Any], parent: dict[str, Any]) -> None:
        if (
            child["issuer"] != parent["subject"]
            or child["issuer_session"] != parent["session_id"]
            or any(
                child[field] != parent[field]
                for field in ("repository", "environment", "policy_revision")
            )
            or child["expires_at"] > parent["expires_at"]
            or child["issued_at"] < parent["issued_at"]
            or child["depth"] != parent["depth"] + 1
            or not set(child["capabilities"]) <= set(parent["capabilities"])
            or not set(parent["forbidden"]) <= set(child["forbidden"])
            or not all(contained(scope, parent["scopes"]) for scope in child["scopes"])
        ):
            raise ControlError("child authority exceeds parent authority")

    def issue(
        self,
        *,
        issuer: str,
        issuer_session: str,
        subject: str,
        session_id: str,
        repository: str,
        environment: str,
        policy_revision: str,
        scopes: list[str],
        capabilities: list[str],
        ttl_seconds: int,
        parent_id: str | None = None,
        forbidden: list[str] | None = None,
    ) -> dict[str, Any]:
        from .agent_state import capabilities as validate_capabilities
        from .agent_state import scopes as validate_scopes

        for value in (issuer, issuer_session, subject, session_id):
            identifier(value)
        if (
            type(ttl_seconds) is not int
            or not 1 <= ttl_seconds <= self.config.max_ttl_seconds
            or environment != self.config.environment
            or not policy_revision
        ):
            raise ControlError("invalid lease lifetime, environment or policy revision")
        now = time.time()
        lease: dict[str, Any] = dict(
            lease_id=uuid.uuid4().hex,
            issuer=issuer,
            issuer_session=issuer_session,
            subject=subject,
            session_id=session_id,
            repository=str(Path(repository).resolve()),
            environment=environment,
            policy_revision=policy_revision,
            scopes=validate_scopes(scopes),
            capabilities=validate_capabilities(capabilities),
            forbidden=validate_capabilities(forbidden) if forbidden else [],
            issued_at=now,
            expires_at=now + ttl_seconds,
            parent_id=parent_id,
            depth=0,
            nonce=uuid.uuid4().hex,
            revoked=False,
            use_count=0,
        )
        with self.transaction() as db:
            if len(self.ids(db, "lease")) >= self.config.max_leases:
                raise ControlError("authority lease storage limit reached")
            if parent_id is not None:
                parent = self._chain(db, parent_id)[0]
                lease["depth"] = parent["depth"] + 1
                lease["forbidden"] = sorted(set(lease["forbidden"]) | set(parent["forbidden"]))
                self._subset(lease, parent)
            if lease["depth"] > self.config.max_depth or set(lease["capabilities"]) & set(
                lease["forbidden"]
            ):
                raise ControlError("delegation depth or forbidden capability violation")
            self.put(db, "lease", lease["lease_id"], lease, new=True)
        return lease

    def validate(
        self,
        lease_id: str,
        *,
        subject: str,
        session_id: str,
        repository: str,
        environment: str,
        policy_revision: str,
        capabilities: list[str],
        resources: list[str],
        nonce: str,
    ) -> dict[str, Any]:
        identifier(nonce)
        with self.transaction() as db:
            lease = self._chain(db, lease_id)[0]
            if (
                subject != lease["subject"]
                or session_id != lease["session_id"]
                or str(Path(repository).resolve()) != lease["repository"]
                or environment != lease["environment"]
                or environment != self.config.environment
                or policy_revision != lease["policy_revision"]
                or not set(capabilities) <= set(lease["capabilities"])
                or set(capabilities) & set(lease["forbidden"])
                or not resources_within(lease["repository"], resources, lease["scopes"])
            ):
                raise ControlError("lease does not authorize this action or principal")
            # Unique insertion under BEGIN IMMEDIATE makes same-action replay atomic.
            self.put(
                db,
                "use",
                lease_id + ":" + nonce,
                dict(
                    lease_id=lease_id,
                    nonce=nonce,
                    subject=subject,
                    session_id=session_id,
                    capabilities=capabilities,
                    resources=[redact_text(value) for value in resources],
                    timestamp=time.time(),
                ),
                new=True,
            )
            lease["use_count"] += 1
            self.put(db, "lease", lease_id, lease)
            return lease

    def check_live(self, lease_id: str, subject: str, session_id: str) -> None:
        with self.transaction() as db:
            lease = self._chain(db, lease_id)[0]
            if lease["subject"] != subject or lease["session_id"] != session_id:
                raise ControlError("lease principal mismatch")

    def inspect(self, lease_id: str) -> dict[str, Any]:
        with self.transaction() as db:
            return self.get(db, "lease", identifier(lease_id))

    def revoke(self, lease_id: str) -> None:
        with self.transaction() as db:
            lease = self.get(db, "lease", identifier(lease_id))
            lease["revoked"] = True
            self.put(db, "lease", lease_id, lease)

    def tree(self, lease_id: str) -> list[dict[str, Any]]:
        with self.transaction() as db:
            records = [self.get(db, "lease", key) for key in self.ids(db, "lease")]
            selected = {identifier(lease_id)}
            for _ in range(self.config.max_depth + 1):
                selected.update(row["lease_id"] for row in records if row["parent_id"] in selected)
            return [row for row in records if row["lease_id"] in selected]
