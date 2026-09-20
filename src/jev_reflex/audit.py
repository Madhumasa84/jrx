"""Append-only, tamper-evident audit log for policy decisions."""

from __future__ import annotations

import fcntl
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import ReflexConfig
from .models import DeterministicFinding
from .policy import PolicyDecision
from .redaction import redact_obj
from .signing import Ed25519Signer

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


class AuditEntry:
    """A single audit log entry with hash chaining."""

    def __init__(
        self,
        seq: int,
        timestamp_utc: str,
        action_summary: str,
        hard_rule_findings: list[dict[str, Any]],
        jev_signals: dict[str, float],
        policy_decision: str,
        policy_version_hash: str,
        prev_hash: str,
        decision_signature: str | None = None,
    ) -> None:
        self.seq = seq
        self.timestamp_utc = timestamp_utc
        self.action_summary = action_summary
        self.hard_rule_findings = hard_rule_findings
        self.jev_signals = jev_signals
        self.policy_decision = policy_decision
        self.policy_version_hash = policy_version_hash
        self.prev_hash = prev_hash
        self.decision_signature = decision_signature
        self.entry_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute the hash of this entry based on prev_hash and canonical JSON."""
        entry_without_hash = {
            "seq": self.seq,
            "timestamp_utc": self.timestamp_utc,
            "action_summary": self.action_summary,
            "hard_rule_findings": self.hard_rule_findings,
            "jev_signals": self.jev_signals,
            "policy_decision": self.policy_decision,
            "policy_version_hash": self.policy_version_hash,
            "prev_hash": self.prev_hash,
        }
        canonical = json.dumps(entry_without_hash, sort_keys=True, separators=(",", ":"))
        combined = self.prev_hash + canonical
        return hashlib.sha256(combined.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "seq": self.seq,
            "timestamp_utc": self.timestamp_utc,
            "action_summary": self.action_summary,
            "hard_rule_findings": self.hard_rule_findings,
            "jev_signals": self.jev_signals,
            "policy_decision": self.policy_decision,
            "policy_version_hash": self.policy_version_hash,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "decision_signature": self.decision_signature,
        }


class AuditLog:
    """Append-only, tamper-evident audit log with hash chaining."""

    def __init__(self, config: ReflexConfig) -> None:
        self.config = config
        self._ensure_log_directory()
        self._signer = None

        # Initialize signer if signing is configured
        if config.signing.private_key_path and config.signing.signer_type == "ed25519":
            try:
                key_path = Path(config.signing.private_key_path).expanduser()
                self._signer = Ed25519Signer(private_key_path=key_path)
            except Exception:
                # Signing failures should not block audit logging
                pass

    def _ensure_log_directory(self) -> None:
        """Create the log directory if it doesn't exist."""
        Path(self.config.audit.path).expanduser().parent.mkdir(parents=True, exist_ok=True)

    def _sign_entry_hash(self, entry: AuditEntry) -> str | None:
        """Sign the entry hash if a signer is configured.

        Args:
            entry: The audit entry to sign.

        Returns:
            Base64-encoded signature if signer is configured, None otherwise.
        """
        if self._signer is None:
            return None

        # Sign the entry hash (the hash is computed in the entry constructor)
        # We need to compute it first since we're being called before entry is fully constructed
        entry_data = {
            "seq": entry.seq,
            "timestamp_utc": entry.timestamp_utc,
            "action_summary": entry.action_summary,
            "hard_rule_findings": entry.hard_rule_findings,
            "jev_signals": entry.jev_signals,
            "policy_decision": entry.policy_decision,
            "policy_version_hash": entry.policy_version_hash,
            "prev_hash": entry.prev_hash,
        }
        canonical = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256((entry.prev_hash + canonical).encode()).hexdigest()

        # Sign the hash
        signature = self._signer.sign(entry_hash.encode())
        import base64

        return base64.b64encode(signature).decode()

    def _get_log_path(self) -> Path:
        """Get the expanded log file path."""
        return Path(self.config.audit.path).expanduser()

    def _get_last_entry(self) -> AuditEntry | None:
        """Read the last entry from the log to get the previous hash."""
        log_path = self._get_log_path()
        if not log_path.exists():
            return None

        try:
            with log_path.open("r", encoding="utf-8") as f:
                lines = f.readlines()
                if not lines:
                    return None
                last_line = lines[-1].strip()
                if not last_line:
                    return None
                data = json.loads(last_line)
                return AuditEntry(
                    seq=data["seq"],
                    timestamp_utc=data["timestamp_utc"],
                    action_summary=data["action_summary"],
                    hard_rule_findings=data["hard_rule_findings"],
                    jev_signals=data["jev_signals"],
                    policy_decision=data["policy_decision"],
                    policy_version_hash=data["policy_version_hash"],
                    prev_hash=data["prev_hash"],
                )
        except (OSError, json.JSONDecodeError, KeyError):
            return None

    def _compute_policy_version_hash(self, config: ReflexConfig) -> str:
        """Compute a hash of the policy configuration for version tracking."""
        policy_data = {
            "mode": config.mode,
            "thresholds": {
                "strong": config.thresholds.strong,
                "review": config.thresholds.review,
            },
            "hold_on": sorted(config.hold_on),
            "review_on": sorted(config.review_on),
        }
        canonical = json.dumps(policy_data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def should_log(self) -> bool:
        """Determine if logging should occur based on configuration."""
        return self.config.audit.enabled or self.config.privacy.store_requests

    def write_entry(
        self,
        action_summary: str,
        deterministic_findings: list[DeterministicFinding],
        jev_signals: dict[str, float],
        policy_decision: PolicyDecision,
    ) -> None:
        """Write a new entry to the audit log with file locking."""
        if not self.should_log():
            return

        # Apply redaction before writing
        redacted_summary = redact_obj(action_summary)
        redacted_findings = [
            {
                "check": finding.check,
                "triggered": finding.triggered,
                "severity": finding.severity,
                "reason_code": finding.reason_code,
                "blocking": finding.blocking,
            }
            for finding in deterministic_findings
        ]

        # Create new entry with atomic read-modify-write
        timestamp = datetime.now(UTC).isoformat()
        policy_version_hash = self._compute_policy_version_hash(self.config)

        # Write with file locking - the lock protects the entire read-modify-write cycle
        self._write_with_lock_atomic(
            redacted_summary,
            redacted_findings,
            jev_signals,
            policy_decision.decision,
            timestamp,
            policy_version_hash,
        )

    def _write_with_lock_atomic(
        self,
        redacted_summary: str,
        redacted_findings: list[dict[str, Any]],
        jev_signals: dict[str, float],
        policy_decision: str,
        timestamp: str,
        policy_version_hash: str,
    ) -> None:
        """Atomically read last entry, compute next sequence, and write with file locking."""
        log_path = self._get_log_path()
        # Create file with 0600 permissions if it doesn't exist
        if not log_path.exists():
            log_path.touch(mode=0o600)

        with log_path.open("a+", encoding="utf-8") as f:
            # Acquire exclusive lock
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                # Read the last entry to get the previous hash and sequence number
                f.seek(0)
                lines = f.readlines()
                last_entry = None
                if lines:
                    try:
                        last_line = lines[-1].strip()
                        if last_line:
                            data = json.loads(last_line)
                            last_entry = AuditEntry(
                                seq=data["seq"],
                                timestamp_utc=data["timestamp_utc"],
                                action_summary=data["action_summary"],
                                hard_rule_findings=data["hard_rule_findings"],
                                jev_signals=data["jev_signals"],
                                policy_decision=data["policy_decision"],
                                policy_version_hash=data["policy_version_hash"],
                                prev_hash=data["prev_hash"],
                            )
                    except (json.JSONDecodeError, KeyError):
                        pass

                # Get previous hash or use genesis
                prev_hash = last_entry.entry_hash if last_entry else GENESIS_HASH
                seq = (last_entry.seq + 1) if last_entry else 1

                # Create new entry (without signature first)
                entry = AuditEntry(
                    seq=seq,
                    timestamp_utc=timestamp,
                    action_summary=redacted_summary,
                    hard_rule_findings=redacted_findings,
                    jev_signals=jev_signals,
                    policy_decision=policy_decision,
                    policy_version_hash=policy_version_hash,
                    prev_hash=prev_hash,
                )

                # Add signature if signer is configured
                entry.decision_signature = self._sign_entry_hash(entry)

                # Write as JSONL
                f.write(json.dumps(entry.to_dict()) + "\n")
                f.flush()
            finally:
                # Release lock
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def verify(self, public_key_path: Path | None = None) -> tuple[bool, str]:
        """Verify the integrity of the hash chain and optionally decision signatures.

        Args:
            public_key_path: Optional path to public key for signature verification.

        Returns:
            (is_valid, message) where message describes the result or first broken link.
        """
        log_path = self._get_log_path()
        if not log_path.exists():
            return True, "chain intact, 0 entries"

        # Load public key if provided
        signer = None
        if public_key_path is not None:
            try:
                from .signing import Ed25519Signer, load_public_key

                public_key = load_public_key(public_key_path)
                signer = Ed25519Signer()
            except Exception:
                return False, f"failed to load public key from {public_key_path}"

        try:
            with log_path.open("r", encoding="utf-8") as f:
                lines = f.readlines()

            if not lines:
                return True, "chain intact, 0 entries"

            entries = []
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(data)
                except json.JSONDecodeError:
                    return False, f"invalid JSON at line {i + 1}"

            if not entries:
                return True, "chain intact, 0 entries"

            # Verify chain integrity
            prev_hash = GENESIS_HASH
            for i, entry_data in enumerate(entries):
                expected_seq = i + 1
                if entry_data.get("seq") != expected_seq:
                    return (
                        False,
                        f"sequence mismatch at index {i}: expected {expected_seq}, got {entry_data.get('seq')}",
                    )

                if entry_data.get("prev_hash") != prev_hash:
                    return (
                        False,
                        f"chain broken at index {i}: expected prev_hash {prev_hash}, got {entry_data.get('prev_hash')}",
                    )

                # Recompute entry hash and verify
                entry_without_hash = {
                    "seq": entry_data["seq"],
                    "timestamp_utc": entry_data["timestamp_utc"],
                    "action_summary": entry_data["action_summary"],
                    "hard_rule_findings": entry_data["hard_rule_findings"],
                    "jev_signals": entry_data["jev_signals"],
                    "policy_decision": entry_data["policy_decision"],
                    "policy_version_hash": entry_data["policy_version_hash"],
                    "prev_hash": entry_data["prev_hash"],
                }
                canonical = json.dumps(entry_without_hash, sort_keys=True, separators=(",", ":"))
                combined = prev_hash + canonical
                expected_hash = hashlib.sha256(combined.encode()).hexdigest()

                actual_hash = entry_data.get("entry_hash")
                if actual_hash != expected_hash:
                    return (
                        False,
                        f"chain broken at index {i}: expected hash {expected_hash}, got {actual_hash}",
                    )

                # Verify decision signature if public key is provided
                if signer is not None:
                    decision_signature = entry_data.get("decision_signature")
                    if decision_signature is None:
                        return (
                            False,
                            f"missing decision signature at index {i}",
                        )

                    # Verify the signature
                    import base64

                    try:
                        signature_bytes = base64.b64decode(decision_signature)
                    except Exception:
                        return (
                            False,
                            f"invalid base64 signature at index {i}",
                        )

                    if not signer.verify(expected_hash.encode(), signature_bytes, public_key):
                        return (
                            False,
                            f"invalid decision signature at index {i}",
                        )

                prev_hash = actual_hash

            signature_status = " (signatures verified)" if signer else ""
            return True, f"chain intact, {len(entries)} entries{signature_status}"

        except OSError as e:
            return False, f"error reading log: {e}"

    def tail(self, n: int = 10) -> list[dict[str, Any]]:
        """Return the last N entries from the log.

        Args:
            n: Number of entries to return (default: 10)

        Returns:
            List of entry dictionaries, most recent first.
        """
        log_path = self._get_log_path()
        if not log_path.exists():
            return []

        try:
            with log_path.open("r", encoding="utf-8") as f:
                lines = f.readlines()

            if not lines:
                return []

            # Get last N non-empty lines
            non_empty_lines = [line.strip() for line in lines if line.strip()]
            last_n = non_empty_lines[-n:] if len(non_empty_lines) > n else non_empty_lines

            entries = []
            for line in reversed(last_n):
                try:
                    data = json.loads(line)
                    entries.append(data)
                except json.JSONDecodeError:
                    continue

            return entries

        except OSError:
            return []
