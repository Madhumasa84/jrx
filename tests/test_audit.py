"""Tests for the audit log functionality."""

import json
import threading
from pathlib import Path

import pytest

from jev_reflex.audit import GENESIS_HASH, AuditLog
from jev_reflex.config import ReflexConfig
from jev_reflex.models import DeterministicFinding
from jev_reflex.policy import PolicyDecision


@pytest.fixture
def temp_audit_path(tmp_path: Path) -> Path:
    """Create a temporary path for audit logs."""
    return tmp_path / "audit.log"


@pytest.fixture
def audit_config(temp_audit_path: Path) -> ReflexConfig:
    """Create a test configuration with audit logging enabled."""
    return ReflexConfig(
        audit={
            "enabled": True,
            "path": str(temp_audit_path),
            "rotate_mb": 100,
        }
    )


@pytest.fixture
def sample_policy_decision() -> PolicyDecision:
    """Create a sample policy decision for testing."""
    return PolicyDecision(
        decision="ALLOW",
        triggered_rules=(),
        reasons=(),
    )


@pytest.fixture
def sample_findings() -> list[DeterministicFinding]:
    """Create sample deterministic findings for testing."""
    return [
        DeterministicFinding(
            check="destructive",
            triggered=False,
            severity="high",
            reason_code="rm_recursive",
            blocking=False,
        )
    ]


def test_chain_integrity_across_sequential_writes(
    audit_config: ReflexConfig,
    sample_policy_decision: PolicyDecision,
    sample_findings: list[DeterministicFinding],
) -> None:
    """Test that chain integrity holds across 1000 sequential writes."""
    audit_log = AuditLog(audit_config)

    # Write 1000 entries
    for i in range(1000):
        audit_log.write_entry(
            action_summary=f"test action {i}",
            deterministic_findings=sample_findings,
            jev_signals={"destructive": 0.1, "secret_exposure": 0.0},
            policy_decision=sample_policy_decision,
        )

    # Verify chain integrity
    is_valid, message = audit_log.verify()
    assert is_valid, f"Chain integrity check failed: {message}"
    assert "chain intact, 1000 entries" == message


def test_tampering_detection(
    audit_config: ReflexConfig,
    sample_policy_decision: PolicyDecision,
    sample_findings: list[DeterministicFinding],
    temp_audit_path: Path,
) -> None:
    """Test that tampering with a single byte is detected."""
    audit_log = AuditLog(audit_config)

    # Write some entries
    for i in range(10):
        audit_log.write_entry(
            action_summary=f"test action {i}",
            deterministic_findings=sample_findings,
            jev_signals={"destructive": 0.1, "secret_exposure": 0.0},
            policy_decision=sample_policy_decision,
        )

    # Verify chain is intact before tampering
    is_valid, message = audit_log.verify()
    assert is_valid, f"Chain should be intact before tampering: {message}"

    # Tamper with a single byte in the middle of the file
    with temp_audit_path.open("r+", encoding="utf-8") as f:
        content = f.read()
        # Find a position in the middle (not the first or last line)
        lines = content.split("\n")
        if len(lines) > 2:
            middle_line_index = len(lines) // 2
            middle_line = lines[middle_line_index]
            if middle_line:
                # Change a character in the middle line
                modified_line = middle_line[:-1] + ("0" if middle_line[-1] != "0" else "1")
                lines[middle_line_index] = modified_line
                f.seek(0)
                f.write("\n".join(lines))
                f.truncate()

    # Verify chain is now broken
    audit_log_after = AuditLog(audit_config)
    is_valid, message = audit_log_after.verify()
    assert not is_valid, "Tampering should be detected"
    # Either chain broken or invalid JSON is acceptable detection
    assert "chain broken" in message.lower() or "invalid json" in message.lower()


def test_concurrent_writers_with_file_lock(
    audit_config: ReflexConfig,
    sample_policy_decision: PolicyDecision,
    sample_findings: list[DeterministicFinding],
) -> None:
    """Test that concurrent writers don't corrupt the chain."""
    num_threads = 10
    writes_per_thread = 20
    errors = []

    def write_entries(thread_id: int) -> None:
        try:
            # Each thread creates its own AuditLog instance to simulate concurrent processes
            thread_audit_log = AuditLog(audit_config)
            for i in range(writes_per_thread):
                thread_audit_log.write_entry(
                    action_summary=f"thread {thread_id} action {i}",
                    deterministic_findings=sample_findings,
                    jev_signals={"destructive": 0.1, "secret_exposure": 0.0},
                    policy_decision=sample_policy_decision,
                )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=write_entries, args=(i,)) for i in range(num_threads)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert not errors, f"Concurrent writes encountered errors: {errors}"

    # Verify chain integrity
    audit_log = AuditLog(audit_config)
    is_valid, message = audit_log.verify()
    assert is_valid, f"Chain integrity check failed after concurrent writes: {message}"


def test_redaction_before_write(
    audit_config: ReflexConfig,
    sample_policy_decision: PolicyDecision,
    sample_findings: list[DeterministicFinding],
    temp_audit_path: Path,
) -> None:
    """Test that redaction is applied before writing entries."""
    audit_log = AuditLog(audit_config)

    # Write an entry with a secret
    action_with_secret = "git push --token sk-1234567890abcdef"
    audit_log.write_entry(
        action_summary=action_with_secret,
        deterministic_findings=sample_findings,
        jev_signals={"destructive": 0.1, "secret_exposure": 0.0},
        policy_decision=sample_policy_decision,
    )

    # Read the log and verify the secret was redacted
    with temp_audit_path.open("r", encoding="utf-8") as f:
        content = f.read()

    assert "sk-1234567890abcdef" not in content
    assert "<REDACTED_SECRET>" in content


def test_should_log_when_enabled(audit_config: ReflexConfig) -> None:
    """Test that should_log returns True when audit is enabled."""
    audit_log = AuditLog(audit_config)
    assert audit_log.should_log()


def test_should_log_when_store_requests_enabled() -> None:
    """Test that should_log returns True when store_requests is enabled."""
    config = ReflexConfig(
        audit={"enabled": False, "path": "/tmp/audit.log", "rotate_mb": 100},
        privacy={"store_requests": True, "redact_secrets": True},
    )
    audit_log = AuditLog(config)
    assert audit_log.should_log()


def test_should_log_when_both_disabled() -> None:
    """Test that should_log returns False when both are disabled."""
    config = ReflexConfig(
        audit={"enabled": False, "path": "/tmp/audit.log", "rotate_mb": 100},
        privacy={"store_requests": False, "redact_secrets": True},
    )
    audit_log = AuditLog(config)
    assert not audit_log.should_log()


def test_verify_empty_log(audit_config: ReflexConfig) -> None:
    """Test verification of an empty log."""
    audit_log = AuditLog(audit_config)
    is_valid, message = audit_log.verify()
    assert is_valid
    assert "chain intact, 0 entries" == message


def test_verify_nonexistent_log(audit_config: ReflexConfig) -> None:
    """Test verification when log file doesn't exist."""
    audit_log = AuditLog(audit_config)
    is_valid, message = audit_log.verify()
    assert is_valid
    assert "chain intact, 0 entries" == message


def test_tail_empty_log(audit_config: ReflexConfig) -> None:
    """Test tail on an empty log."""
    audit_log = AuditLog(audit_config)
    entries = audit_log.tail(10)
    assert entries == []


def test_tail_with_entries(
    audit_config: ReflexConfig,
    sample_policy_decision: PolicyDecision,
    sample_findings: list[DeterministicFinding],
) -> None:
    """Test tail returns the most recent entries."""
    audit_log = AuditLog(audit_config)

    # Write 20 entries
    for i in range(20):
        audit_log.write_entry(
            action_summary=f"test action {i}",
            deterministic_findings=sample_findings,
            jev_signals={"destructive": 0.1, "secret_exposure": 0.0},
            policy_decision=sample_policy_decision,
        )

    # Get last 5 entries
    entries = audit_log.tail(5)
    assert len(entries) == 5

    # Verify they are the most recent (highest sequence numbers)
    seq_numbers = [entry["seq"] for entry in entries]
    assert seq_numbers == sorted(seq_numbers, reverse=True)
    assert max(seq_numbers) == 20


def test_file_permissions(audit_config: ReflexConfig, temp_audit_path: Path) -> None:
    """Test that the audit log is created with 0600 permissions."""
    audit_log = AuditLog(audit_config)

    # Write an entry to create the file
    audit_log.write_entry(
        action_summary="test action",
        deterministic_findings=[],
        jev_signals={},
        policy_decision=PolicyDecision(decision="ALLOW", triggered_rules=(), reasons=()),
    )

    # Check file permissions
    stat = temp_audit_path.stat()
    # On Unix, 0o600 means rw-------
    permissions = stat.st_mode & 0o777
    assert permissions == 0o600, f"Expected 0o600, got {oct(permissions)}"


def test_genesis_hash_usage(
    audit_config: ReflexConfig,
    sample_policy_decision: PolicyDecision,
    sample_findings: list[DeterministicFinding],
) -> None:
    """Test that the first entry uses GENESIS_HASH as prev_hash."""
    audit_log = AuditLog(audit_config)

    audit_log.write_entry(
        action_summary="first action",
        deterministic_findings=sample_findings,
        jev_signals={"destructive": 0.1},
        policy_decision=sample_policy_decision,
    )

    # Read the first entry
    log_path = audit_log._get_log_path()
    with log_path.open("r", encoding="utf-8") as f:
        first_entry = json.loads(f.readline().strip())

    assert first_entry["prev_hash"] == GENESIS_HASH
    assert first_entry["seq"] == 1


def test_hash_chaining(
    audit_config: ReflexConfig,
    sample_policy_decision: PolicyDecision,
    sample_findings: list[DeterministicFinding],
) -> None:
    """Test that each entry's hash is correctly chained to the previous."""
    audit_log = AuditLog(audit_config)

    # Write 3 entries
    for i in range(3):
        audit_log.write_entry(
            action_summary=f"action {i}",
            deterministic_findings=sample_findings,
            jev_signals={"destructive": 0.1},
            policy_decision=sample_policy_decision,
        )

    # Read all entries
    log_path = audit_log._get_log_path()
    with log_path.open("r", encoding="utf-8") as f:
        entries = [json.loads(line.strip()) for line in f if line.strip()]

    # Verify chaining
    assert entries[0]["prev_hash"] == GENESIS_HASH
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    assert entries[2]["prev_hash"] == entries[1]["entry_hash"]


def test_write_when_disabled(
    sample_policy_decision: PolicyDecision,
    sample_findings: list[DeterministicFinding],
    temp_audit_path: Path,
) -> None:
    """Test that no entries are written when audit is disabled."""
    config = ReflexConfig(
        audit={"enabled": False, "path": str(temp_audit_path), "rotate_mb": 100},
        privacy={"store_requests": False, "redact_secrets": True},
    )
    audit_log = AuditLog(config)

    audit_log.write_entry(
        action_summary="test action",
        deterministic_findings=sample_findings,
        jev_signals={"destructive": 0.1},
        policy_decision=sample_policy_decision,
    )

    # File should not exist
    assert not temp_audit_path.exists()


@pytest.mark.parametrize("suffix", ["{", "\n", "null\n", "[]\n"])
@pytest.mark.parametrize("override", [False, True])
def test_append_refuses_corrupt_tail_without_modifying_log(tmp_path, suffix, override):
    config = ReflexConfig(audit={"enabled": True, "path": str(tmp_path / "audit.log")})
    audit = AuditLog(config)
    audit.write_entry("first", [], {}, PolicyDecision("ALLOW", (), ()))
    path = tmp_path / "audit.log"
    original = path.read_bytes() + suffix.encode()
    path.write_bytes(original)
    with pytest.raises(ValueError, match="audit"):
        if override:
            audit.write_human_override("reviewer", "REVIEW", "second")
        else:
            audit.write_entry("second", [], {}, PolicyDecision("ALLOW", (), ()))
    assert path.read_bytes() == original


@pytest.mark.parametrize("payload", ["null\n", "[]\n", "1\n", '"text"\n'])
def test_verify_rejects_non_object_records(tmp_path, payload):
    config = ReflexConfig(audit={"path": str(tmp_path / "audit.log")})
    (tmp_path / "audit.log").write_text(payload)
    valid, _ = AuditLog(config).verify()
    assert valid is False


def test_verify_streams_large_chain_without_retaining_records(tmp_path):
    import hashlib
    import tracemalloc

    path = tmp_path / "audit.log"
    previous = "0" * 64
    with path.open("w") as handle:
        for sequence in range(1, 10_001):
            payload = {
                "seq": sequence,
                "prev_hash": previous,
                "action_summary": "x" * 512,
            }
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            previous = hashlib.sha256((previous + canonical).encode()).hexdigest()
            handle.write(json.dumps({**payload, "entry_hash": previous}) + "\n")
    audit = AuditLog(ReflexConfig(audit={"path": str(path)}))
    tracemalloc.start()
    try:
        assert audit.verify() == (True, "chain intact, 10000 entries")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 3_000_000


def test_verify_rejects_blank_and_truncated_records(tmp_path):
    path = tmp_path / "audit.log"
    audit = AuditLog(ReflexConfig(audit={"path": str(path)}))
    for payload in ("\n", '{"seq": 1}'):
        path.write_text(payload)
        valid, _ = audit.verify()
        assert not valid


@pytest.mark.parametrize("signer_type", ["ed25519", "cosign"])
def test_invalid_signing_key_refuses_unsigned_audit(tmp_path, signer_type):
    key = tmp_path / "invalid-key"
    key.write_text("not a private key")
    config = ReflexConfig(
        audit={"enabled": True, "path": str(tmp_path / "audit.log")},
        signing={"private_key_path": str(key), "signer_type": signer_type},
    )
    with pytest.raises((OSError, ValueError)):
        AuditLog(config)
    assert not (tmp_path / "audit.log").exists()
