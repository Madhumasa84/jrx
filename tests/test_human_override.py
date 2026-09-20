"""Tests for human override identity requirements, logging, and policy controls."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from jev_reflex.audit import AuditLog
from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig
from jev_reflex.identity import resolve_approver
from jev_reflex.policy_source import PolicyMerger

runner = CliRunner()


def test_approver_resolution_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test identity resolution in priority order: --approver, $JRX_APPROVER, getpass.getuser()."""
    # 1. Explicit approver wins over everything
    monkeypatch.setenv("JRX_APPROVER", "env_user")
    monkeypatch.setattr("getpass.getuser", lambda: "os_user")
    assert resolve_approver("explicit_user") == "explicit_user"

    # 2. JRX_APPROVER wins over os_user when explicit is None or whitespace
    assert resolve_approver(None) == "env_user"
    assert resolve_approver("   ") == "env_user"

    # 3. Falls back to getpass.getuser() when JRX_APPROVER is unset or empty
    monkeypatch.delenv("JRX_APPROVER", raising=False)
    assert resolve_approver(None) == "os_user"

    monkeypatch.setenv("JRX_APPROVER", "   ")
    assert resolve_approver(None) == "os_user"

    # 4. Returns None when all three are empty or whitespace
    monkeypatch.delenv("JRX_APPROVER", raising=False)
    monkeypatch.setattr("getpass.getuser", lambda: "")
    assert resolve_approver(None) is None
    assert resolve_approver("   ") is None

    # 5. Returns None when getpass.getuser() raises an exception
    def raise_err() -> str:
        raise OSError("no user")

    monkeypatch.setattr("getpass.getuser", raise_err)
    assert resolve_approver(None) is None


def test_override_with_no_identity_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Override with no identity available (mock all three sources as empty) is refused."""
    monkeypatch.delenv("JRX_APPROVER", raising=False)
    monkeypatch.setattr("getpass.getuser", lambda: "")

    # Execute a command in review mode that produces REVIEW
    # Pass 'y' to confirm the prompt, and a justification
    marker = tmp_path / "should_not_run.txt"
    code = f"import pathlib; pathlib.Path({str(marker)!r}).write_text('ran')"

    result = runner.invoke(
        app,
        [
            "exec",
            "--demo",
            "--mode",
            "review",
            "--cwd",
            str(tmp_path),
            "--",
            sys.executable,
            "-c",
            code,
        ],
        input="y\nUrgent fix\n",
    )

    assert result.exit_code == 2
    assert "Human override refused: no approver identity available" in result.output
    assert not marker.exists()


def test_override_with_explicit_approver_succeeds_and_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Override is logged with correct fields and shows up in jrx audit overrides."""
    audit_file = tmp_path / "audit.log"
    config_file = tmp_path / "reflex.yaml"
    config_file.write_text(
        f"""
mode: review
audit:
  path: {audit_file}
"""
    )

    marker = tmp_path / "ran.txt"
    code = f"import pathlib; pathlib.Path({str(marker)!r}).write_text('ok')"

    result = runner.invoke(
        app,
        [
            "exec",
            "--demo",
            "--config",
            str(config_file),
            "--cwd",
            str(tmp_path),
            "--approver",
            "security-alice",
            "--",
            sys.executable,
            "-c",
            code,
        ],
        input="y\nAuthorizing critical bugfix in review mode\n",
    )

    assert result.exit_code == 0, result.output
    assert marker.exists()
    assert marker.read_text() == "ok"

    # Verify audit log contains human_override entry with correct fields
    assert audit_file.exists()
    with audit_file.open("r", encoding="utf-8") as f:
        lines = [json.loads(line.strip()) for line in f if line.strip()]

    override_entries = [e for e in lines if e.get("event_type") == "human_override"]
    assert len(override_entries) == 1
    entry = override_entries[0]

    assert entry["identity"] == "security-alice"
    assert entry["original_decision"] == "REVIEW"
    assert sys.executable in entry["action_summary"]
    assert entry["justification"] == "Authorizing critical bugfix in review mode"
    assert "timestamp_utc" in entry
    assert "entry_hash" in entry
    assert "prev_hash" in entry

    # Verify hash chain integrity
    cfg = ReflexConfig(audit={"path": str(audit_file)})
    audit_log = AuditLog(cfg)
    is_valid, msg = audit_log.verify()
    assert is_valid, f"Hash chain broken: {msg}"

    # Verify jrx audit overrides displays it
    report = runner.invoke(app, ["audit", "overrides", "--path", str(audit_file)])
    assert report.exit_code == 0, report.output
    assert "Approver: security-alice" in report.output
    assert "Original Decision: REVIEW" in report.output
    assert "Justification: Authorizing critical bugfix in review mode" in report.output
    assert sys.executable in report.output

    # Verify jrx audit overrides --json
    json_report = runner.invoke(app, ["audit", "overrides", "--path", str(audit_file), "--json"])
    assert json_report.exit_code == 0, json_report.output
    data = json.loads(json_report.output)
    assert len(data) == 1
    assert data[0]["identity"] == "security-alice"
    assert data[0]["original_decision"] == "REVIEW"
    assert data[0]["justification"] == "Authorizing critical bugfix in review mode"


def test_override_with_empty_justification(tmp_path: Path) -> None:
    """Empty justification is accepted, logged as empty, and reported."""
    audit_file = tmp_path / "audit.log"
    config_file = tmp_path / "reflex.yaml"
    config_file.write_text(
        f"""
mode: review
audit:
  path: {audit_file}
"""
    )

    marker = tmp_path / "ran.txt"
    code = f"import pathlib; pathlib.Path({str(marker)!r}).write_text('ok')"

    result = runner.invoke(
        app,
        [
            "exec",
            "--demo",
            "--config",
            str(config_file),
            "--cwd",
            str(tmp_path),
            "--approver",
            "bob",
            "--",
            sys.executable,
            "-c",
            code,
        ],
        input="y\n\n",  # Confirm, empty justification
    )

    assert result.exit_code == 0, result.output
    assert marker.exists()

    with audit_file.open("r", encoding="utf-8") as f:
        lines = [json.loads(line.strip()) for line in f if line.strip()]

    override_entries = [e for e in lines if e.get("event_type") == "human_override"]
    assert len(override_entries) == 1
    assert override_entries[0]["justification"] == ""

    # Check human report formatting for empty justification
    report = runner.invoke(app, ["audit", "overrides", "--path", str(audit_file)])
    assert report.exit_code == 0, report.output
    assert "Approver: bob" in report.output
    assert "Justification: (empty)" in report.output


def test_allow_hold_override_false_blocks_in_enforce_mode(tmp_path: Path) -> None:
    """allow_hold_override: false blocks overriding a HOLD in enforce mode even with a valid identity."""
    audit_file = tmp_path / "audit.log"
    config_file = tmp_path / "reflex.yaml"
    config_file.write_text(
        f"""
mode: enforce
policy:
  allow_hold_override: false
audit:
  path: {audit_file}
"""
    )

    target = tmp_path / "critical_data"
    target.mkdir()

    result = runner.invoke(
        app,
        [
            "exec",
            "--demo",
            "--config",
            str(config_file),
            "--approver",
            "admin-charlie",
            "--cwd",
            str(tmp_path),
            "--yes",
            "--",
            "rm",
            "-rf",
            str(target),
        ],
    )

    assert result.exit_code == 2
    assert "HOLD cannot be overridden in enforce mode" in result.output
    assert target.exists()

    # Verify no override entry was logged
    if audit_file.exists():
        with audit_file.open("r", encoding="utf-8") as f:
            lines = [json.loads(line.strip()) for line in f if line.strip()]
        assert not any(e.get("event_type") == "human_override" for e in lines)


def test_allow_hold_override_true_permits_in_enforce_mode(tmp_path: Path) -> None:
    """allow_hold_override: true permits overriding a HOLD in enforce mode with a valid identity."""
    audit_file = tmp_path / "audit.log"
    config_file = tmp_path / "reflex.yaml"
    config_file.write_text(
        f"""
mode: enforce
policy:
  allow_hold_override: true
audit:
  path: {audit_file}
"""
    )

    dir_to_remove = tmp_path / "cache_to_delete"
    dir_to_remove.mkdir()
    (dir_to_remove / "temp_file.txt").write_text("delete me")

    # A command that triggers HOLD in demo mode (rm -rf)
    result = runner.invoke(
        app,
        [
            "exec",
            "--demo",
            "--config",
            str(config_file),
            "--approver",
            "secops-lead",
            "--cwd",
            str(tmp_path),
            "--",
            "rm",
            "-rf",
            str(dir_to_remove),
        ],
        input="y\nEmergency incident mitigation\n",
    )

    # In demo mode, rm -rf triggers HOLD; with allow_hold_override: true, it permits execution
    assert result.exit_code == 0, result.output
    assert not dir_to_remove.exists()

    # Verify human_override log entry
    report = runner.invoke(app, ["audit", "overrides", "--path", str(audit_file)])
    assert report.exit_code == 0, report.output
    assert "Approver: secops-lead" in report.output
    assert "Original Decision: HOLD" in report.output
    assert "Justification: Emergency incident mitigation" in report.output


def test_audit_overrides_since_filter(tmp_path: Path) -> None:
    """Test filtering audit overrides by --since DATE."""
    audit_file = tmp_path / "audit.log"
    cfg = ReflexConfig(audit={"path": str(audit_file)})
    audit_log = AuditLog(cfg)

    # Write override from yesterday
    yesterday = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    audit_log.write_human_override(
        identity="user1",
        original_decision="REVIEW",
        action_summary="action1",
        justification="justification1",
    )
    # Manually tamper timestamp of first entry in file to be 2 days ago
    lines = audit_file.read_text().splitlines()
    data0 = json.loads(lines[0])
    data0["timestamp_utc"] = yesterday
    data0["timestamp"] = yesterday
    audit_file.write_text(json.dumps(data0) + "\n")

    # Write override today
    audit_log.write_human_override(
        identity="user2",
        original_decision="HOLD",
        action_summary="action2",
        justification="justification2",
    )

    # Filter since yesterday (YYYY-MM-DD)
    today_str = datetime.now(UTC).strftime("%Y-%m-%d")
    report_today = runner.invoke(
        app, ["audit", "overrides", "--path", str(audit_file), "--since", today_str]
    )
    assert report_today.exit_code == 0
    assert "user2" in report_today.output
    assert "user1" not in report_today.output

    # Invalid date format
    bad_date = runner.invoke(
        app, ["audit", "overrides", "--path", str(audit_file), "--since", "not-a-date"]
    )
    assert bad_date.exit_code == 2
    assert "Invalid date format" in bad_date.output


def test_policy_merger_tighten_only_allow_hold_override() -> None:
    """PolicyMerger enforces tighten-only invariant for allow_hold_override (False is stricter)."""
    # Central False, local True -> cannot loosen, stays False
    central = ReflexConfig(policy={"allow_hold_override": False})
    local = ReflexConfig(policy={"allow_hold_override": True})
    merged = PolicyMerger.merge_policies(central, local)
    assert merged.policy.allow_hold_override is False

    # Central True, local False -> local can tighten to False
    central2 = ReflexConfig(policy={"allow_hold_override": True})
    local2 = ReflexConfig(policy={"allow_hold_override": False})
    merged2 = PolicyMerger.merge_policies(central2, local2)
    assert merged2.policy.allow_hold_override is False

    # Both True -> True
    central3 = ReflexConfig(policy={"allow_hold_override": True})
    local3 = ReflexConfig(policy={"allow_hold_override": True})
    merged3 = PolicyMerger.merge_policies(central3, local3)
    assert merged3.policy.allow_hold_override is True
