"""Verified report aggregates, date filters, signatures and privacy boundaries."""

import base64
import json

import pytest
from typer.testing import CliRunner

from jev_reflex.audit import GENESIS_HASH, AuditEntry, AuditLog
from jev_reflex.audit_report import build_audit_report
from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig
from jev_reflex.signing import Ed25519Signer


def append(path, config, *, signer=None, **fields):
    if "degraded" in fields:
        fields.setdefault("risk_choice", "low")
    previous = (
        json.loads(path.read_text().splitlines()[-1])
        if path.exists() and path.stat().st_size
        else None
    )
    entry = AuditEntry(
        seq=previous["seq"] + 1 if previous else 1,
        prev_hash=previous["entry_hash"] if previous else GENESIS_HASH,
        timestamp_utc=fields.pop("timestamp", "2026-10-09T10:00:00+00:00"),
        action_summary="password=private-action-fixture",
        policy_version_hash=AuditLog(config)._compute_policy_version_hash(config),
        **fields,
    )
    if signer:
        entry.decision_signature = base64.b64encode(signer.sign(entry.entry_hash.encode())).decode()
    with path.open("a") as stream:
        stream.write(json.dumps(entry.to_dict()) + "\n")


def test_report_counts_decisions_degraded_overrides_and_findings(tmp_path):
    path = tmp_path / "audit.jsonl"
    config = ReflexConfig()
    append(path, config, policy_decision="ALLOW", degraded=False)
    append(path, config, policy_decision="REVIEW", degraded=True)
    append(
        path,
        config,
        policy_decision="HOLD",
        hard_rule_findings=[
            {"check": "destructive", "triggered": True},
            {"check": "not_triggered", "triggered": False},
            {"check": "password=private-check-fixture\n\x1b[31m", "triggered": True},
        ],
    )
    append(
        path,
        config,
        event_type="human_override",
        original_decision="HOLD",
        identity="private-user-fixture",
        justification="private-justification-fixture",
    )
    report = build_audit_report(path, config)
    assert report["verification"]["records_verified"] == 4
    assert not report["verification"]["signatures_verified"]
    assert report["records_selected"] == 4
    assert report["decisions"] == {"ALLOW": 1, "REVIEW": 1, "HOLD": 1}
    assert report["degraded_evaluations"] == 1
    assert report["legacy_unknown_degraded"] == 1
    assert report["human_overrides"] == 1
    assert report["override_original_decisions"]["HOLD"] == 1
    assert report["triggered_checks"] == {"destructive": 1, "other": 1}
    assert len(report["policy_versions"]) == 1
    assert "private-" not in json.dumps(report)


def test_utc_inclusive_filters_verify_the_entire_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    config = ReflexConfig()
    append(path, config, timestamp="2026-10-08T23:00:00Z", policy_decision="ALLOW")
    append(path, config, timestamp="2026-10-09T02:00:00+02:00", policy_decision="HOLD")
    append(path, config, timestamp="2026-10-10", policy_decision="REVIEW")
    report = build_audit_report(path, config, since="2026-10-09", until="2026-10-09")
    assert report["verification"]["records_verified"] == 3
    assert report["records_selected"] == 1
    assert report["decisions"]["HOLD"] == 1
    assert report["range"]["first_event"] == "2026-10-09T00:00:00+00:00"
    path.write_text(path.read_text().replace('"ALLOW"', '"HOLD"', 1))
    with pytest.raises(ValueError, match="verification failed"):
        build_audit_report(path, config, since="2026-10-09")


def test_signed_report_uses_configured_pinned_key_and_no_private_key(tmp_path):
    signer = Ed25519Signer()
    path = tmp_path / "audit.jsonl"
    public = tmp_path / "key.pub"
    public.write_text(signer.get_public_key_pem())
    config = ReflexConfig.model_validate(
        {
            "signing": {
                "public_key_path": str(public),
                "private_key_path": str(tmp_path / "unavailable.key"),
                "require_signature": True,
            }
        }
    )
    # Writing this fixture does not require loading the deliberately absent key.
    plain_config = config.model_copy(
        update={"signing": config.signing.model_copy(update={"private_key_path": None})}
    )
    append(path, plain_config, signer=signer, policy_decision="ALLOW")
    assert build_audit_report(path, config)["verification"]["signatures_verified"]
    public.write_text(Ed25519Signer().get_public_key_pem())
    with pytest.raises(ValueError, match="verification failed"):
        build_audit_report(path, config)


def test_unsigned_records_cannot_pass_signature_verification(tmp_path):
    path = tmp_path / "audit.jsonl"
    config = ReflexConfig()
    append(path, config, policy_decision="ALLOW")
    public = tmp_path / "key.pub"
    public.write_text(Ed25519Signer().get_public_key_pem())
    with pytest.raises(ValueError, match="verification failed"):
        build_audit_report(path, config, public_key=public)
    required = config.model_copy(
        update={"signing": config.signing.model_copy(update={"require_signature": True})}
    )
    with pytest.raises(ValueError, match="requires a public key"):
        build_audit_report(path, required)


def test_report_consumes_the_verified_snapshot_if_file_changes(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    config = ReflexConfig()
    append(path, config, policy_decision="ALLOW")
    original = AuditLog.verify

    def verify_then_replace(self, **kwargs):
        result = original(self, **kwargs)
        path.write_text("unverified replacement")
        return result

    monkeypatch.setattr(AuditLog, "verify", verify_then_replace)
    assert build_audit_report(path, config)["decisions"]["ALLOW"] == 1


@pytest.mark.parametrize(
    "fields",
    [
        {"policy_decision": []},
        {"policy_decision": "UNKNOWN"},
        {"event_type": "human_override", "original_decision": []},
        {"policy_decision": "ALLOW", "timestamp": "private-timestamp-fixture"},
        {"policy_decision": "ALLOW", "degraded": "yes"},
        {"policy_decision": "ALLOW", "hard_rule_findings": ["bad"]},
        {"policy_decision": "ALLOW", "hard_rule_findings": [{"triggered": True, "check": []}]},
    ],
)
def test_hash_valid_but_malformed_records_are_rejected(tmp_path, fields):
    path = tmp_path / "audit.jsonl"
    append(path, ReflexConfig(), **fields)
    with pytest.raises(ValueError):
        build_audit_report(path, ReflexConfig())


@pytest.mark.parametrize("contents", ["broken\n", "{}", "\n"])
def test_broken_and_incomplete_records_fail_closed(tmp_path, contents):
    path = tmp_path / "audit.jsonl"
    path.write_text(contents)
    with pytest.raises(ValueError, match="verification failed"):
        build_audit_report(path, ReflexConfig())


def test_empty_missing_and_size_limited_logs(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    with pytest.raises(OSError):
        build_audit_report(path, ReflexConfig())
    path.touch()
    report = build_audit_report(path, ReflexConfig())
    assert report["records_selected"] == 0
    assert report["range"]["first_event"] is None
    monkeypatch.setattr("jev_reflex.audit_report.MAX_REPORT_BYTES", 2)
    path.write_text("too big")
    with pytest.raises(ValueError, match="exceeds"):
        build_audit_report(path, ReflexConfig())


@pytest.mark.parametrize(
    "filters", [{"since": "bad"}, {"since": "2026-10-10", "until": "2026-10-09"}]
)
def test_invalid_ranges_are_rejected(tmp_path, filters):
    with pytest.raises(ValueError):
        build_audit_report(tmp_path / "missing", ReflexConfig(), **filters)


def test_cli_json_human_output_and_failure_do_not_leak_actions(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "audit.jsonl"
    append(path, ReflexConfig(), policy_decision="HOLD")
    args = ["audit", "report", "--path", str(path)]
    result = CliRunner().invoke(app, [*args, "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["decisions"]["HOLD"] == 1
    human = CliRunner().invoke(app, args)
    assert human.exit_code == 0, human.output
    assert "HOLD=1" in human.stdout and "signatures not checked" in human.stdout
    path.write_text("private-invalid-content-fixture")
    bad = CliRunner().invoke(app, [*args, "--json"])
    assert bad.exit_code == 2
    assert not bad.stdout
    assert "private" not in bad.output


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"])
def test_unicode_separators_inside_json_do_not_split_audit_records(tmp_path, separator):
    path = tmp_path / "audit.jsonl"
    config = ReflexConfig()
    entry = AuditEntry(
        seq=1,
        timestamp_utc="2026-10-09T00:00:00Z",
        action_summary="echo first" + separator + "second",
        policy_decision="ALLOW",
        policy_version_hash=AuditLog(config)._compute_policy_version_hash(config),
    )
    path.write_text(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n", encoding="utf-8")
    report = build_audit_report(path, config)
    assert report["verification"]["records_verified"] == 1
    assert report["decisions"]["ALLOW"] == 1


@pytest.mark.parametrize("date", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"])
def test_out_of_range_utc_dates_return_a_clean_cli_error(tmp_path, date):
    path = tmp_path / "audit.jsonl"
    path.touch()
    result = CliRunner().invoke(
        app, ["audit", "report", "--path", str(path), "--since", date, "--json"]
    )
    assert result.exit_code == 2
    assert not result.stdout
    assert "Audit report failed" in result.stderr
