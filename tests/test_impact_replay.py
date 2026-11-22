"""Signed replay, aggregate transitions and the PR status contract."""

import base64
import json

import pytest
from typer.testing import CliRunner

from jev_reflex.cli import app
from jev_reflex.policy_impact import PolicyImpactReport
from jev_reflex.signing import Ed25519Signer


@pytest.mark.parametrize(
    ("review", "after", "allows", "hold_review"),
    [(0.5, "REVIEW", 0, 1), (0.7, "ALLOW", 1, 0)],
)
def test_hold_relaxations(
    impact_case, write_impact_entry, tmp_path, review, after, allows, hold_review
):
    audit, baseline, candidate, run = impact_case
    data = json.loads(baseline.read_text())
    data["thresholds"] = {"review": 0.3, "strong": 0.5}
    baseline.write_text(json.dumps(data))
    audit.unlink()
    write_impact_entry(data, {"destructive": 0.6})
    data["thresholds"] = {"review": review, "strong": 0.9}
    candidate.write_text(json.dumps(data))

    output = tmp_path / "github"
    result = run("--github-output", str(output), "--max-relaxations", "1")
    assert result.exit_code == 0
    assert f"| HOLD → {after} | 1 |" in result.stdout
    transition = ", 1 HOLD->REVIEW" if hold_review else ""
    assert (
        output.read_text() == f"counts=1/1 replayed, {allows} new ALLOW{transition}, 0 new HOLD\n"
    )
    assert run("--max-new-allows", "0").exit_code == allows
    assert run("--max-relaxations", "0").exit_code == 1


def test_review_to_allow_counts_toward_relaxations(impact_case):
    *_, run = impact_case
    assert run("--max-relaxations", "0").exit_code == 1
    assert run("--max-relaxations", "1").exit_code == 0
    assert run("--max-relaxations", "-1").exit_code == 2


@pytest.mark.parametrize("count", [10**15 - 1, 10**100])
def test_status_with_all_counts_fits_github_limit(count):
    report = PolicyImpactReport(
        total=count * 4,
        replayed=count * 3,
        new_allows=count,
        new_holds=count,
        skipped_legacy=count,
        skipped_policy_mismatch=0,
        skipped_decision_mismatch=0,
        changes={"HOLD_to_REVIEW": count},
    )
    status = "Limit exceeded. " + report.summary()
    assert len(status) < 140
    assert all(label in status for label in ("replayed", "new ALLOW", "HOLD->REVIEW", "new HOLD"))


@pytest.mark.parametrize("command", ["simulate", "impact"])
@pytest.mark.parametrize("override", [False, True])
def test_signed_audit_verified_without_signer(
    impact_case, write_impact_entry, tmp_path, monkeypatch, command, override
):
    audit, baseline, candidate, _ = impact_case
    private = tmp_path / "producer.pem"
    public = tmp_path / "verifier.pub"
    signer = Ed25519Signer()
    private.write_text(signer.get_private_key_pem())
    public.write_text(signer.get_public_key_pem())
    for path in (baseline, candidate):
        data = json.loads(path.read_text())
        data["signing"] = {
            "require_signature": override,
            "private_key_path": str(private),
            "public_key_path": str(tmp_path / "producer-only.pub" if override else public),
        }
        path.write_text(json.dumps(data))
    audit.unlink()
    write_impact_entry(json.loads(baseline.read_text()))
    private.unlink()
    record = json.loads(audit.read_text())
    assert record["decision_signature"]
    wrong_signature = Ed25519Signer().sign(record["entry_hash"].encode())

    def forbid_signer(*args, **kwargs):
        pytest.fail("read-only verification initialized a private signer")

    monkeypatch.setattr(Ed25519Signer, "__init__", forbid_signer)
    args = [
        "policy",
        command,
        "--audit",
        str(audit),
        "--baseline",
        str(baseline),
        "--candidate",
        str(candidate),
    ]
    if override:
        args.extend(["--public-key", str(public)])
    verified = CliRunner().invoke(app, args)
    assert verified.exit_code == 0, verified.output
    assert "PRIVATE-CANARY" not in verified.output
    github_output = tmp_path / "github-output"
    github_output.write_text("prior=value\n")
    if command == "impact":
        args.extend(["--github-output", str(github_output)])
    for invalid_signature in (base64.b64encode(wrong_signature).decode(), None):
        record["decision_signature"] = invalid_signature
        audit.write_text(json.dumps(record) + "\n")
        rejected = CliRunner().invoke(app, args)
        assert rejected.exit_code == 2
        assert "PRIVATE-CANARY" not in rejected.output
        assert github_output.read_text() == "prior=value\n"


def test_required_audit_signature_needs_public_key(impact_case, write_impact_entry):
    audit, baseline, candidate, run = impact_case
    for path in (baseline, candidate):
        data = json.loads(path.read_text())
        data["signing"] = {"require_signature": True}
        path.write_text(json.dumps(data))
    audit.unlink()
    write_impact_entry(json.loads(baseline.read_text()))
    assert run().exit_code == 2


def test_sparse_report_treats_missing_hold_to_review_as_zero():
    report = PolicyImpactReport(1, 1, 1, 0, 0, 0, 0, {"REVIEW_to_ALLOW": 1})
    assert report.relaxations == 1
    assert report.summary() == "1/1 replayed, 1 new ALLOW, 0 new HOLD"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_simulation_invalid_yaml_has_value_free_diagnostic(impact_case, encoding):
    audit, baseline, candidate, _ = impact_case
    if encoding == "utf-16":
        candidate.write_text(candidate.read_text(), encoding=encoding)
    else:
        candidate.write_text("hold_on: [PRIVATE-CANARY", encoding=encoding)
    result = CliRunner().invoke(
        app,
        [
            "policy",
            "simulate",
            "--audit",
            str(audit),
            "--baseline",
            str(baseline),
            "--candidate",
            str(candidate),
        ],
    )
    assert result.exit_code == 2
    assert "Policy simulation failed" in result.output
    assert "PRIVATE-CANARY" not in result.output
