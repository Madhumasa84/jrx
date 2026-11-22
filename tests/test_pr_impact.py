"""Check aggregate policy replay output and audit verification."""

import json

import pytest

from jev_reflex.signing import Ed25519Signer


def test_preview_and_optional_gate(impact_case, tmp_path):
    _, _, _, run = impact_case
    outputs = tmp_path / "outputs"
    result = run("--github-output", str(outputs))

    assert result.exit_code == 0
    assert "| REVIEW → ALLOW | 1 |" in result.output
    assert outputs.read_text() == "counts=1/1 replayed, 1 new ALLOW, 0 new HOLD\n"
    rejected_outputs = tmp_path / "rejected-outputs"
    assert run("--max-new-allows", "0", "--github-output", str(rejected_outputs)).exit_code == 1
    assert rejected_outputs.read_text() == outputs.read_text()
    assert run("--max-new-allows", "1").exit_code == 0


def test_unwritable_github_output_is_unassessed(impact_case, tmp_path):
    _, _, _, run = impact_case
    result = run("--github-output", str(tmp_path / "missing-parent" / "output"))
    assert result.exit_code == 2
    assert "Could not write the GitHub output file." in result.output


@pytest.mark.parametrize("problem", ["empty", "tampered", "unsupported", "unknown", "aliases"])
def test_unassessed_does_not_publish_counts(impact_case, tmp_path, problem):
    audit, _, candidate, run = impact_case
    if problem == "empty":
        audit.write_text("")
    elif problem == "tampered":
        entry = json.loads(audit.read_text())
        entry["entry_hash"] = "0" * 64
        audit.write_text(json.dumps(entry) + "\n")
    elif problem == "aliases":
        candidate.write_text("hold_on: &rules [destructive]\nreview_on: *rules\n")
    else:
        data = json.loads(candidate.read_text())
        data.update({"jev": {"samples": 3}} if problem == "unsupported" else {"typo": True})
        candidate.write_text(json.dumps(data))

    outputs = tmp_path / "outputs"
    result = run("--github-output", str(outputs))
    assert result.exit_code == 2
    assert "Unassessed" in result.output
    assert not outputs.exists()


def test_partial_replay_reports_baseline_mismatches(impact_case, write_impact_entry):
    _, _, candidate, run = impact_case
    write_impact_entry(json.loads(candidate.read_text()))

    result = run()
    assert result.exit_code == 0
    assert "Replayed 1 of 2 policy decisions." in result.output
    assert "1 baseline mismatch" in result.output


def test_signed_producer_replays_without_private_key(impact_case, tmp_path, write_impact_entry):
    audit, baseline, candidate, run = impact_case
    key = tmp_path / "key.pem"
    key.write_text(Ed25519Signer().get_private_key_pem())
    key.chmod(0o600)
    audit.unlink()
    for path in (baseline, candidate):
        data = json.loads(path.read_text())
        data["signing"] = {"private_key_path": str(key)}
        path.write_text(json.dumps(data))
    write_impact_entry(json.loads(baseline.read_text()))
    assert json.loads(audit.read_text())["decision_signature"]
    key.unlink()

    result = run()
    assert result.exit_code == 0
    assert "Replayed 1 of 1 policy decisions." in result.output
