"""Check policy replay output and the GitHub workflow's data boundary."""

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from jev_reflex.audit import AuditLog
from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig
from jev_reflex.policy import decide
from jev_reflex.signing import Ed25519Signer

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/policy-impact.yml"
PRIVATE_ACTION = "PRIVATE-CANARY: unreleased deployment"


def _write_entry(data):
    config = ReflexConfig.model_validate(data)
    signals = {"unsafe": 0.6}
    AuditLog(config).write_entry(
        PRIVATE_ACTION,
        [],
        signals,
        decide([], signals, config),
        risk_choice="low",
        risk_confidence=0.95,
        degraded=False,
        forced_review=False,
    )


@pytest.fixture
def impact_case(tmp_path):
    audit = tmp_path / "audit.jsonl"
    baseline = tmp_path / "base.yaml"
    candidate = tmp_path / "candidate.yaml"
    data = {
        "mode": "enforce",
        "audit": {"enabled": True, "path": str(audit)},
        "thresholds": {"review": 0.5, "strong": 0.9},
    }
    baseline.write_text(json.dumps(data))
    _write_entry(data)
    data["thresholds"]["review"] = 0.7
    candidate.write_text(json.dumps(data))

    def run(*args):
        result = CliRunner().invoke(
            app,
            [
                "policy",
                "impact",
                "--audit",
                str(audit),
                "--baseline",
                str(baseline),
                "--candidate",
                str(candidate),
                *args,
            ],
        )
        assert PRIVATE_ACTION not in result.output
        return result

    return audit, baseline, candidate, run


def test_preview_and_optional_gate(impact_case, tmp_path):
    _, _, _, run = impact_case
    outputs = tmp_path / "outputs"
    result = run("--github-output", str(outputs))

    assert result.exit_code == 0
    assert "| REVIEW → ALLOW | 1 |" in result.output
    assert outputs.read_text() == "counts=1/1 replayed, 1 new ALLOW, 0 new HOLD\n"
    assert run("--max-new-allows", "0").exit_code == 1
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
        audit.write_text(audit.read_text().replace(PRIVATE_ACTION, "changed"))
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


def test_partial_replay_reports_baseline_mismatches(impact_case):
    _, _, candidate, run = impact_case
    _write_entry(json.loads(candidate.read_text()))

    result = run()
    assert result.exit_code == 0
    assert "Replayed 1 of 2 policy decisions." in result.output
    assert "1 baseline mismatch" in result.output


def test_signed_producer_replays_without_private_key(impact_case, tmp_path):
    audit, baseline, candidate, run = impact_case
    key = tmp_path / "key.pem"
    key.write_text(Ed25519Signer().get_private_key_pem())
    key.chmod(0o600)
    audit.unlink()
    for path in (baseline, candidate):
        data = json.loads(path.read_text())
        data["signing"] = {"private_key_path": str(key)}
        path.write_text(json.dumps(data))
    _write_entry(json.loads(baseline.read_text()))
    assert json.loads(audit.read_text())["decision_signature"]
    key.unlink()

    result = run()
    assert result.exit_code == 0
    assert "Replayed 1 of 1 policy decisions." in result.output


@pytest.mark.parametrize(
    ("proposal", "exit_code"),
    [
        ("changed", 0),
        ("untouched", 0),
        ("absent", 2),
        ("symlink", 2),
        ("oversized", 2),
        ("stale", 2),
    ],
)
def test_workflow_extracts_a_policy_from_the_expected_merge(tmp_path, proposal, exit_code):
    workflow = yaml.safe_load(WORKFLOW.read_text())
    steps = workflow["jobs"]["preview"]["steps"]
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["ref"] == "${{ github.event.pull_request.base.sha }}"
    extract = next(step["run"] for step in steps if step.get("id") == "inputs")
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=repo, check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init", "-b", "main")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.test")
    git("config", "commit.gpgsign", "false")
    policy = repo / "policies/agent.yaml"
    policy.parent.mkdir()
    (repo / "README.md").write_text("base\n")
    if proposal != "absent":
        policy.write_text("mode: enforce\n")
    git("add", ".")
    git("commit", "-m", "baseline")
    base = git("rev-parse", "HEAD")
    git("switch", "-c", "proposal")
    if proposal in {"changed", "stale"}:
        policy.write_text("mode: advisory\n")
    elif proposal == "symlink":
        policy.unlink()
        policy.symlink_to("../README.md")
    elif proposal == "oversized":
        policy.write_text("#" + "a" * 1_048_576)
    (repo / "README.md").write_text("proposal\n")
    git("add", ".")
    git("commit", "-m", "proposal")
    head = git("rev-parse", "HEAD")
    git("switch", "main")
    git("merge", "--no-ff", "proposal", "-m", "merge")
    git("update-ref", "refs/pull/1/merge", git("rev-parse", "HEAD"))
    git("switch", "--detach", base)
    git("update-ref", "refs/heads/main", base)
    checkout = tmp_path / "checkout"
    git("clone", "--depth=1", "--branch", "main", repo.as_uri(), str(checkout))
    env = {
        **os.environ,
        "BASE": base,
        "HEAD_SHA": base if proposal == "stale" else head,
        "PR": "1",
        "POLICY": "policies/agent.yaml",
        "GITHUB_OUTPUT": str(tmp_path / "outputs"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        "RUNNER_TEMP": str(tmp_path),
    }

    command = ["bash", "-c", "sleep() { :; }\n" + extract]
    result = subprocess.run(command, cwd=checkout, env=env, capture_output=True)
    assert result.returncode == exit_code, result.stderr
    assert (checkout / "README.md").read_text() == "base\n"
    if proposal == "changed":
        assert (tmp_path / "base.yaml").read_text() == "mode: enforce\n"
        assert (tmp_path / "candidate.yaml").read_text() == "mode: advisory\n"
        assert (tmp_path / "outputs").read_text() == "changed=true\n"
    else:
        assert not (tmp_path / "candidate.yaml").exists()
        if proposal == "untouched":
            assert (tmp_path / "outputs").read_text() == "changed=false\n"
        else:
            assert not (tmp_path / "outputs").exists()


@pytest.mark.parametrize(
    ("job_status", "replay_exit", "changed", "status", "description"),
    [
        ("success", "0", "true", "success", "1/1 replayed, 1 new ALLOW, 0 new HOLD"),
        ("success", "", "false", "success", "Policy file unchanged."),
        (
            "failure",
            "1",
            "true",
            "failure",
            "Limit exceeded. 1/1 replayed, 1 new ALLOW, 0 new HOLD",
        ),
        ("failure", "2", "true", "error", "Unassessed. See workflow run."),
    ],
)
def test_workflow_posts_status_on_pr_head(
    tmp_path, job_status, replay_exit, changed, status, description
):
    workflow = yaml.safe_load(WORKFLOW.read_text())
    publish = workflow["jobs"]["preview"]["steps"][-1]["run"]
    call = tmp_path / "call"
    counts = "1/1 replayed, 1 new ALLOW, 0 new HOLD" if replay_exit in {"0", "1"} else ""
    env = {
        **os.environ,
        "CALL": str(call),
        "HEAD_SHA": "b" * 40,
        "GITHUB_REPOSITORY": "fixture/jrx",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_RUN_ID": "123",
        "RESULT": job_status,
        "RC": replay_exit,
        "CHANGED": changed,
        "COUNTS": counts,
    }
    subprocess.run(
        ["bash", "-e", "-c", 'gh() { printf "%s\\n" "$@" > "$CALL"; }\n' + publish],
        env=env,
        check=True,
    )
    assert call.read_text().splitlines() == [
        "api",
        "--silent",
        f"repos/fixture/jrx/statuses/{'b' * 40}",
        "-f",
        "context=jrx/policy-impact",
        "-f",
        f"state={status}",
        "-f",
        f"description={description}",
        "-f",
        "target_url=https://github.com/fixture/jrx/actions/runs/123",
    ]
