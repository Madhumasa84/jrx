"""Exercise the trusted workflow steps against a temporary GitHub-style merge ref."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/policy-impact.yml"
SCRIPT = Path(".github/scripts/policy-impact-inputs.sh")
COUNTS = "1/1 replayed, 0 new ALLOW, 1 HOLD->REVIEW, 0 new HOLD"


def _job(name):
    return yaml.safe_load(WORKFLOW.read_text())["jobs"][name]


def _run_step(step, directory, env):
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", step["run"]],
        cwd=directory,
        env={**os.environ, **env},
        text=True,
        capture_output=True,
    )


def _step(job, step_id):
    return next(s for s in _job(job)["steps"] if s.get("id") == step_id)


def test_retargeting_rechecks_policy_without_canceling_replay_on_metadata_edits():
    workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    assert "edited" in workflow["on"]["pull_request_target"]["types"]
    triggers_replay = "(github.event.action != 'edited' || github.event.changes.base.ref.from)"
    assert triggers_replay in _job("detect")["if"]
    assert triggers_replay in workflow["concurrency"]["group"]
    assert "|| github.run_id" in workflow["concurrency"]["group"]


def test_only_trusted_policy_changes_enter_evidence_environment():
    detect = _job("detect")
    replay = _job("replay")
    assert detect["outputs"]["merge"] == "${{ steps.inputs.outputs.merge }}"
    assert _step("replay", "inputs")["env"]["EXPECTED_MERGE"] == "${{ needs.detect.outputs.merge }}"
    assert "environment" not in detect
    assert "secrets." not in str(detect)
    assert replay["environment"] == "jrx-impact"
    assert replay["needs"] == "detect"
    assert replay["if"] == (
        "needs.detect.outputs.changed == 'true' && needs.detect.outputs.ref_status == 'ok' && "
        "github.event.pull_request.head.repo.full_name == github.repository"
    )
    for job in (detect, replay):
        checkout = next(s for s in job["steps"] if "uses" in s)
        assert re.fullmatch(r"actions/checkout@[a-f0-9]{40}", checkout["uses"])
        assert checkout["with"]["ref"] == "${{ github.sha }}"
    steps = [s.get("id") for s in replay["steps"]]
    assert steps.index("inputs") < steps.index("install") < steps.index("evidence")
    assert "-I -m jev_reflex policy impact" in _step("replay", "replay")["run"]


@pytest.mark.parametrize(
    ("proposal", "ref_status", "code"),
    [
        ("changed", "ok", 0),
        ("unchanged", "ok", 0),
        ("absent", "ok", 2),
        ("fetch-race", "ok", 0),
        ("deleted", "ok", 2),
        ("symlink", "ok", 2),
        ("executable", "ok", 2),
        ("oversized", "ok", 2),
        ("stale-base", "stale", 2),
        ("stale-head", "stale", 2),
        ("conflict", "conflict", 2),
    ],
)
def test_merge_ref_and_data_only_checkout(tmp_path, proposal, ref_status, code):
    origin = tmp_path / "origin.git"
    repo = tmp_path / "producer"
    repo.mkdir()

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=repo, check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init", "--bare", "-b", "main", str(origin))
    git("init", "-b", "main")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.test")
    git("config", "commit.gpgsign", "false")
    git("remote", "add", "origin", origin.as_uri())
    policy = repo / "policies/agent.yaml"
    policy.parent.mkdir()
    # The proposed branch can change both CLI and workflow helper. Only the
    # bytes of its policy may be materialized in the runner.
    script = repo / SCRIPT
    script.parent.mkdir(parents=True)
    shutil.copy(ROOT / SCRIPT, script)
    (repo / "cli.py").write_text("print('trusted CLI')\n")
    if proposal != "absent":
        policy.write_bytes(b"mode: enforce\n")
    git("add", ".")
    git("commit", "-m", "baseline")
    base = git("rev-parse", "HEAD")
    git("push", "origin", "main")
    git("switch", "-c", "fork-proposal")
    script.write_text("exit 19\n")
    (repo / "cli.py").write_text("print('proposed CLI')\n")
    candidate = b"# preserved CRLF\r\nmode: advisory\r\n"
    if proposal in {"changed", "fetch-race"}:
        policy.write_bytes(candidate)
    elif proposal == "deleted":
        policy.unlink()
    elif proposal == "symlink":
        policy.unlink()
        policy.symlink_to("../cli.py")
    elif proposal == "executable":
        policy.chmod(0o755)
    elif proposal == "oversized":
        policy.write_bytes(b"#" * 1_048_577)
    git("add", ".")
    git("commit", "-m", "proposal")
    head = git("rev-parse", "HEAD")
    git("switch", "main")
    git("merge", "--no-ff", "fork-proposal", "-m", "merge")
    merge = git("rev-parse", "HEAD")
    if proposal != "conflict":
        git("push", "origin", "HEAD:refs/pull/1/merge")
    checkout = tmp_path / "checkout"
    git("clone", "--depth=1", "--branch", "main", origin.as_uri(), str(checkout))
    # Replace the retry delay only for the local, immutable merge-ref fixture.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    sleeper = bin_dir / "sleep"
    sleeper.write_text("#!/bin/sh\nexit 0\n")
    sleeper.chmod(0o755)
    if proposal == "fetch-race":
        # The ref exists by the time ls-remote probes after the first failed fetch.
        git_wrapper = bin_dir / "git"
        git_wrapper.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = fetch ] && [ ! -e "$RUNNER_TEMP/retried" ]; then\n'
            '    touch "$RUNNER_TEMP/retried"\n'
            "    exit 1\n"
            "fi\n"
            'exec "$REAL_GIT" "$@"\n'
        )
        git_wrapper.chmod(0o755)
    outputs = tmp_path / "outputs"
    env = {
        "BASE": head if proposal == "stale-base" else base,
        "HEAD_SHA": base if proposal == "stale-head" else head,
        "PR": "1",
        "POLICY": "policies/agent.yaml",
        "GITHUB_OUTPUT": str(outputs),
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "RUNNER_TEMP": str(tmp_path),
        "REAL_GIT": shutil.which("git"),
    }
    result = _run_step(_step("detect", "inputs"), checkout, env)
    assert result.returncode == code, result.stderr
    values = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
    assert values["ref_status"] == ref_status
    assert values["changed"] == ("true" if proposal in {"changed", "fetch-race"} else "false")
    assert not (tmp_path / "candidate.yaml").exists()
    if proposal in {"changed", "fetch-race"}:
        assert values["merge"] == merge
        result = _run_step(_step("replay", "inputs"), checkout, {**env, "EXPECTED_MERGE": merge})
        assert result.returncode == 0, result.stderr
        assert (tmp_path / "base.yaml").read_bytes() == b"mode: enforce\n"
        assert (tmp_path / "candidate.yaml").read_bytes() == candidate
        result = _run_step(_step("replay", "inputs"), checkout, {**env, "EXPECTED_MERGE": head})
        assert result.returncode == 2
        assert "ref_status=stale" in outputs.read_text()
    assert (checkout / "cli.py").read_text() == "print('trusted CLI')\n"
    assert (checkout / SCRIPT).read_bytes() == (ROOT / SCRIPT).read_bytes()


@pytest.mark.parametrize(
    ("job", "result", "rc", "changed", "ref_status", "fork", "state", "desc"),
    [
        ("detect", "success", "", "false", "ok", "false", "success", "Policy file unchanged."),
        ("detect", "success", "", "true", "ok", "true", "error", "Fork policy change"),
        ("detect", "failure", "", "false", "stale", "false", "error", "Stale merge"),
        ("detect", "failure", "", "false", "conflict", "false", "error", "Merge ref missing"),
        ("replay", "success", "0", "true", "ok", "false", "success", COUNTS),
        ("replay", "failure", "1", "true", "ok", "false", "failure", f"Limit exceeded. {COUNTS}"),
        ("replay", "failure", "2", "true", "ok", "false", "error", "Unassessed"),
    ],
)
def test_posts_status_on_pr_head(tmp_path, job, result, rc, changed, ref_status, fork, state, desc):
    call = tmp_path / "call"
    step = _step(job, "status").copy()
    step["run"] = 'gh() { printf "%s\\n" "$@" > "$CALL"; }\n' + step["run"]
    env = {
        "CALL": str(call),
        "HEAD_SHA": "b" * 40,
        "GITHUB_REPOSITORY": "fixture/jrx",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_RUN_ID": "123",
        "RESULT": result,
        "REF_STATUS": ref_status,
        "IS_FORK": fork,
        "RC": rc,
        "CHANGED": changed,
        "COUNTS": COUNTS,
    }
    result = _run_step(step, tmp_path, env)
    assert result.returncode == 0, result.stderr
    args = call.read_text().splitlines()
    assert f"repos/fixture/jrx/statuses/{'b' * 40}" in args
    assert "context=jrx/policy-impact" in args
    assert f"state={state}" in args
    description = next(v.removeprefix("description=") for v in args if v.startswith("description="))
    assert description.startswith(desc)
    assert len(description) <= 140


@pytest.mark.parametrize(("shape", "valid"), [("regular", True), ("symlink", False)])
def test_evidence_step_reads_only_pinned_regular_blob(tmp_path, shape, valid):
    # Exercise the fetch and object selection without a live GitHub credential.
    # The branch tip advances beyond the pinned evidence before the step runs.
    remote = tmp_path / "host" / "fixture" / "evidence.git"
    remote.parent.mkdir(parents=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir()

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=workspace, capture_output=True, check=True, text=True
        ).stdout.strip()

    git("init", "--bare", str(remote))
    git("init", "-b", "main")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.test")
    git("config", "commit.gpgsign", "false")
    log = workspace / "audit.jsonl"
    if shape == "regular":
        log.write_bytes(b"PRIVATE-CANARY\n")
    else:
        log.symlink_to("other")
    git("add", ".")
    git("commit", "-m", "pinned")
    pin = git("rev-parse", "HEAD")
    assert git("ls-tree", pin, "--", "audit.jsonl").split()[0] == ("100644" if valid else "120000")
    log.unlink()
    log.write_text("newer\n")
    git("add", ".")
    git("commit", "-m", "next")
    git("push", str(remote), "main")
    env = {
        "REPOSITORY": "fixture/evidence",
        "SNAPSHOT": pin,
        "GITHUB_SERVER_URL": (tmp_path / "host").as_uri(),
        "RUNNER_TEMP": str(runner_temp),
        "JRX_EVIDENCE_TOKEN": "PRIVATE-CANARY-unused-placeholder",
    }
    result = _run_step(_step("replay", "evidence"), workspace, env)
    assert (result.returncode == 0) == valid, result.stderr
    assert "PRIVATE-CANARY" not in result.stdout + result.stderr
    audit = runner_temp / "evidence" / "audit.jsonl"
    if valid:
        assert audit.read_bytes() == b"PRIVATE-CANARY\n"
    else:
        assert not audit.exists()
    assert log.read_bytes() == b"newer\n"
