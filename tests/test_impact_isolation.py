"""Exercise policy impact's input and output boundaries through the CLI."""

import json
import os
import subprocess
import sys

import pytest
import yaml

from jev_reflex.policy_lint import lint_policy
from jev_reflex.serialization import MAX_CONFIG_BYTES


@pytest.mark.parametrize("side", ["baseline", "candidate"])
@pytest.mark.parametrize("problem", ["oversize", "duplicate", "unknown", "invalid_yaml"])
def test_malformed_policy_is_unassessed(impact_case, tmp_path, side, problem):
    _, baseline, candidate, run = impact_case
    path = baseline if side == "baseline" else candidate
    if problem == "oversize":
        # Every byte through the limit is valid input. Truncation would accept it.
        prefix = path.read_bytes() + b"\n# PRIVATE-CANARY"
        raw = prefix.ljust(MAX_CONFIG_BYTES + 1, b" ")
    elif problem == "duplicate":
        raw = b"mode: PRIVATE-CANARY\n" + yaml.safe_dump(json.loads(path.read_bytes())).encode()
    elif problem == "unknown":
        data = json.loads(path.read_bytes())
        data["audit"]["typo"] = "PRIVATE-CANARY"
        raw = json.dumps(data).encode()
    else:
        raw = b"audit: [PRIVATE-CANARY\n"
    path.write_bytes(raw)
    diagnostics = lint_policy(path)
    codes = {issue["code"] for issue in diagnostics["issues"]}
    expected = {
        "oversize": "invalid_structure",
        "duplicate": "duplicate_key",
        "unknown": "unknown_field",
        "invalid_yaml": "invalid_yaml",
    }
    assert expected[problem] in codes
    assert "PRIVATE-CANARY" not in json.dumps(diagnostics)
    output = tmp_path / "outputs"
    assert run("--github-output", str(output)).exit_code == 2
    assert not output.exists()


@pytest.mark.parametrize("proposal", ["matched", "paths", "https_schema", "file_schema"])
def test_candidate_cannot_initiate_io(impact_case, write_impact_entry, tmp_path, proposal):
    audit, baseline, candidate, _ = impact_case
    local = tmp_path / "PRIVATE-CANARY"
    local.write_text("fixture")
    remote = "https://example.invalid/PRIVATE-CANARY"
    data = json.loads(candidate.read_text())
    data.update(
        signing={"public_key_path": str(local), "private_key_path": str(local)},
        audit={"enabled": True, "path": str(local)},
        session={"enabled": True, "path": str(local)},
        access={
            "issuer": remote,
            "audience": "fixture",
            "jwks_uri": remote,
            "environment": "staging",
            "rules": [
                {
                    "role": "reader",
                    "actions": ["view"],
                    "repositories": ["*"],
                    "environments": ["*"],
                }
            ],
            "approval_db": str(local),
        },
    )
    if proposal == "matched":
        # The collector uses the same access and session settings. Only the
        # threshold changes, so the full replay must also complete offline.
        original = json.loads(baseline.read_text())
        original.update(access=data["access"], session=data["session"])
        del data["signing"]
        data["audit"] = original["audit"]
        audit.unlink()
        write_impact_entry(original)
        baseline.write_text(json.dumps(original))
    elif proposal.endswith("_schema"):
        data["mcp"] = {
            "tools": [
                {
                    "server": "fixture",
                    "name": "tool",
                    "effect": "read",
                    "argument_schema": {
                        "$ref": remote if proposal == "https_schema" else local.as_uri()
                    },
                }
            ]
        }
    candidate.write_text(json.dumps(data))
    output = tmp_path / "outputs"
    result = subprocess.run(
        [
            sys.executable,
            __file__,
            "policy",
            "impact",
            "--baseline",
            str(baseline),
            "--candidate",
            str(candidate),
            "--audit",
            str(audit),
            "--github-output",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert "PRIVATE-CANARY" not in result.stdout + result.stderr
    if proposal == "matched":
        assert result.returncode == 0, result.stderr
        assert output.read_text() == "counts=1/1 replayed, 1 new ALLOW, 0 new HOLD\n"
    else:
        assert result.returncode == 2, result.stderr
        assert "Unassessed" in result.stdout
        assert not output.exists()


if __name__ == "__main__":
    # Audit hooks cannot be removed. Arm the child interpreter when the CLI
    # first opens a policy, after imports finish. Exit on prohibited I/O even
    # when the calling library would catch an ordinary permission error.
    from jev_reflex.cli import app

    paths = {
        name: sys.argv[sys.argv.index("--" + name) + 1]
        for name in ("baseline", "candidate", "audit", "github-output")
    }
    policies = {paths["baseline"], paths["candidate"]}
    allowed_files = set(paths.values())
    armed = False

    def observe(event, args):
        global armed
        if event == "open" and args[0] in policies:
            armed = True
        if not armed or (event == "open" and args[0] in allowed_files):
            return
        if event.startswith("socket.") or event in (
            "open",
            "os.listdir",
            "os.scandir",
            "sqlite3.connect",
            "subprocess.Popen",
            "os.posix_spawn",
            "os.system",
        ):
            os._exit(86)

    sys.addaudithook(observe)
    app()
