"""OIDC authorization and reviewed execution across the public CLI."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from typer.testing import CliRunner

from jev_reflex import cli
from jev_reflex.cli import app
from jev_reflex.config import AccessConfig
from jev_reflex.enterprise import (
    AccessDenied,
    ApprovalStore,
    Identity,
    authorize,
    verified_identity,
)
from jev_reflex.models import EvaluationResult, RiskInfo

runner = CliRunner()


def _encode(value: object) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )


def _integer(value: int) -> str:
    return (
        base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))
        .rstrip(b"=")
        .decode()
    )


@pytest.fixture
def oidc(monkeypatch: pytest.MonkeyPatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "keys": [
                    {
                        "kid": "test",
                        "kty": "RSA",
                        "alg": "RS256",
                        "use": "sig",
                        "n": _integer(numbers.n),
                        "e": _integer(numbers.e),
                    }
                ]
            }

    monkeypatch.setattr("jev_reflex.enterprise.requests.get", lambda *args, **kwargs: Response())

    def token(subject: str, roles: list[str], **claims):
        header = _encode({"alg": "RS256", "kid": "test"})
        payload = {
            "iss": "https://idp.example",
            "aud": "jrx",
            "sub": subject,
            "exp": time.time() + 300,
            "roles": roles,
        }
        payload.update(claims)
        body = _encode(payload)
        signed = f"{header}.{body}".encode()
        signature = private_key.sign(signed, padding.PKCS1v15(), SHA256())
        value = f"{header}.{body}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"
        monkeypatch.setenv("JRX_ID_TOKEN", value)
        return value

    return token


def _config(tmp_path: Path, repo: Path, environment: str = "development") -> Path:
    path = tmp_path / "reflex.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "mode": "review",
                "access": {
                    "issuer": "https://idp.example",
                    "audience": "jrx",
                    "jwks_uri": "https://idp.example/jwks",
                    "environment": environment,
                    "approval_db": str(tmp_path / "approvals.sqlite3"),
                    "rules": [
                        {
                            "role": "developer",
                            "actions": ["execute"],
                            "repositories": [str(repo)],
                            "environments": ["development", "production"],
                        },
                        {
                            "role": "reviewer",
                            "actions": ["review"],
                            "repositories": [str(repo)],
                            "environments": ["development", "production"],
                        },
                    ],
                },
            }
        )
    )
    return path


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "tracked.txt").write_text("initial")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "initial",
        ],
        check=True,
    )
    return repo


def test_oidc_signature_claims_and_scope(oidc, tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    config = AccessConfig.model_validate(
        yaml.safe_load(_config(tmp_path, repo).read_text())["access"]
    )
    token = oidc("alice", ["developer"])
    assert verified_identity(config).subject == "alice"
    authorize(verified_identity(config), config, "execute", str(repo), "development")
    with pytest.raises(AccessDenied):
        authorize(verified_identity(config), config, "review", str(repo), "development")
    with pytest.raises(AccessDenied):
        authorize(
            verified_identity(config), config, "execute", str(tmp_path / "other"), "development"
        )
    with pytest.raises(AccessDenied):
        authorize(verified_identity(config), config, "execute", str(repo), "production")
    oidc("alice", ["developer"], exp=time.time() - 1)
    with pytest.raises(AccessDenied):
        verified_identity(config)
    oidc("alice", ["developer"], exp=float("nan"))
    with pytest.raises(AccessDenied):
        verified_identity(config)
    oidc("alice", ["developer"], aud="wrong")
    with pytest.raises(AccessDenied):
        verified_identity(config)
    os.environ["JRX_ID_TOKEN"] = token[:-3] + "abc"
    with pytest.raises(AccessDenied):
        verified_identity(config)


def test_production_requires_two_distinct_reviewers_and_one_time_use(
    oidc, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    config = _config(tmp_path, repo, "production")
    monkeypatch.setattr(
        cli,
        "_evaluate",
        lambda *args, **kwargs: EvaluationResult(decision="REVIEW", risk=RiskInfo(choice="medium")),
    )
    oidc("alice", ["developer"])
    args = ["--config", str(config), "--cwd", str(repo), "--environment", "production"]
    mislabeled = runner.invoke(
        app,
        [
            "approval",
            "request",
            "--command",
            sys.executable + " -c pass",
            "--config",
            str(config),
            "--cwd",
            str(repo),
            "--environment",
            "development",
        ],
    )
    assert mislabeled.exit_code == 2
    requested = runner.invoke(
        app, ["approval", "request", "--command", sys.executable + " -c pass", *args]
    )
    assert requested.exit_code == 0, requested.output
    approval_id = requested.stdout.strip()
    exec_args = ["exec", *args, "--approval-id", approval_id, "--", sys.executable, "-c", "pass"]
    assert runner.invoke(app, exec_args).exit_code == 2
    assert (
        runner.invoke(app, ["approval", "grant", approval_id, "--config", str(config)]).exit_code
        == 2
    )

    oidc("bob", ["reviewer"])
    pending = runner.invoke(app, ["approval", "pending", "--config", str(config)])
    assert pending.exit_code == 0
    assert json.loads(pending.stdout)[0]["id"] == approval_id
    assert json.loads(pending.stdout)[0]["summary"] == sys.executable + " -c pass"
    first = runner.invoke(app, ["approval", "grant", approval_id, "--config", str(config)])
    assert first.exit_code == 0 and "(1/2)" in first.stdout
    assert (
        runner.invoke(app, ["approval", "grant", approval_id, "--config", str(config)]).exit_code
        == 2
    )
    oidc("alice", ["developer"])
    assert runner.invoke(app, exec_args).exit_code == 2
    oidc("carol", ["reviewer"])
    second = runner.invoke(app, ["approval", "grant", approval_id, "--config", str(config)])
    assert second.exit_code == 0 and "(2/2)" in second.stdout
    oidc("alice", ["developer"])
    executed = runner.invoke(app, exec_args)
    assert executed.exit_code == 0, executed.output
    assert runner.invoke(app, exec_args).exit_code == 2


def test_enterprise_hook_denies_unverified_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    config = _config(tmp_path, repo)
    monkeypatch.delenv("JRX_ID_TOKEN", raising=False)
    payload = json.dumps(
        {"cwd": str(repo), "tool_name": "Bash", "tool_input": {"command": "echo ok"}}
    )
    result = runner.invoke(app, ["codex-hook", "--config", str(config)], input=payload)
    assert result.exit_code == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_approved_hook_allows_once(oidc, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path)
    config = _config(tmp_path, repo)
    command = "python deploy.py"
    oidc("alice", ["developer"])
    requested = runner.invoke(
        app,
        [
            "approval",
            "request",
            "--config",
            str(config),
            "--cwd",
            str(repo),
            "--environment",
            "development",
            "--hook-command",
            "--command",
            command,
        ],
    )
    assert requested.exit_code == 0, requested.output
    approval_id = requested.stdout.strip()
    oidc("bob", ["reviewer"])
    assert (
        runner.invoke(app, ["approval", "grant", approval_id, "--config", str(config)]).exit_code
        == 0
    )
    oidc("alice", ["developer"])
    monkeypatch.setenv("JRX_ENVIRONMENT", "development")
    monkeypatch.setenv("JRX_APPROVAL_ID", approval_id)
    monkeypatch.setattr(
        cli,
        "evaluate_codex_hook",
        lambda *args, **kwargs: (
            EvaluationResult(decision="REVIEW", risk=RiskInfo(choice="medium")),
            {"hookSpecificOutput": {"permissionDecision": "deny"}},
        ),
    )
    payload = json.dumps(
        {"cwd": str(repo), "tool_name": "Bash", "tool_input": {"command": command}}
    )
    first = runner.invoke(app, ["codex-hook", "--config", str(config)], input=payload)
    assert first.exit_code == 0 and json.loads(first.stdout) == {}
    second = runner.invoke(app, ["codex-hook", "--config", str(config)], input=payload)
    assert json.loads(second.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_approval_rejects_repository_or_policy_change(
    oidc, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    config = _config(tmp_path, repo)
    monkeypatch.setattr(
        cli,
        "_evaluate",
        lambda *args, **kwargs: EvaluationResult(decision="REVIEW", risk=RiskInfo(choice="medium")),
    )
    oidc("alice", ["developer"])
    args = ["--config", str(config), "--cwd", str(repo), "--environment", "development"]
    requested = runner.invoke(
        app, ["approval", "request", "--command", sys.executable + " -c pass", *args]
    )
    assert requested.exit_code == 0, requested.output
    approval_id = requested.stdout.strip()
    oidc("bob", ["reviewer"])
    assert (
        runner.invoke(app, ["approval", "grant", approval_id, "--config", str(config)]).exit_code
        == 0
    )
    oidc("alice", ["developer"])
    exec_args = ["exec", *args, "--approval-id", approval_id, "--", sys.executable, "-c", "pass"]
    altered_args = [
        "exec",
        *args,
        "--approval-id",
        approval_id,
        "--",
        sys.executable,
        "-c",
        "print(1)",
    ]
    assert runner.invoke(app, altered_args).exit_code == 2
    (repo / "tracked.txt").write_text("changed")
    assert runner.invoke(app, exec_args).exit_code == 2
    (repo / "tracked.txt").write_text("initial")
    settings = yaml.safe_load(config.read_text())
    settings["thresholds"] = {"review": 0.6}
    config.write_text(yaml.safe_dump(settings))
    assert runner.invoke(app, exec_args).exit_code == 2


def test_expired_approval_cannot_be_granted_or_used(
    oidc, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    config = _config(tmp_path, repo)
    monkeypatch.setattr(
        cli,
        "_evaluate",
        lambda *args, **kwargs: EvaluationResult(decision="REVIEW", risk=RiskInfo(choice="medium")),
    )
    oidc("alice", ["developer"])
    args = ["--config", str(config), "--cwd", str(repo), "--environment", "development"]
    requested = runner.invoke(
        app, ["approval", "request", "--command", sys.executable + " -c pass", *args]
    )
    assert requested.exit_code == 0, requested.output
    approval_id = requested.stdout.strip()
    with sqlite3.connect(tmp_path / "approvals.sqlite3") as connection:
        connection.execute("UPDATE approvals SET expires=0 WHERE id=?", (approval_id,))
    oidc("bob", ["reviewer"])
    assert (
        runner.invoke(app, ["approval", "grant", approval_id, "--config", str(config)]).exit_code
        == 2
    )
    oidc("alice", ["developer"])
    assert (
        runner.invoke(
            app,
            ["exec", *args, "--approval-id", approval_id, "--", sys.executable, "-c", "pass"],
        ).exit_code
        == 2
    )


def test_enforce_mode_rejects_degraded_evaluation_even_with_approval(
    oidc, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    config = _config(tmp_path, repo)
    settings = yaml.safe_load(config.read_text())
    settings["mode"] = "enforce"
    config.write_text(yaml.safe_dump(settings))
    monkeypatch.setattr(
        cli,
        "_evaluate",
        lambda *args, **kwargs: EvaluationResult(
            decision="REVIEW", risk=RiskInfo(choice="medium"), degraded=True
        ),
    )
    oidc("alice", ["developer"])
    args = ["--config", str(config), "--cwd", str(repo), "--environment", "development"]
    requested = runner.invoke(
        app, ["approval", "request", "--command", sys.executable + " -c pass", *args]
    )
    assert requested.exit_code == 0, requested.output
    approval_id = requested.stdout.strip()
    oidc("bob", ["reviewer"])
    assert (
        runner.invoke(app, ["approval", "grant", approval_id, "--config", str(config)]).exit_code
        == 0
    )
    oidc("alice", ["developer"])
    result = runner.invoke(
        app,
        ["exec", *args, "--approval-id", approval_id, "--", sys.executable, "-c", "pass"],
    )
    assert result.exit_code == 2
    assert "semantic evaluation is unavailable" in result.output


def test_concurrent_consumers_cannot_reuse_approval(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    access = AccessConfig.model_validate(
        yaml.safe_load(_config(tmp_path, repo).read_text())["access"]
    )
    store = ApprovalStore(access)
    requester = Identity("alice", frozenset({"developer"}))
    reviewer = Identity("bob", frozenset({"reviewer"}))
    approval_id = store.request(requester, str(repo), "development", "fixed-binding", "echo ok")
    store.grant(approval_id, reviewer)

    def consume() -> bool:
        try:
            store.consume(approval_id, requester, "fixed-binding")
            return True
        except AccessDenied:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: consume(), range(2)))
    assert results.count(True) == 1
