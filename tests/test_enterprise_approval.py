"""OIDC authorization and reviewed execution across the public CLI."""

from __future__ import annotations

import base64
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from io import BytesIO
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from typer.testing import CliRunner

from jev_reflex import cli, mcp_gateway
from jev_reflex.cli import app
from jev_reflex.config import AccessConfig, load_config
from jev_reflex.enterprise import (
    AccessDenied,
    ApprovalStore,
    Identity,
    authorize,
    verified_identity,
)
from jev_reflex.models import EvaluationResult, RiskInfo
from jev_reflex.session_limits import SessionStore

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


def test_approval_operations_close_connections_on_success_and_failure(tmp_path, monkeypatch):
    config = AccessConfig(
        issuer="https://idp.example",
        audience="jrx",
        jwks_uri="https://idp.example/jwks",
        approval_db=str(tmp_path / "approvals.sqlite3"),
        environment="development",
        rules=[
            {
                "role": "reviewer",
                "actions": ["review"],
                "repositories": ["*"],
                "environments": ["*"],
            }
        ],
    )
    store = ApprovalStore(config)
    connections = []
    original = store._connect

    def connect():
        connection = original()
        connections.append(connection)
        return connection

    monkeypatch.setattr(store, "_connect", connect)
    identity = Identity("requester", frozenset())
    approval_id = store.request(identity, "repo", "development", "binding", "summary")
    assert store.pending(identity) == []
    with pytest.raises(AccessDenied):
        store.grant(approval_id, identity)
    with pytest.raises(AccessDenied):
        store.consume(approval_id, identity, "binding")
    try:
        for connection in connections:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                connection.execute("SELECT 1")
    finally:
        for connection in connections:
            connection.close()


RELEASE_ARGS = {
    "repository": "example/widgets",
    "tag": "v1.2.3",
    "notes": "Fix empty release listings.",
    "options": {"assets": ["linux", "mac"], "draft": True, "build": 1},
}
LIVE_ALLOW = EvaluationResult(decision="ALLOW", risk=RiskInfo(choice="low"), semantic_source="jev")
FAKE_RELEASE_SERVER = Path(__file__).resolve().parents[1] / "examples/mcp_release_approval.py"


def _release_request(arguments=None, *, request_id=1, tool="publish_release"):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": RELEASE_ARGS if arguments is None else arguments},
    }


@pytest.fixture
def release(tmp_path, monkeypatch, oidc):
    repo = _repo(tmp_path)
    monkeypatch.chdir(repo)
    monkeypatch.setattr(mcp_gateway, "evaluate_context", lambda *args, **kwargs: LIVE_ALLOW)
    config = _config(tmp_path, repo)
    calls = tmp_path / "received.jsonl"
    upstream = [sys.executable, str(FAKE_RELEASE_SERVER), "--fake-upstream", str(calls)]
    settings = yaml.safe_load(config.read_text())
    rule = {
        "server": "github-demo",
        "name": "publish_release",
        "effect": "write",
        "require_approval": True,
        "argument_schema": {
            "type": "object",
            "required": ["repository", "tag", "notes"],
            "properties": {field: {"type": "string"} for field in ("repository", "tag", "notes")},
        },
    }
    settings["mcp"] = {"tools": [rule]}
    oidc("alice", ["developer"])

    def write_policy():
        config.write_text(yaml.safe_dump(settings))

    def approval(*args):
        return runner.invoke(app, ["approval", *args, "--config", str(config)])

    def send(*requests, approval_id=None, server="github-demo", drop_reply=False, exit_codes=(0,)):
        argv = ["mcp", "serve", "--server", server, "--config", str(config)]
        if approval_id is not None:
            argv += ["--approval-id", approval_id]
        result = runner.invoke(
            app,
            [*argv, "--", *upstream, *(["--drop-reply"] if drop_reply else [])],
            input="".join(
                (request if isinstance(request, str) else json.dumps(request)) + "\n"
                for request in requests
            ),
        )
        assert result.exit_code in exit_codes, (result.output, result.exception)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def recorded():
        return (
            [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        )

    def request(affected_call=None):
        (response,) = send(affected_call or _release_request())
        status = response["result"]["structuredContent"]
        assert status["status"] == "pending_approval"
        assert recorded() == []
        return status["approval_id"]

    def grant(approval_id, reviewer="bob"):
        oidc(reviewer, ["reviewer"])
        result = approval("grant", approval_id)
        assert result.exit_code == 0, result.output
        oidc("alice", ["developer"])

    write_policy()
    return {
        "send": send,
        "request": request,
        "approval": approval,
        "grant": grant,
        "recorded": recorded,
        "write_policy": write_policy,
        "settings": settings,
        "rule": rule,
        "config": config,
        "upstream": upstream,
    }


def _mcp_error(response):
    assert response["result"]["isError"]
    return response["result"]["content"][0]["text"]


def test_mcp_release_approval_via_gateway_and_cli(release, oidc):
    approval_id = release["request"]()
    oidc("bob", ["reviewer"])
    pending = release["approval"]("pending")
    assert pending.exit_code == 0, pending.output
    (review,) = json.loads(pending.stdout)
    assert review["id"] == approval_id
    assert review["requester"] == "alice"
    assert review["repository"] == str(Path.cwd())
    assert review["environment"] == "development"
    assert json.loads(review["summary"]) == {
        "server": "github-demo",
        "tool": "publish_release",
        "arguments": RELEASE_ARGS,
    }
    release["grant"](approval_id)

    reordered = dict(reversed(list(RELEASE_ARGS.items())))
    reordered["options"] = dict(reversed(list(RELEASE_ARGS["options"].items())))
    retry = _release_request(reordered, request_id=2)
    replay = _release_request(request_id=3)
    responses = {
        item["id"]: item for item in release["send"](retry, replay, approval_id=approval_id)
    }
    assert responses[2]["result"]["content"][0]["text"] == "Fake release published"
    assert "already consumed" in _mcp_error(responses[3])
    assert release["recorded"]() == [retry]


def test_mcp_approval_rejects_changed_arguments(release):
    approval_id = release["request"]()
    release["grant"](approval_id)
    variants = [
        {**RELEASE_ARGS, "repository": "elsewhere/widgets"},
        {**RELEASE_ARGS, "tag": "v1.2.4"},
        {**RELEASE_ARGS, "notes": "Different release notes."},
        {**RELEASE_ARGS, "options": {**RELEASE_ARGS["options"], "draft": 1}},
        {**RELEASE_ARGS, "options": {**RELEASE_ARGS["options"], "build": 1.0}},
        {**RELEASE_ARGS, "options": {**RELEASE_ARGS["options"], "assets": ["mac", "linux"]}},
    ]
    requests = [_release_request(args, request_id=i) for i, args in enumerate(variants)]
    responses = release["send"](*requests, approval_id=approval_id)
    assert len(responses) == len(variants)
    assert all("does not match" in _mcp_error(response) for response in responses)
    assert release["recorded"]() == []
    replacement = release["request"](_release_request(variants[1]))
    assert replacement != approval_id


def test_mcp_approval_distinguishes_exact_decimal_values(release):
    request = json.dumps(_release_request({**RELEASE_ARGS, "build": 1.0}))
    precise = request.replace('"build": 1.0', '"build": 1.00000000000000001')
    approval_id = release["request"](precise)
    release["grant"](approval_id)
    (denied,) = release["send"](request, approval_id=approval_id)
    assert "does not match" in _mcp_error(denied)
    assert release["recorded"]() == []


def test_mcp_production_approval_requires_two_independent_reviewers(release, oidc):
    release["settings"]["access"]["environment"] = "production"
    release["write_policy"]()
    approval_id = release["request"]()
    oidc("alice", ["developer", "reviewer"])
    assert release["approval"]("grant", approval_id).exit_code == 2
    release["grant"](approval_id)
    oidc("bob", ["reviewer"])
    assert release["approval"]("grant", approval_id).exit_code == 2
    oidc("alice", ["developer"])
    (waiting,) = release["send"](_release_request(), approval_id=approval_id)
    assert "waiting for reviewers" in _mcp_error(waiting)
    assert release["recorded"]() == []

    release["grant"](approval_id, "carol")
    oidc("dave", ["developer"])
    (wrong,) = release["send"](_release_request(), approval_id=approval_id)
    assert "does not match this requester" in _mcp_error(wrong)
    assert release["recorded"]() == []
    oidc("alice", ["developer"])
    release["send"](_release_request(), approval_id=approval_id)
    assert release["recorded"]() == [_release_request()]


def test_mcp_expired_approval_cannot_dispatch(release):
    approval_id = release["request"]()
    release["grant"](approval_id)
    with sqlite3.connect(release["settings"]["access"]["approval_db"]) as connection:
        connection.execute("UPDATE approvals SET expires=0 WHERE id=?", (approval_id,))
    (expired,) = release["send"](_release_request(), approval_id=approval_id)
    assert "expired" in _mcp_error(expired)
    assert release["recorded"]() == []


def test_mcp_approval_binds_server_tool_and_access_scope(release, monkeypatch, tmp_path):
    settings = release["settings"]
    settings["mcp"]["tools"] += [
        {**deepcopy(release["rule"]), "server": "another-server"},
        {**deepcopy(release["rule"]), "name": "edit_release"},
    ]
    for rule in settings["access"]["rules"]:
        rule["repositories"] = ["*"]
    release["write_policy"]()
    approval_id = release["request"]()
    release["grant"](approval_id)

    (wrong_server,) = release["send"](
        _release_request(), server="another-server", approval_id=approval_id
    )
    (wrong_tool,) = release["send"](_release_request(tool="edit_release"), approval_id=approval_id)
    with monkeypatch.context() as other_scope:
        other_scope.chdir(tmp_path)
        (wrong_repository,) = release["send"](_release_request(), approval_id=approval_id)
    settings["access"]["environment"] = "production"
    release["write_policy"]()
    (wrong_environment,) = release["send"](_release_request(), approval_id=approval_id)
    for response in (wrong_server, wrong_tool, wrong_repository, wrong_environment):
        assert "does not match this requester or action" in _mcp_error(response)
    assert release["recorded"]() == []


def test_mcp_approval_cannot_bypass_current_gateway_checks(release, monkeypatch, oidc):
    approval_id = release["request"]()
    release["grant"](approval_id)
    for result in [
        LIVE_ALLOW.model_copy(update={"decision": "HOLD"}),
        LIVE_ALLOW.model_copy(update={"decision": "REVIEW"}),
        LIVE_ALLOW.model_copy(update={"degraded": True}),
        LIVE_ALLOW.model_copy(update={"semantic_source": "demo"}),
    ]:
        monkeypatch.setattr(
            mcp_gateway, "evaluate_context", lambda *args, decision=result, **kwargs: decision
        )
        (denied,) = release["send"](_release_request(), approval_id=approval_id)
        assert "blocked" in _mcp_error(denied) or "live semantic decision" in _mcp_error(denied)
    monkeypatch.setattr(mcp_gateway, "evaluate_context", lambda *args, **kwargs: LIVE_ALLOW)

    (invalid,) = release["send"](
        _release_request({**RELEASE_ARGS, "tag": 123}), approval_id=approval_id
    )
    assert "arguments do not match policy" in _mcp_error(invalid)
    oidc("alice", ["reviewer"])
    (denied,) = release["send"](_release_request(), approval_id=approval_id)
    assert "policy or session check failed" in _mcp_error(denied)
    oidc("alice", ["developer"])

    release["rule"]["argument_constraints"] = {"/tag": ["v2"]}
    release["write_policy"]()
    (denied,) = release["send"](_release_request(), approval_id=approval_id)
    assert "arguments do not match policy" in _mcp_error(denied)
    release["rule"].pop("argument_constraints")
    release["settings"]["thresholds"] = {"review": 0.6}
    release["write_policy"]()
    (changed,) = release["send"](_release_request(), approval_id=approval_id)
    assert "does not match this requester or action" in _mcp_error(changed)
    assert release["recorded"]() == []

    release["settings"].pop("thresholds")
    release["write_policy"]()
    release["send"](_release_request(), approval_id=approval_id)
    assert release["recorded"]() == [_release_request()]


def test_mcp_stopped_session_cannot_dispatch_approved_call(release, monkeypatch, tmp_path):
    release["settings"]["session"] = {"enabled": True, "path": str(tmp_path / "sessions.sqlite3")}
    release["write_policy"]()
    monkeypatch.setenv("JRX_SESSION_ID", "release-session")
    approval_id = release["request"]()
    release["grant"](approval_id)
    SessionStore(load_config(release["config"]).session).stop("release-session")
    (stopped,) = release["send"](
        _release_request(), approval_id=approval_id, exit_codes=(0, -signal.SIGTERM)
    )
    assert "policy or session check failed" in _mcp_error(stopped)
    assert release["recorded"]() == []


def test_mcp_concurrent_gateway_retries_dispatch_at_most_once(release, monkeypatch):
    approval_id = release["request"]()
    release["grant"](approval_id)
    concurrent = threading.Barrier(2)
    config = load_config(release["config"])

    def evaluate(*args, **kwargs):
        concurrent.wait(timeout=10)
        return LIVE_ALLOW

    monkeypatch.setattr(mcp_gateway, "evaluate_context", evaluate)

    def retry(request_id):
        source = BytesIO((json.dumps(_release_request(request_id=request_id)) + "\n").encode())
        sink = BytesIO()
        gateway = mcp_gateway.MCPGateway(
            config,
            "github-demo",
            release["upstream"],
            approval_id=approval_id,
            source=source,
            sink=sink,
        )
        assert gateway.run() == 0
        return json.loads(sink.getvalue())

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(retry, (10, 11)))
    (success,) = [response for response in responses if not response["result"].get("isError")]
    (denied,) = [response for response in responses if response["result"].get("isError")]
    assert "already consumed" in _mcp_error(denied)
    assert release["recorded"]() == [_release_request(request_id=success["id"])]


def test_mcp_lost_reply_leaves_approval_spent(release):
    approval_id = release["request"]()
    release["grant"](approval_id)
    (response,) = release["send"](_release_request(), approval_id=approval_id, drop_reply=True)
    assert response["result"]["structuredContent"] == {"status": "outcome_unknown"}
    assert "Approval spent" in _mcp_error(response)
    (replay,) = release["send"](_release_request(), approval_id=approval_id, drop_reply=True)
    assert "already consumed" in _mcp_error(replay)
    assert release["recorded"]() == [_release_request()]


def test_mcp_approval_rejects_secret_content_and_request_supplied_metadata(release, oidc):
    secret_request = _release_request({**RELEASE_ARGS, "notes": "authorization: private-value"})
    secret_field = _release_request({**RELEASE_ARGS, "extra": {"client_token": "private-value"}})
    metadata = _release_request(request_id=3)
    metadata["params"]["_meta"] = {"approval_id": "pretend"}
    duplicate = json.dumps(_release_request()).replace(
        '"method": "tools/call"', '"method": "tools/call", "method": "initialize"'
    )
    secret, field, injected, bad_json = release["send"](
        secret_request, secret_field, metadata, duplicate
    )
    assert "cannot be reviewed safely" in _mcp_error(secret)
    assert "cannot be reviewed safely" in _mcp_error(field)
    assert "only supports plain tools/call" in _mcp_error(injected)
    assert bad_json["error"]["code"] == -32700
    assert "private-value" not in str([secret, field])
    assert release["recorded"]() == []
    oidc("bob", ["reviewer"])
    assert json.loads(release["approval"]("pending").stdout) == []


def test_mcp_live_write_without_opt_in_forwards_as_before(release):
    release["rule"].pop("require_approval")
    release["write_policy"]()
    assert "require_approval" not in load_config(release["config"]).model_dump()["mcp"]["tools"][0]
    request = _release_request()
    (response,) = release["send"](request)
    assert not response["result"].get("isError")
    assert release["recorded"]() == [request]


def test_mcp_approval_rejects_sensitive_fields_before_evaluation(release, monkeypatch, oidc):
    evaluated = []

    def evaluate(context, **kwargs):
        evaluated.append(context)
        return LIVE_ALLOW

    monkeypatch.setattr(mcp_gateway, "evaluate_context", evaluate)
    values = [["sample"], {"primary": "sample"}, 123456, "$sample"]
    requests = [
        _release_request({**RELEASE_ARGS, "extra": [{"access_token": value}]}, request_id=i)
        for i, value in enumerate(values)
    ]
    replies = release["send"](*requests)
    assert len(replies) == len(requests)
    assert all("cannot be reviewed safely" in _mcp_error(reply) for reply in replies)
    assert evaluated == []
    assert release["recorded"]() == []
    oidc("bob", ["reviewer"])
    assert json.loads(release["approval"]("pending").stdout) == []
