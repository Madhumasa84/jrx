"""End-to-end coverage for replay, staged activation, and operations status."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from jev_reflex.audit import AuditLog
from jev_reflex.cli import app
from jev_reflex.config import BootstrapConfig, ReflexConfig, load_config
from jev_reflex.dashboard import DashboardConfig, make_handler, snapshot
from jev_reflex.enterprise import AccessDenied, Identity
from jev_reflex.policy import decide
from jev_reflex.policy_rollout import RolloutStore, policy_hash, simulate
from jev_reflex.signing import Ed25519Signer, sign_file


def _policy(tmp_path: Path, review: float = 0.5) -> ReflexConfig:
    return ReflexConfig.model_validate(
        {
            "mode": "enforce",
            "audit": {"enabled": True, "path": str(tmp_path / "audit.jsonl")},
            "thresholds": {"review": review, "strong": 0.9},
        }
    )


def _decision(config: ReflexConfig, signal: float = 0.6) -> None:
    findings = []
    signals = {"unsafe": signal}
    AuditLog(config).write_entry(
        "safe command",
        findings,
        signals,
        decide(findings, signals, config),
        risk_choice="low",
        risk_confidence=0.95,
        degraded=False,
        forced_review=False,
    )


def test_simulate_reports_changes_and_rejects_tampering(tmp_path: Path) -> None:
    baseline = _policy(tmp_path)
    candidate = _policy(tmp_path, review=0.7)
    _decision(baseline)
    report = simulate(tmp_path / "audit.jsonl", baseline, candidate)
    assert report["replayed"] == 1
    assert report["new_allows"] == 1
    assert report["changes"]["REVIEW_to_ALLOW"] == 1

    log = tmp_path / "audit.jsonl"
    log.write_text(log.read_text().replace("safe command", "changed command"))
    with pytest.raises(ValueError, match="audit chain"):
        simulate(log, baseline, candidate)


def test_rollout_store_canary_promotion_rollback_and_permissions(tmp_path: Path) -> None:
    baseline = _policy(tmp_path)
    candidate = _policy(tmp_path, review=0.7)
    store = RolloutStore(tmp_path / "state.json")
    store.stage(baseline, candidate)
    store.promote(10)
    selected = {policy_hash(store.select(f"repository-{index}")) for index in range(1000)}
    assert selected == {policy_hash(baseline), policy_hash(candidate)}
    assert policy_hash(store.select("repository-1")) == policy_hash(store.select("repository-1"))
    store.rollback()
    assert store.status()["candidate_hash"] is None
    assert policy_hash(store.select("repository-1")) == policy_hash(baseline)
    store.stage(baseline, candidate)
    store.promote(100)
    assert store.status()["active_hash"] == policy_hash(candidate)
    store.rollback()
    assert store.status()["active_hash"] == policy_hash(baseline)
    store.path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        store.status()


def test_runtime_selects_promoted_revision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    baseline = _policy(tmp_path)
    candidate = _policy(tmp_path, review=0.7)
    policy_path = tmp_path / "reflex.yaml"
    policy_path.write_text(yaml.safe_dump(baseline.model_dump(mode="json")))
    state_path = tmp_path / "state.json"
    store = RolloutStore(state_path)
    store.stage(baseline, candidate)
    store.promote(100)
    monkeypatch.setattr(
        "jev_reflex.config.load_bootstrap_config",
        lambda: BootstrapConfig(rollout_state_path=str(state_path)),
    )
    assert load_config(policy_path, scope="repo-a").thresholds.review == 0.7
    store.rollback()
    assert load_config(policy_path, scope="repo-a").thresholds.review == 0.5


def test_signed_policy_stage_gate_and_cli(tmp_path: Path) -> None:
    baseline = _policy(tmp_path)
    candidate = _policy(tmp_path, review=0.7)
    _decision(baseline)
    baseline_path = tmp_path / "baseline.yaml"
    candidate_path = tmp_path / "candidate.yaml"
    baseline_path.write_text(yaml.safe_dump(baseline.model_dump(mode="json")))
    candidate_path.write_text(yaml.safe_dump(candidate.model_dump(mode="json")))
    signer = Ed25519Signer()
    sign_file(candidate_path, signer)
    bootstrap = tmp_path / "bootstrap.yaml"
    bootstrap.write_text(
        yaml.safe_dump(
            {
                "rollout_state_path": str(tmp_path / "state.json"),
                "policy_source": {
                    "type": "local",
                    "uri": str(candidate_path),
                    "pinned_signature_pubkey": signer.get_public_key_pem(),
                },
            }
        )
    )
    runner = CliRunner()
    command = [
        "policy",
        "rollout",
        "stage",
        "--bootstrap",
        str(bootstrap),
        "--baseline",
        str(baseline_path),
        "--audit",
        str(tmp_path / "audit.jsonl"),
    ]
    blocked = runner.invoke(app, command)
    assert blocked.exit_code == 2
    staged = runner.invoke(app, [*command, "--max-new-allows", "1"])
    assert staged.exit_code == 0, staged.output
    assert json.loads(staged.output)["status"]["candidate_hash"] == policy_hash(candidate)
    promoted = runner.invoke(
        app, ["policy", "rollout", "promote", "--bootstrap", str(bootstrap), "--percent", "100"]
    )
    assert promoted.exit_code == 0, promoted.output
    rolled_back = runner.invoke(
        app, ["policy", "rollout", "rollback", "--bootstrap", str(bootstrap)]
    )
    assert rolled_back.exit_code == 0, rolled_back.output
    candidate_path.write_text(candidate_path.read_text() + "\n# tampered\n")
    invalid = runner.invoke(app, command)
    assert invalid.exit_code == 2


def test_dashboard_scopes_approvals_and_rejects_bad_audit(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    _decision(policy)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy.model_dump(mode="json")))
    database = tmp_path / "approvals.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE approvals (id TEXT, requester TEXT, repository TEXT, environment TEXT, summary TEXT, expires REAL, required INTEGER, consumed INTEGER)"
        )
        connection.execute("CREATE TABLE grants (approval_id TEXT, reviewer TEXT)")
        for repo in ("repo-a", "repo-b"):
            connection.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                (repo, "requester", repo, "production", "deploy", time.time() + 1000, 2),
            )
    access = {
        "issuer": "https://idp.example",
        "audience": "jrx",
        "jwks_uri": "https://idp.example/jwks",
        "environment": "dashboard",
        "rules": [
            {
                "role": "ops",
                "actions": ["view"],
                "repositories": ["repo-a"],
                "environments": ["dashboard"],
            }
        ],
    }
    config = DashboardConfig.model_validate(
        {
            "access": access,
            "sources": [
                {
                    "team": "a",
                    "repository": "repo-a",
                    "policy_path": str(policy_path),
                    "audit_path": str(tmp_path / "audit.jsonl"),
                    "approval_db": str(database),
                },
                {
                    "team": "b",
                    "repository": "repo-b",
                    "policy_path": str(policy_path),
                    "audit_path": str(tmp_path / "audit.jsonl"),
                    "approval_db": str(database),
                },
            ],
        }
    )
    result = snapshot(config, Identity("operator", frozenset({"ops"})))
    assert len(result["teams"]) == 1
    assert [item["id"] for item in result["teams"][0]["pending_approvals"]] == ["repo-a"]
    assert result["teams"][0]["decisions"]["REVIEW"] == 1
    path = tmp_path / "audit.jsonl"
    path.write_text(path.read_text().replace("safe command", "changed command"))
    result = snapshot(config, Identity("operator", frozenset({"ops"})))
    assert result["teams"][0]["audit_integrity"]["valid"] is False
    assert "decisions" not in result["teams"][0]


def test_dashboard_http_requires_bearer_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = DashboardConfig.model_validate(
        {
            "access": {
                "issuer": "https://idp.example",
                "audience": "jrx",
                "jwks_uri": "https://idp.example/jwks",
                "environment": "dashboard",
                "rules": [
                    {
                        "role": "ops",
                        "actions": ["view"],
                        "repositories": ["repo-a"],
                        "environments": ["dashboard"],
                    }
                ],
            },
            "sources": [
                {
                    "team": "a",
                    "repository": "repo-a",
                    "policy_path": str(tmp_path / "policy.yaml"),
                    "audit_path": str(tmp_path / "audit.jsonl"),
                }
            ],
        }
    )
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump(_policy(tmp_path).model_dump(mode="json")))

    def verify(_access, token):
        if token != "valid":
            raise AccessDenied("invalid token")
        return Identity("operator", frozenset({"ops"}))

    monkeypatch.setattr("jev_reflex.dashboard.verified_identity", verify)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(config))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    endpoint = f"http://127.0.0.1:{server.server_port}/api/summary"
    try:
        with pytest.raises(urllib.error.HTTPError) as missing:
            urllib.request.urlopen(endpoint, timeout=2)
        assert missing.value.code == 401
        request = urllib.request.Request(endpoint, headers={"Authorization": "Bearer invalid"})
        with pytest.raises(urllib.error.HTTPError) as invalid:
            urllib.request.urlopen(request, timeout=2)
        assert invalid.value.code == 403
        request = urllib.request.Request(endpoint, headers={"Authorization": "Bearer valid"})
        with urllib.request.urlopen(request, timeout=2) as response:
            assert response.headers["Cache-Control"] == "no-store"
            assert json.load(response)["teams"][0]["team"] == "a"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_dashboard_uses_broker_health_and_bounded_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _policy(tmp_path)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy.model_dump(mode="json")))
    config = DashboardConfig.model_validate(
        {
            "access": {
                "issuer": "https://idp.example",
                "audience": "jrx",
                "jwks_uri": "https://idp.example/jwks",
                "environment": "dashboard",
                "rules": [
                    {
                        "role": "ops",
                        "actions": ["view"],
                        "repositories": ["repo-a"],
                        "environments": ["dashboard"],
                    }
                ],
            },
            "sources": [
                {
                    "team": "a",
                    "repository": "repo-a",
                    "policy_path": str(policy_path),
                    "audit_path": str(tmp_path / "audit.jsonl"),
                    "broker_socket": str(tmp_path / "broker.sock"),
                    "metrics_port": 9090,
                }
            ],
        }
    )
    monkeypatch.setattr("jev_reflex.dashboard.BrokerClient.health", lambda _: {"running": True})

    class Response:
        content = b"jrx_broker_uptime_seconds 12\nunrelated_metric 99\n"
        text = content.decode()

        def raise_for_status(self):
            return None

    monkeypatch.setattr("jev_reflex.dashboard.requests.get", lambda *args, **kwargs: Response())
    team = snapshot(config, Identity("operator", frozenset({"ops"})))["teams"][0]
    assert team["broker"]["running"] is True
    assert team["metrics"] == {"jrx_broker_uptime_seconds": 12.0}
