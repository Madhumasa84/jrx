"""Regression tests for confirmed configuration, rollout and YAML review findings."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from jev_reflex import config as config_module
from jev_reflex.audit import AuditLog
from jev_reflex.cli import app
from jev_reflex.config import (
    BootstrapConfig,
    PolicySourceConfig,
    ReflexConfig,
    load_bootstrap_config,
    load_config,
)
from jev_reflex.models import EvaluationResult
from jev_reflex.policy import decide
from jev_reflex.policy_lint import lint_policy
from jev_reflex.serialization import safe_yaml_load
from jev_reflex.signing import Ed25519Signer, sign_file
from jev_reflex.stability import build_report


def _use_bootstrap(monkeypatch: pytest.MonkeyPatch, bootstrap: BootstrapConfig) -> None:
    monkeypatch.setattr(config_module, "load_bootstrap_config", lambda: bootstrap)


def _record(config: ReflexConfig, signals: dict[str, float], risk: str = "low") -> None:
    AuditLog(config).write_entry(
        "fixture action",
        [],
        signals,
        decide([], signals, config, risk_choice=risk, risk_confidence=0.95),
        risk_choice=risk,
        risk_confidence=0.95,
        degraded=False,
        forced_review=False,
    )


def _write_policy(path: Path, config: ReflexConfig) -> Path:
    path.write_text(yaml.safe_dump(config.model_dump(mode="json")))
    return path


def _operator_controlled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Evaluate as a uid that owns none of the test files (operator-written state)."""
    import os

    from jev_reflex import trust

    other = os.geteuid() + 100_000
    monkeypatch.setattr(trust, "evaluator_identity", lambda: trust.Identity(other, frozenset()))


# Finding 1: unsigned rollout state replaced the signature-verified policy.


def test_forged_unsigned_rollout_state_cannot_replace_signed_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from jev_reflex.policy_rollout import policy_hash

    signer = Ed25519Signer()
    public_key = tmp_path / "pub.pem"
    public_key.write_text(signer.get_public_key_pem())
    policy = tmp_path / "reflex.yaml"
    policy.write_text("mode: enforce\npolicy: {allow_hold_override: false}\n")
    sign_file(policy, signer)
    state = tmp_path / "state" / "rollout.json"
    state.parent.mkdir()
    _use_bootstrap(
        monkeypatch,
        BootstrapConfig(
            require_signature=True, public_key_path=str(public_key), rollout_state_path=str(state)
        ),
    )
    _operator_controlled(monkeypatch)
    assert load_config(policy).mode == "enforce"

    # Same-uid forgery: no key is needed to compute the unkeyed snapshot hash.
    forged = ReflexConfig.model_validate(
        {
            "mode": "advisory",
            "hold_on": [],
            "review_on": [],
            "policy": {"allow_hold_override": True},
        }
    )
    entry = {"hash": policy_hash(forged), "policy": forged.model_dump(mode="json")}
    for schema in (1, 2):
        state.write_text(
            json.dumps(
                {
                    "schema": schema,
                    "active": entry,
                    "candidate": None,
                    "previous": None,
                    "percent": 0,
                }
            )
        )
        state.chmod(0o600)
        with pytest.raises(ValueError, match="re-stage"):
            load_config(policy)
    # Where the evaluating user owns the state, it is refused before it is read.
    monkeypatch.undo()
    _use_bootstrap(
        monkeypatch,
        BootstrapConfig(
            require_signature=True, public_key_path=str(public_key), rollout_state_path=str(state)
        ),
    )
    with pytest.raises(ValueError, match="rewritten or replaced by the evaluating user"):
        load_config(policy)


def _signed_rollout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from jev_reflex.policy_rollout import RolloutStore, SignedPolicy

    admin, central = Ed25519Signer(), Ed25519Signer()
    public_key = tmp_path / "admin.pub"
    public_key.write_text(admin.get_public_key_pem())
    state = tmp_path / "rollout.json"
    bootstrap = BootstrapConfig(
        require_signature=True,
        public_key_path=str(public_key),
        rollout_state_path=str(state),
        policy_source=PolicySourceConfig(
            type="local",
            uri=str(tmp_path / "central.yaml"),
            pinned_signature_pubkey=central.get_public_key_pem(),
        ),
    )
    _use_bootstrap(monkeypatch, bootstrap)
    baseline = b"mode: enforce\n"
    candidate = b"mode: enforce\nthresholds: {review: 0.6, strong: 0.85}\n"
    store = RolloutStore(state, bootstrap)
    store.stage(
        SignedPolicy(baseline, admin.sign(baseline), "bootstrap"),
        SignedPolicy(candidate, central.sign(candidate), "policy_source"),
    )
    store.promote(100)
    policy = tmp_path / "reflex.yaml"
    policy.write_bytes(baseline)
    sign_file(policy, admin)
    return store, state, policy


def test_signed_rollout_snapshots_are_reverified_on_every_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from jev_reflex.policy_rollout import policy_hash

    store, state, policy = _signed_rollout(tmp_path, monkeypatch)
    _operator_controlled(monkeypatch)
    assert load_config(policy).thresholds.review == 0.6
    original = json.loads(state.read_text())
    assert original["schema"] == 2
    assert original["active"]["trust_root"] == "policy_source"
    assert original["previous"]["trust_root"] == "bootstrap"
    assert "policy" not in original["active"]

    attacker = Ed25519Signer()
    looser = b"mode: advisory\nhold_on: []\n"
    looser_hash = policy_hash(config_module.parse_policy_bytes(looser))
    encoded = base64.b64encode(looser).decode()
    forgeries = {
        "edited bytes": {**original["active"], "raw": encoded, "hash": looser_hash},
        "attacker signature": {
            **original["active"],
            "raw": encoded,
            "hash": looser_hash,
            "signature": base64.b64encode(attacker.sign(looser)).decode(),
        },
        "unknown root": {**original["active"], "trust_root": "repository"},
        "wrong root": {**original["active"], "trust_root": "bootstrap"},
        "signature stripped": {
            "hash": looser_hash,
            "policy": config_module.parse_policy_bytes(looser).model_dump(mode="json"),
        },
    }
    for entry in forgeries.values():
        state.write_text(json.dumps({**original, "active": entry}))
        state.chmod(0o600)
        with pytest.raises(ValueError):
            load_config(policy)
        with pytest.raises(ValueError):
            store.status()
    # An unselected but forged snapshot also fails closed.
    state.write_text(json.dumps({**original, "previous": forgeries["edited bytes"]}))
    state.chmod(0o600)
    with pytest.raises(ValueError):
        load_config(policy)


def test_legacy_unsigned_state_still_works_without_required_signatures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from jev_reflex.policy_rollout import RolloutStore, policy_hash

    baseline = ReflexConfig(mode="enforce")
    candidate = ReflexConfig.model_validate({"mode": "enforce", "thresholds": {"review": 0.6}})
    state = tmp_path / "rollout.json"
    entry = {"hash": policy_hash(baseline), "policy": baseline.model_dump(mode="json")}
    state.write_text(
        json.dumps(
            {"schema": 1, "active": entry, "candidate": None, "previous": None, "percent": 0}
        )
    )
    state.chmod(0o600)
    _use_bootstrap(monkeypatch, BootstrapConfig(rollout_state_path=str(state)))
    policy = _write_policy(tmp_path / "reflex.yaml", baseline)
    assert load_config(policy).thresholds.review == baseline.thresholds.review
    store = RolloutStore(state, BootstrapConfig(rollout_state_path=str(state)))
    store.stage(baseline, candidate)
    store.promote(100)
    assert json.loads(state.read_text())["schema"] == 2
    assert load_config(policy).thresholds.review == 0.6
    with pytest.raises(ValueError, match="only signed policies"):
        RolloutStore(tmp_path / "other.json", BootstrapConfig(require_signature=True)).stage(
            baseline, candidate
        )


def test_rollout_stage_cli_keeps_verified_bytes_for_both_trust_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from jev_reflex.policy_rollout import policy_hash

    audit = tmp_path / "audit.jsonl"
    data = {"mode": "enforce", "audit": {"enabled": True, "path": str(audit)}}
    baseline = ReflexConfig.model_validate({**data, "thresholds": {"review": 0.5, "strong": 0.9}})
    candidate = ReflexConfig.model_validate({**data, "thresholds": {"review": 0.4, "strong": 0.9}})
    _record(baseline, {"unsafe": 0.6})
    admin, central = Ed25519Signer(), Ed25519Signer()
    (tmp_path / "admin.pub").write_text(admin.get_public_key_pem())
    baseline_path = _write_policy(tmp_path / "baseline.yaml", baseline)
    sign_file(baseline_path, admin)
    candidate_path = _write_policy(tmp_path / "candidate.yaml", candidate)
    sign_file(candidate_path, central)
    bootstrap = tmp_path / "bootstrap.yaml"
    bootstrap.write_text(
        yaml.safe_dump(
            {
                "require_signature": True,
                "public_key_path": "admin.pub",
                "rollout_state_path": "state/rollout.json",
                "policy_source": {
                    "type": "local",
                    "uri": str(candidate_path),
                    "pinned_signature_pubkey": central.get_public_key_pem(),
                },
            }
        )
    )
    # Swap the baseline right after its signature verifies (TOCTOU): staging must
    # keep the bytes it verified, not re-read the file.
    verified = baseline_path.read_bytes()
    swapped: list[bytes] = []
    real_verify = config_module.verify_policy_signature

    def verify_then_swap(data: bytes, signature: bytes, settings: BootstrapConfig) -> None:
        real_verify(data, signature, settings)
        if not swapped:
            relaxed = baseline.model_copy(update={"mode": "advisory"})
            swapped.append(_write_policy(baseline_path, relaxed).read_bytes())

    monkeypatch.setattr(config_module, "verify_policy_signature", verify_then_swap)
    runner = CliRunner()
    staged = runner.invoke(
        app,
        [
            "policy",
            "rollout",
            "stage",
            "--bootstrap",
            str(bootstrap),
            "--baseline",
            str(baseline_path),
            "--audit",
            str(audit),
        ],
    )
    assert staged.exit_code == 0, staged.output
    assert swapped and swapped[0] != verified  # the swap ran during the successful stage
    state = json.loads((tmp_path / "state" / "rollout.json").read_text())
    assert base64.b64decode(state["active"]["raw"]) == verified
    assert state["active"]["hash"] == policy_hash(baseline)
    monkeypatch.setattr(config_module, "verify_policy_signature", real_verify)
    baseline_path.write_bytes(verified)  # runtime verifies the local file again below
    promoted = runner.invoke(
        app, ["policy", "rollout", "promote", "--bootstrap", str(bootstrap), "--percent", "100"]
    )
    assert promoted.exit_code == 0, promoted.output
    state = json.loads((tmp_path / "state" / "rollout.json").read_text())
    assert state["schema"] == 2
    assert state["active"]["trust_root"] == "policy_source"
    assert state["previous"]["trust_root"] == "bootstrap"
    assert base64.b64decode(state["previous"]["raw"]) == baseline_path.read_bytes()
    assert state["active"]["hash"] == policy_hash(candidate)

    real = load_bootstrap_config
    monkeypatch.setattr(config_module, "load_bootstrap_config", lambda: real(bootstrap))
    _operator_controlled(monkeypatch)
    assert load_config(baseline_path).thresholds.review == 0.4


# Finding 2: central policy docs and `jrx policy status` overstated the runtime.


def test_policy_status_does_not_report_an_unused_fetcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    _use_bootstrap(
        monkeypatch,
        BootstrapConfig(
            policy_source=PolicySourceConfig(
                type="local",
                uri=str(tmp_path / "central.yaml"),
                pinned_signature_pubkey=Ed25519Signer().get_public_key_pem(),
            )
        ),
    )
    result = CliRunner().invoke(app, ["policy", "status"])
    assert result.exit_code == 0, result.output
    for misleading in ("Has cached policy", "Last fetch time", "Poll interval", "Local override"):
        assert misleading not in result.output
    assert "jrx policy rollout stage" in result.output
    assert "Rollout state: not configured" in result.output


def test_security_docs_do_not_claim_an_unwired_tighten_only_overlay() -> None:
    text = (Path(__file__).parents[1] / "docs" / "security.md").read_text(encoding="utf-8")
    assert "advisory < enforce < review" not in text
    assert "becomes an override layer" not in text
    assert "jrx policy rollout stage" in text


# Finding 3: `jrx policy test -c FILE` tested the rollout-selected policy.


def test_policy_test_uses_the_given_file_even_with_rollout_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from jev_reflex.golden_runner import run_fixtures
    from jev_reflex.policy_rollout import RolloutStore

    candidate = tmp_path / "candidate.yaml"
    candidate.write_text(
        "mode: advisory\nhold_on: []\nreview_on: []\nthresholds: {strong: 0.999, review: 0.998}\n"
    )
    _use_bootstrap(monkeypatch, BootstrapConfig())
    expected = run_fixtures(config_path=candidate)
    state = tmp_path / "rollout.json"
    RolloutStore(state).stage(ReflexConfig(mode="enforce"), ReflexConfig(mode="enforce"))
    _use_bootstrap(monkeypatch, BootstrapConfig(rollout_state_path=str(state)))
    report = run_fixtures(config_path=candidate)
    assert [item.actual for item in report.results] == [item.actual for item in expected.results]
    assert report.passed == expected.passed < report.total


# Finding 4: canary cohorts were keyed on the hook's working directory.


def test_canary_cohort_is_keyed_on_the_repository_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from jev_reflex.config import _rollout_scope
    from jev_reflex.policy_rollout import RolloutStore

    state = tmp_path / "rollout.json"
    store = RolloutStore(state)
    store.stage(ReflexConfig(mode="enforce"), ReflexConfig(mode="review"))
    store.promote(50)
    _use_bootstrap(monkeypatch, BootstrapConfig(rollout_state_path=str(state)))
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    policy = repo / "reflex.yaml"
    policy.write_text("mode: enforce\n")
    directories = [repo] + [repo / f"dir{index}" / "nested" for index in range(16)]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    modes = {load_config(policy, scope=str(directory)).mode for directory in directories}
    assert len(modes) == 1

    assert _rollout_scope(str(repo / "dir3" / "nested"), policy) == str(repo.resolve())
    worktree = tmp_path / "worktree"
    (worktree / "pkg").mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: /elsewhere/.git/worktrees/x\n")
    assert _rollout_scope(str(worktree / "pkg"), policy) == str(worktree.resolve())
    assert _rollout_scope("not-a-directory-scope", policy) == "not-a-directory-scope"


# Finding 5: relative bootstrap paths resolved against the agent's working directory.


def test_relative_bootstrap_paths_resolve_next_to_the_bootstrap_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin, attacker = Ed25519Signer(), Ed25519Signer()
    host = tmp_path / "host"
    (host / "keys").mkdir(parents=True)
    (host / "keys" / "policy.pub").write_text(admin.get_public_key_pem())
    bootstrap_file = host / "bootstrap.yaml"
    bootstrap_file.write_text(
        "require_signature: true\npublic_key_path: keys/policy.pub\n"
        "rollout_state_path: state/rollout.json\n"
    )
    settings = load_bootstrap_config(bootstrap_file)
    assert settings.public_key_path == str(host / "keys" / "policy.pub")
    assert settings.rollout_state_path == str(host / "state" / "rollout.json")

    repo = tmp_path / "repo"
    (repo / "keys").mkdir(parents=True)
    (repo / "keys" / "policy.pub").write_text(attacker.get_public_key_pem())
    (repo / "reflex.yaml").write_text("mode: advisory\n")
    sign_file(repo / "reflex.yaml", attacker)
    monkeypatch.chdir(repo)
    monkeypatch.setattr(
        config_module, "load_bootstrap_config", lambda: load_bootstrap_config(bootstrap_file)
    )
    with pytest.raises(ValueError, match="Signature verification failed"):
        load_config()
    (repo / "reflex.yaml").write_text("mode: enforce\n")
    sign_file(repo / "reflex.yaml", admin)
    _operator_controlled(monkeypatch)  # the bootstrap directory is host-controlled
    assert load_config().mode == "enforce"
    assert not (repo / "state").exists()


# Finding 6: lint accepted YAML that the runtime loader rejects.


@pytest.mark.parametrize(
    "text",
    [
        "mode: enforce\nhold_on: &h [destructive, secret_exposure]\nreview_on: *h\n",
        "mode: enforce\naudit:\n  <<: {enabled: true}\n  fail_closed: true\n",
        "<<: {mode: advisory}\nmode: enforce\n",
    ],
)
def test_lint_rejects_yaml_that_the_runtime_loader_rejects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    path = tmp_path / "reflex.yaml"
    path.write_text(text)
    _use_bootstrap(monkeypatch, BootstrapConfig())
    with pytest.raises(ValueError, match="configuration YAML is invalid"):
        load_config(path)
    report = lint_policy(path)
    assert not report["valid"]
    assert codes_of(report) <= {"invalid_yaml", "invalid_structure"}


def codes_of(report: dict) -> set[str]:
    return {issue["code"] for issue in report["issues"]}


# Finding 7: the rollout gate ignored HOLD -> REVIEW under a mode that ran REVIEW unattended.
# Since REVIEW never runs unattended in enforce mode either, the gate reports the transition
# without counting it as newly executable, in both enforcing modes.


def test_rollout_stage_gate_reports_hold_to_review_without_unattended_execution(
    tmp_path: Path,
) -> None:
    audit = tmp_path / "audit.jsonl"
    data = {"mode": "enforce", "audit": {"enabled": True, "path": str(audit)}}
    baseline = ReflexConfig.model_validate(data)
    _record(baseline, {"destructive": 0.97}, risk="high")
    baseline_path = _write_policy(tmp_path / "baseline.yaml", baseline)
    hold_on = [name for name in baseline.hold_on if name != "destructive"]
    signer = Ed25519Signer()

    def stage(candidate_data: dict, *extra: str):
        mode = candidate_data["mode"]
        candidate_path = _write_policy(
            tmp_path / f"candidate-{mode}.yaml", ReflexConfig.model_validate(candidate_data)
        )
        sign_file(candidate_path, signer)
        bootstrap = tmp_path / f"bootstrap-{mode}.yaml"
        bootstrap.write_text(
            yaml.safe_dump(
                {
                    "rollout_state_path": str(tmp_path / f"state-{mode}.json"),
                    "policy_source": {
                        "type": "local",
                        "uri": str(candidate_path),
                        "pinned_signature_pubkey": signer.get_public_key_pem(),
                    },
                }
            )
        )
        command = ["policy", "rollout", "stage", "--bootstrap", str(bootstrap)]
        command += ["--baseline", str(baseline_path), "--audit", str(audit), *extra]
        return CliRunner().invoke(app, command)

    for mode in ("enforce", "review"):
        staged = stage({**data, "mode": mode, "hold_on": hold_on})
        assert staged.exit_code == 0, staged.output
        simulation = json.loads(staged.output)["simulation"]
        assert simulation["changes"]["HOLD_to_REVIEW"] == 1
        assert simulation["newly_executable"] == 0


# Finding 8: non-core YAML tags gave process-dependent policies and hashes.


def test_non_core_yaml_tags_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for text in (
        "hold_on: !!set {destructive: null, secret_exposure: null}\n",
        "rule_modes: !!omap [{git_risk: enforce}]\n",
        "rule_modes: !!pairs [{git_risk: enforce}]\n",
        "mode: !!binary ZW5mb3JjZQ==\n",
        "mode: !!timestamp 2024-01-01\n",
        "mode: 2024-01-01\n",
        "mode: !custom enforce\n",
    ):
        with pytest.raises(yaml.YAMLError):
            safe_yaml_load(text)
    path = tmp_path / "reflex.yaml"
    path.write_text("mode: enforce\nhold_on: !!set {destructive: null, fail_open: null}\n")
    _use_bootstrap(monkeypatch, BootstrapConfig())
    with pytest.raises(ValueError, match="configuration YAML is invalid"):
        load_config(path)
    assert safe_yaml_load("mode: !!str enforce\nn: !!int 3\nf: !!float 1\n") == {
        "mode": "enforce",
        "n": 3,
        "f": 1.0,
    }


# Finding 9: a malformed local override was silently dropped by the reloader.


def test_reloader_fails_closed_on_a_malformed_local_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from jev_reflex.policy_source import PolicyFetchError, PolicyReloader

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    signer = Ed25519Signer()
    central = tmp_path / "central.yaml"
    central.write_text("mode: advisory\n")
    sign_file(central, signer)
    local = tmp_path / "reflex.yaml"
    source = PolicySourceConfig(
        type="local", uri=str(central), pinned_signature_pubkey=signer.get_public_key_pem()
    )

    local.write_text("mode: enforce\npolicy: {allow_hold_overide: false}\n")
    with pytest.raises(PolicyFetchError):
        PolicyReloader(source, local_config_path=local)._reload_policy()

    local.write_text("mode: enforce\n")
    reloader = PolicyReloader(source, local_config_path=local)
    reloader._reload_policy()
    previous = reloader.get_current_policy()
    assert previous is not None and previous.mode == "enforce"
    local.write_text("mode: enforce\npolicy: {allow_hold_overide: false}\n")
    reloader._reload_policy()
    assert reloader.get_current_policy() == previous


# Finding 10: stability crossings ignored the review boundary for hold signals.


def test_stability_crossings_count_the_review_boundary_for_hold_signals() -> None:
    config = ReflexConfig()
    results = []
    for probability in (0.5, 0.8, 0.5, 0.8):
        signals = {"destructive": probability}
        results.append(
            EvaluationResult.model_construct(
                decision=decide([], signals, config).decision, signals=signals, degraded=False
            )
        )
    report = build_report(results, config)
    assert report.decision_flip_rate == 0.5
    assert report.signals["destructive"].threshold_crossings == 2
    assert report.signals["destructive"].threshold_crossing_rate == 0.5
