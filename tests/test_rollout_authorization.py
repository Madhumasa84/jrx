"""Rollout freshness, canary and rollback authorization, and the effective-enforcement gate.

Signatures authenticate a staged policy's contents only. These tests check that, while
signatures are required, the evaluating user cannot pick the active revision, the canary
percentage or a rollback by rewriting rollout state, and that the stage gate treats a
mode downgrade as a relaxation. All fixtures are local and synthetic.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from typer.testing import CliRunner

from jev_reflex import config as config_module
from jev_reflex import trust
from jev_reflex.audit import AuditLog
from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig, load_bootstrap_config, load_config
from jev_reflex.policy import decide
from jev_reflex.policy_rollout import enforcement_relaxations, policy_hash
from jev_reflex.signing import Ed25519Signer, sign_file

OTHER_UID = os.geteuid() + 100_000
REFUSED = "rewritten or replaced by the evaluating user"


def _record(config: ReflexConfig, signals: dict[str, float], risk: str) -> None:
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


def _deployment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    candidate: dict | None = None,
    records: tuple[tuple[dict[str, float], str], ...] = (({"unsafe": 0.1}, "low"),),
    require_signature: bool = True,
    state: Path | None = None,
):
    """A signed reflex.yaml, a signed central candidate, an audit log and a bootstrap."""
    audit = tmp_path / "audit.jsonl"
    common = {"mode": "enforce", "audit": {"enabled": True, "path": str(audit)}}
    baseline = ReflexConfig.model_validate(common)
    staged = ReflexConfig.model_validate(
        {**common, **(candidate or {"thresholds": {"review": 0.6, "strong": 0.85}})}
    )
    for signals, risk in records:
        _record(baseline, signals, risk)
    admin, central = Ed25519Signer(), Ed25519Signer()
    (tmp_path / "admin.pub").write_text(admin.get_public_key_pem())
    policy = tmp_path / "reflex.yaml"
    policy.write_text(yaml.safe_dump(baseline.model_dump(mode="json")))
    sign_file(policy, admin)
    central_policy = tmp_path / "central.yaml"
    central_policy.write_text(yaml.safe_dump(staged.model_dump(mode="json")))
    sign_file(central_policy, central)
    state = state or tmp_path / "operator" / "rollout.json"
    bootstrap = tmp_path / "bootstrap.yaml"
    bootstrap.write_text(
        yaml.safe_dump(
            {
                "require_signature": require_signature,
                "public_key_path": "admin.pub",
                "rollout_state_path": str(state),
                "policy_source": {
                    "type": "local",
                    "uri": str(central_policy),
                    "pinned_signature_pubkey": central.get_public_key_pem(),
                },
            }
        )
    )
    # Evaluation reads the default bootstrap; operator commands pass --bootstrap.
    monkeypatch.setattr(
        config_module,
        "load_bootstrap_config",
        lambda path=None: load_bootstrap_config(path or bootstrap),
    )
    return SimpleNamespace(
        audit=audit,
        baseline=baseline,
        candidate=staged,
        policy=policy,
        state=state,
        bootstrap=bootstrap,
    )


def _rollout(deployment, command: str, *extra: str):
    args = ["policy", "rollout", command, "--bootstrap", str(deployment.bootstrap)]
    if command == "stage":
        args += ["--baseline", str(deployment.policy), "--audit", str(deployment.audit)]
    return CliRunner().invoke(app, [*args, *extra])


def _as_evaluator(monkeypatch: pytest.MonkeyPatch, uid: int = OTHER_UID) -> None:
    """Evaluate as ``uid``; OTHER_UID owns none of the test files (operator-written state)."""
    monkeypatch.setattr(trust, "evaluator_identity", lambda: trust.Identity(uid, frozenset()))


def _effective(deployment, scope: str = "repository") -> str:
    return policy_hash(load_config(deployment.policy, scope=scope))


def _staged_and_promoted(tmp_path, monkeypatch, percent: str = "100"):
    deployment = _deployment(tmp_path, monkeypatch)
    assert _rollout(deployment, "stage").exit_code == 0
    assert _rollout(deployment, "promote", "--percent", percent).exit_code == 0
    return deployment


# --- operator-controlled state: legitimate operator behaviour -----------------------


def test_operator_stage_canary_promotion_and_rollback_drive_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment = _deployment(tmp_path, monkeypatch)
    _as_evaluator(monkeypatch)
    baseline, candidate = policy_hash(deployment.baseline), policy_hash(deployment.candidate)

    assert _effective(deployment) == baseline  # no state yet: the signed reflex.yaml
    staged = _rollout(deployment, "stage")
    assert staged.exit_code == 0, staged.output
    assert _effective(deployment) == baseline  # staged at 0 %

    assert _rollout(deployment, "promote", "--percent", "50").exit_code == 0
    cohorts = {_effective(deployment, f"/fixture/repository-{index}") for index in range(200)}
    assert cohorts == {baseline, candidate}

    assert _rollout(deployment, "promote", "--percent", "100").exit_code == 0
    assert _effective(deployment) == candidate

    rolled_back = _rollout(deployment, "rollback")
    assert rolled_back.exit_code == 0, rolled_back.output
    assert _effective(deployment) == baseline
    assert oct(deployment.state.stat().st_mode & 0o777) == "0o644"


def test_operator_narrower_state_mode_is_kept_on_rewrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment = _staged_and_promoted(tmp_path, monkeypatch, percent="10")
    deployment.state.chmod(0o640)
    assert _rollout(deployment, "promote", "--percent", "100").exit_code == 0
    assert deployment.state.stat().st_mode & 0o777 == 0o640


def test_unsigned_deployment_keeps_same_user_rollout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without required signatures reflex.yaml itself is unprotected, so rollout state the
    # evaluating user owns keeps working as before.
    deployment = _deployment(tmp_path, monkeypatch, require_signature=False)
    assert _rollout(deployment, "stage").exit_code == 0
    assert _rollout(deployment, "promote", "--percent", "100").exit_code == 0
    assert _effective(deployment) == policy_hash(deployment.candidate)


# --- state the evaluating user can rewrite is refused --------------------------------


def _stale(deployment, earlier: dict) -> None:
    deployment.state.write_text(json.dumps(earlier))


def _canary(deployment, earlier: dict) -> None:
    deployment.state.write_text(json.dumps({**earlier, "percent": 100}))


def _rollback(deployment, earlier: dict) -> None:
    data = json.loads(deployment.state.read_text())
    data["active"], data["previous"] = data["previous"], None
    deployment.state.write_text(json.dumps(data))


@pytest.mark.parametrize(
    "tamper",
    [_stale, _canary, _rollback],
    ids=["stale-signed-state", "altered-canary", "unauthorized-rollback"],
)
def test_state_the_evaluating_user_can_rewrite_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper
) -> None:
    deployment = _deployment(tmp_path, monkeypatch)
    assert _rollout(deployment, "stage").exit_code == 0
    assert _rollout(deployment, "promote", "--percent", "10").exit_code == 0
    earlier = json.loads(deployment.state.read_text())  # every snapshot validly signed
    assert _rollout(deployment, "promote", "--percent", "100").exit_code == 0
    tamper(deployment, earlier)

    # Every tampered state still carries valid signatures, so signature checks alone
    # would accept it. The test user owns the file, which is exactly the agent-writable
    # case, and evaluation refuses it whatever it says.
    with pytest.raises(ValueError, match=REFUSED):
        load_config(deployment.policy)
    # Only an operator-controlled copy of the same bytes would be honoured.
    _as_evaluator(monkeypatch)
    assert load_config(deployment.policy) is not None


def test_hook_denies_when_rollout_state_is_agent_writable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment = _staged_and_promoted(tmp_path, monkeypatch)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "cwd": str(tmp_path),
    }
    command = ["claude-code-hook", "--demo", "--config", str(deployment.policy)]
    denied = CliRunner().invoke(app, command, input=json.dumps(payload))
    assert '"permissionDecision":"deny"' in denied.output.replace(" ", ""), denied.output
    _as_evaluator(monkeypatch)
    allowed = CliRunner().invoke(app, command, input=json.dumps(payload))
    assert "deny" not in allowed.output, allowed.output


def test_missing_state_is_trusted_only_where_the_user_could_not_remove_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o755)
    deployment = _deployment(tmp_path, monkeypatch, state=shared / "rollout.json")
    _as_evaluator(monkeypatch)
    assert _effective(deployment) == policy_hash(deployment.baseline)
    shared.chmod(0o777)  # anyone could have deleted operator state here
    try:
        with pytest.raises(ValueError, match=REFUSED):
            load_config(deployment.policy)
    finally:
        shared.chmod(0o755)


@pytest.mark.parametrize(
    ("directory_mode", "accepted"),
    [(0o755, True), (0o775, False), (0o777, False), (0o1777, True)],
)
def test_operator_state_directory_must_not_let_the_user_replace_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, directory_mode: int, accepted: bool
) -> None:
    deployment = _staged_and_promoted(tmp_path, monkeypatch)
    group = os.stat(deployment.state.parent).st_gid
    monkeypatch.setattr(
        trust, "evaluator_identity", lambda: trust.Identity(OTHER_UID, frozenset({group}))
    )
    deployment.state.parent.chmod(directory_mode)
    try:
        if accepted:
            # Sticky directories only let entry owners rename or unlink entries.
            assert _effective(deployment) == policy_hash(deployment.candidate)
        else:
            with pytest.raises(ValueError, match=REFUSED):
                load_config(deployment.policy)
    finally:
        deployment.state.parent.chmod(0o755)


def test_state_reached_through_a_replaceable_symlink_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator = tmp_path / "operator"
    operator.mkdir()
    operator.chmod(0o755)  # explicit, whatever the umask
    links = tmp_path / "links"
    links.mkdir()
    links.chmod(0o755)
    (links / "state").symlink_to(operator, target_is_directory=True)
    deployment = _deployment(tmp_path, monkeypatch, state=links / "state" / "rollout.json")
    assert _rollout(deployment, "stage").exit_code == 0
    assert _rollout(deployment, "promote", "--percent", "100").exit_code == 0
    _as_evaluator(monkeypatch)
    assert _effective(deployment) == policy_hash(deployment.candidate)
    links.chmod(0o777)  # the user could re-point the symlink at forged state
    try:
        with pytest.raises(ValueError, match=REFUSED):
            load_config(deployment.policy)
    finally:
        links.chmod(0o755)


def test_root_evaluator_cannot_trust_rollout_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment = _staged_and_promoted(tmp_path, monkeypatch)
    _as_evaluator(monkeypatch, 0)
    with pytest.raises(ValueError, match=REFUSED):
        load_config(deployment.policy)


def test_group_writable_state_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment = _staged_and_promoted(tmp_path, monkeypatch)
    _as_evaluator(monkeypatch)
    deployment.state.chmod(0o664)
    with pytest.raises(ValueError, match="group or world write"):
        load_config(deployment.policy)


# --- effective-enforcement stage gate --------------------------------------------------

HOLD_HISTORY = (({"destructive": 0.97}, "high"), ({"unsafe": 0.1}, "low"))
ALLOW_HISTORY = (({"unsafe": 0.1}, "low"),)


@pytest.mark.parametrize(
    ("mode", "history", "staged"),
    [
        ("advisory", HOLD_HISTORY, False),  # HOLD labels unchanged, but HOLD now runs
        ("advisory", ALLOW_HISTORY, False),  # no blocked history: still a relaxation
        ("review", HOLD_HISTORY, True),  # review blocks REVIEW as well: tighter
    ],
)
def test_stage_gate_judges_effective_enforcement_not_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, history, staged: bool
) -> None:
    deployment = _deployment(tmp_path, monkeypatch, candidate={"mode": mode}, records=history)
    result = _rollout(deployment, "stage", "--max-new-allows", "1000")
    assert (result.exit_code == 0) is staged, result.output
    assert deployment.state.exists() is staged


def test_enforcement_relaxations_compare_modes(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    review = ReflexConfig.model_validate(
        {"mode": "review", "audit": {"enabled": True, "path": str(audit)}}
    )
    enforce = review.model_copy(update={"mode": "enforce"})
    assert enforcement_relaxations(review, enforce) == ["REVIEW"]
    assert enforcement_relaxations(enforce, review) == []
    assert set(enforcement_relaxations(enforce, review.model_copy(update={"mode": "advisory"})))
    assert enforcement_relaxations(review, review) == []


def test_stage_output_reports_mode_relaxation_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment = _deployment(tmp_path, monkeypatch, records=HOLD_HISTORY)
    allowed = _rollout(deployment, "stage")
    assert allowed.exit_code == 0, allowed.output
    simulation = json.loads(allowed.output)["simulation"]
    assert simulation["newly_executable"] == 0
    assert simulation["enforcement_relaxations"] == []


def test_policy_impact_flags_a_mode_only_downgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment = _deployment(
        tmp_path, monkeypatch, candidate={"mode": "advisory"}, records=HOLD_HISTORY
    )
    args = ["policy", "impact", "--audit", str(deployment.audit)]
    args += ["--baseline", str(deployment.policy)]
    candidate = tmp_path / "candidate.yaml"
    shutil.copy(tmp_path / "central.yaml", candidate)
    args += ["--candidate", str(candidate)]
    unlimited = CliRunner().invoke(app, args)
    assert unlimited.exit_code == 0, unlimited.output
    assert "HOLD" in unlimited.output and "blocked them" in unlimited.output
    limited = CliRunner().invoke(app, [*args, "--max-relaxations", "1000"])
    assert limited.exit_code == 1, limited.output
    assert "relaxes enforcement" in limited.output
