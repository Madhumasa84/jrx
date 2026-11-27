"""Which bootstrap, key and rollout inputs establish trust against the evaluating user.

``require_signature`` lives inside the bootstrap file, so it protects nothing against a
user who can edit or replace that file. These tests pin the rules in ``config.py``:

* a bootstrap is an independent trust anchor only when the evaluating user can neither
  rewrite it nor replace it through its directories (``operator_controlled``);
* an operator-controlled bootstrap's public key and rollout state must be
  operator-controlled too;
* rollout state may replace a policy file only when it is at least as protected as that
  file, so a bootstrap the user can write cannot redirect an operator-owned policy;
* same-user installations, where nothing is protected, keep working unchanged.

Ownership is simulated by evaluating as a uid that owns none of the temporary files,
as the rollout tests do; ``test_bootstrap_trust_privileged.py`` repeats the key cases
with real root-owned files where CI can use sudo.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from jev_reflex import config as config_module
from jev_reflex import signing, trust
from jev_reflex.cli import app
from jev_reflex.config import (
    BootstrapConfig,
    ReflexConfig,
    load_bootstrap_config,
    load_config,
    trust_report,
)
from jev_reflex.policy_rollout import RolloutStore
from jev_reflex.signing import Ed25519Signer, sign_file

OTHER_UID = os.geteuid() + 100_000
REFUSED = "rewritten or replaced by the evaluating user"
HOOK_EVENT = {
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "ls"},
}


class Host:
    """An operator directory, an agent-writable home, and no system bootstrap yet."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.operator = tmp_path / "operator"
        self.operator.mkdir(mode=0o755)
        self.operator.chmod(0o755)
        self.home = tmp_path / "home"
        self.user_dir = self.home / ".jev-reflex"
        self.user_dir.mkdir(parents=True)
        # World-writable without the sticky bit: the simulated agent user can write
        # and replace everything here, as it could in its own home directory.
        self.home.chmod(0o777)
        self.user_dir.chmod(0o777)
        self.system_bootstrap = self.operator / "bootstrap.yaml"
        monkeypatch.setattr(config_module, "SYSTEM_BOOTSTRAP", self.system_bootstrap)
        monkeypatch.setattr(Path, "home", lambda: self.home)
        self.monkeypatch = monkeypatch

    def evaluate_as_agent(self, uid: int = OTHER_UID) -> None:
        self.monkeypatch.setattr(
            trust, "evaluator_identity", lambda: trust.Identity(uid, frozenset())
        )

    def policy(self, directory: Path, text: str = "mode: enforce\n") -> Path:
        path = directory / "reflex.yaml"
        path.write_text(text)
        path.chmod(0o644)
        return path

    def unsigned_rollout(self, path: Path, mode: str = "advisory") -> Path:
        weaker = ReflexConfig.model_validate({"mode": mode})
        RolloutStore(path, BootstrapConfig()).stage(weaker, weaker)
        path.chmod(0o644)
        return path

    def bootstrap(self, path: Path, **settings: object) -> Path:
        path.write_text(json.dumps(settings))
        path.chmod(0o644)
        return path

    def signed_policy(self, directory: Path, key_directory: Path) -> tuple[Path, Path]:
        signer = Ed25519Signer()
        key = key_directory / "policy.pub"
        key.write_text(signer.get_public_key_pem())
        key.chmod(0o644)
        policy = self.policy(directory)
        sign_file(policy, signer)
        return policy, key


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Host:
    return Host(tmp_path, monkeypatch)


def _hook(policy: Path) -> str:
    event = {**HOOK_EVENT, "cwd": str(policy.parent)}
    result = CliRunner().invoke(
        app, ["claude-code-hook", "--config", str(policy)], input=json.dumps(event)
    )
    assert result.exit_code == 0, result.output
    return result.output.replace(" ", "")


# --- the confirmed bypass: a user bootstrap redirecting an operator policy --------------


def test_agent_writable_bootstrap_cannot_redirect_an_operator_policy(host: Host) -> None:
    # Reproduced on 3250d85: an enforce policy passed with --config became advisory.
    policy = host.policy(host.operator)
    state = host.unsigned_rollout(host.user_dir / "state.json")
    host.bootstrap(host.user_dir / "bootstrap.yaml", rollout_state_path=str(state))
    host.evaluate_as_agent()

    assert not load_bootstrap_config().operator_controlled
    with pytest.raises(ValueError, match=REFUSED):
        load_config(policy)
    assert '"permissionDecision":"deny"' in _hook(policy)
    report = trust_report(policy)
    assert report["policy"]["operator_controlled"] is True
    assert report["policy_protected_from_evaluating_user"] is False
    assert any("rollout state is writable" in issue for issue in report["issues"])


def test_same_user_installation_keeps_unsigned_rollout(host: Host) -> None:
    # Nothing here is protected from the evaluating user (the real test user), so the
    # rollout cannot weaken anything that was protected and keeps working as before.
    policy = host.policy(host.user_dir)
    state = host.unsigned_rollout(host.user_dir / "state.json")
    host.bootstrap(host.user_dir / "bootstrap.yaml", rollout_state_path=str(state))

    assert load_config(policy).mode == "advisory"
    report = trust_report(policy)
    assert report["issues"] == []
    assert report["policy_protected_from_evaluating_user"] is False


def test_operator_rollout_still_replaces_an_operator_policy(host: Host) -> None:
    policy = host.policy(host.operator)
    state = host.unsigned_rollout(host.operator / "state.json", mode="review")
    host.bootstrap(host.system_bootstrap, rollout_state_path=str(state))
    host.evaluate_as_agent()

    assert load_bootstrap_config().operator_controlled
    assert load_config(policy).mode == "review"
    assert trust_report(policy)["policy_protected_from_evaluating_user"] is True


def test_operator_bootstrap_refuses_agent_writable_rollout_state(host: Host) -> None:
    # Without signatures nothing else authenticates the state an operator bootstrap names.
    policy = host.policy(host.user_dir)
    state = host.unsigned_rollout(host.user_dir / "state.json")
    host.bootstrap(host.system_bootstrap, rollout_state_path=str(state))
    host.evaluate_as_agent()

    with pytest.raises(ValueError, match="bootstrap .* is operator-controlled"):
        load_config(policy)

    # Recovery: move the state under the operator directory and stage it there again.
    moved = host.unsigned_rollout(host.operator / "state.json")
    host.bootstrap(host.system_bootstrap, rollout_state_path=str(moved))
    assert load_config(policy).mode == "advisory"


# --- the public key of an operator-controlled bootstrap --------------------------------


def test_operator_bootstrap_refuses_an_agent_writable_public_key(host: Host) -> None:
    policy, key = host.signed_policy(host.user_dir, key_directory=host.user_dir)
    host.bootstrap(host.system_bootstrap, require_signature=True, public_key_path=str(key))
    host.evaluate_as_agent()

    with pytest.raises(ValueError, match="public key .* can be rewritten or replaced"):
        load_config(policy)
    assert '"permissionDecision":"deny"' in _hook(policy)
    assert trust_report(policy)["issues"]

    # Migration: install the same key where only the operator can write.
    protected_key = host.operator / "policy.pub"
    protected_key.write_bytes(key.read_bytes())
    protected_key.chmod(0o644)
    host.bootstrap(
        host.system_bootstrap, require_signature=True, public_key_path=str(protected_key)
    )
    assert load_config(policy).mode == "enforce"
    assert trust_report(policy)["policy_protected_from_evaluating_user"] is True

    # The signature still binds the agent-writable policy file's contents.
    policy.write_text("mode: advisory\n")
    with pytest.raises(ValueError, match="Signature verification failed"):
        load_config(policy)


def test_operator_key_rotation_and_resigning_keep_working(host: Host) -> None:
    policy, key = host.signed_policy(host.user_dir, key_directory=host.operator)
    host.bootstrap(host.system_bootstrap, require_signature=True, public_key_path=str(key))
    host.evaluate_as_agent()
    assert load_config(policy).mode == "enforce"

    # A legitimate operator update: new key, policy re-signed with it.
    rotated = Ed25519Signer()
    key.write_text(rotated.get_public_key_pem())
    policy.write_text("mode: review\n")
    sign_file(policy, rotated)
    assert load_config(policy).mode == "review"


def test_same_user_signed_installation_keeps_verifying(host: Host) -> None:
    # Real identity: the user owns everything, so the bootstrap is no independent anchor
    # (the user could edit require_signature away), but signatures are still checked
    # and the limitation is reported rather than hidden.
    policy, key = host.signed_policy(host.user_dir, key_directory=host.user_dir)
    host.bootstrap(
        host.user_dir / "bootstrap.yaml", require_signature=True, public_key_path=str(key)
    )
    assert not load_bootstrap_config().operator_controlled
    assert load_config(policy).mode == "enforce"
    policy.write_text("mode: advisory\n")
    with pytest.raises(ValueError, match="Signature verification failed"):
        load_config(policy)
    report = trust_report(policy)
    assert report["bootstrap"]["operator_controlled"] is False
    assert report["policy_protected_from_evaluating_user"] is False


# --- what makes a bootstrap an anchor ----------------------------------------------------


@pytest.mark.parametrize(
    ("file_mode", "directory_mode", "anchored"),
    [
        (0o644, 0o755, True),
        (0o666, 0o755, False),  # content modification: the user can rewrite the file
        (0o644, 0o777, False),  # replacement: the user can rename a forged file over it
        (0o644, 0o1777, True),  # sticky: only the entry's owner can replace it
    ],
)
def test_bootstrap_anchor_requires_no_rewrite_and_no_replacement(
    host: Host, file_mode: int, directory_mode: int, anchored: bool
) -> None:
    host.bootstrap(host.system_bootstrap)
    host.system_bootstrap.chmod(file_mode)
    host.operator.chmod(directory_mode)
    host.evaluate_as_agent()
    try:
        assert load_bootstrap_config().operator_controlled is anchored
    finally:
        host.operator.chmod(0o755)


def test_system_bootstrap_shadows_the_user_bootstrap(host: Host) -> None:
    host.bootstrap(host.user_dir / "bootstrap.yaml", rollout_state_path="/nonexistent")
    host.bootstrap(host.system_bootstrap)
    loaded = load_bootstrap_config()
    assert loaded.path == host.system_bootstrap
    assert loaded.rollout_state_path is None


def test_root_or_privileged_evaluator_has_no_anchor(host: Host) -> None:
    host.bootstrap(host.system_bootstrap)
    host.evaluate_as_agent(uid=0)
    assert not load_bootstrap_config().operator_controlled
    host.monkeypatch.setattr(
        trust,
        "evaluator_identity",
        lambda: trust.Identity(OTHER_UID, frozenset(), privileged=True),
    )
    assert not load_bootstrap_config().operator_controlled


def test_bypassing_capabilities_are_read_from_proc_status(tmp_path: Path) -> None:
    status = tmp_path / "status"
    status.write_text("Name:\tpython\nCapEff:\t0000000000000000\n")
    assert trust.bypassing_capabilities(status) == []
    # CAP_DAC_OVERRIDE (bit 1) and CAP_SYS_ADMIN (bit 21)
    status.write_text(f"CapEff:\t{(1 << 1) | (1 << 21):016x}\n")
    assert trust.bypassing_capabilities(status) == ["CAP_DAC_OVERRIDE", "CAP_SYS_ADMIN"]
    assert trust.bypassing_capabilities(tmp_path / "missing") == []


def test_kernel_reported_write_access_defeats_mode_bits(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An ACL can grant write access that ownership and mode bits do not show.
    host.bootstrap(host.system_bootstrap)
    checked = trust.Identity(OTHER_UID, frozenset(), kernel=True)
    monkeypatch.setattr(trust, "_kernel_allows_write", lambda path: path == host.system_bootstrap)
    assert trust.protected_location(host.system_bootstrap, checked) is None
    monkeypatch.setattr(trust, "_kernel_allows_write", lambda path: False)
    assert trust.protected_location(host.system_bootstrap, checked) == host.system_bootstrap


# --- the bytes used are the bytes validated -------------------------------------------


def test_policy_bytes_swapped_after_verification_are_not_used(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, key = host.signed_policy(host.user_dir, key_directory=host.operator)
    host.bootstrap(host.system_bootstrap, require_signature=True, public_key_path=str(key))
    host.evaluate_as_agent()
    verify = signing.verify_file
    swapped: list[bool] = []

    def verify_then_swap(*args, **kwargs):
        verified = verify(*args, **kwargs)
        policy.write_text("mode: advisory\n")  # an agent racing the loader
        swapped.append(verified)
        return verified

    monkeypatch.setattr(signing, "verify_file", verify_then_swap)
    assert load_config(policy).mode == "enforce"
    assert swapped == [True]


def test_policy_status_reports_trust_through_the_cli(host: Host) -> None:
    policy = host.policy(host.operator)
    state = host.unsigned_rollout(host.user_dir / "state.json")
    host.bootstrap(host.user_dir / "bootstrap.yaml", rollout_state_path=str(state))
    host.evaluate_as_agent()

    text = CliRunner().invoke(app, ["policy", "status", "--config", str(policy)])
    assert text.exit_code == 0, text.output
    assert "Bootstrap:" in text.output and "writable by you" in text.output
    assert "Effective policy protected from the evaluating user: no" in text.output
    assert "Evaluation will refuse: rollout state is writable" in text.output
    data = CliRunner().invoke(app, ["policy", "status", "--config", str(policy), "--json"])
    assert json.loads(data.output)["bootstrap"]["operator_controlled"] is False


def test_policy_status_never_calls_a_missing_policy_protected(host: Host) -> None:
    # A path the user cannot create is "operator-controlled", but evaluation of an
    # explicit missing --config fails, so it must not be reported as protected.
    missing = host.operator / "absent" / "reflex.yaml"
    host.evaluate_as_agent()
    report = trust_report(missing)
    assert report["policy"]["exists"] is False
    assert report["policy_protected_from_evaluating_user"] is False
    assert "policy file does not exist" in report["issues"]


def test_dot_dot_in_the_policy_path_does_not_hide_its_protection(host: Host) -> None:
    # `..` must resolve like the kernel resolves it, not count as "unprotected",
    # or a user bootstrap could redirect /operator/sub/../reflex.yaml.
    policy = host.policy(host.operator)
    (host.operator / "sub").mkdir(mode=0o755)
    indirect = host.operator / "sub" / ".." / "reflex.yaml"
    state = host.unsigned_rollout(host.user_dir / "state.json")
    host.bootstrap(host.user_dir / "bootstrap.yaml", rollout_state_path=str(state))
    host.evaluate_as_agent()

    assert trust.operator_controlled(indirect)
    with pytest.raises(ValueError, match=REFUSED):
        load_config(indirect)
    # A `..` that climbs out of a user-writable directory stays unprotected.
    assert not trust.operator_controlled(host.user_dir / ".." / ".jev-reflex" / "state.json")
    assert policy.exists()
