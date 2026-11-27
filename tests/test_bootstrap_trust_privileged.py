"""Trust anchors with real root-owned files, on Linux and macOS CI runners.

The simulated-uid tests in ``test_bootstrap_trust.py`` cover the rules. These repeat the
central cases against the operating system itself: files that root owns and the test
user cannot change, a root-owned file the user can still replace through its directory,
and a POSIX ACL that grants write access the mode bits do not show.

They need a non-root user with password-less ``sudo`` and run only when
``JRX_PRIVILEGED_TESTS=1`` (set in CI). They create files only under a fresh
``/tmp/jrx-trust-*`` directory and remove it afterwards.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from jev_reflex import config as config_module
from jev_reflex import trust
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


def _sudo_available() -> bool:
    if os.environ.get("JRX_PRIVILEGED_TESTS") != "1" or os.geteuid() == 0:
        return False
    return subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(
    not _sudo_available(), reason="needs JRX_PRIVILEGED_TESTS=1, a non-root user and sudo -n"
)


def _sudo(*args: str) -> None:
    subprocess.run(["sudo", "-n", *args], check=True, capture_output=True)


@pytest.fixture
def root_dir() -> Iterator[Path]:
    """A root-owned 0755 directory directly under the sticky, root-owned /tmp."""
    created = subprocess.run(
        ["sudo", "-n", "mktemp", "-d", "/tmp/jrx-trust-XXXXXX"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    path = Path(created)
    _sudo("chmod", "0755", created)
    try:
        yield path.resolve()
    finally:
        _sudo("rm", "-rf", created)


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".jev-reflex").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    return home


def _install_as_root(source: Path, target: Path, mode: str = "0644") -> Path:
    _sudo("install", "-o", "root", "-m", mode, str(source), str(target))
    return target


def _signed_operator_policy(staging: Path, root_dir: Path) -> tuple[Path, Path]:
    signer = Ed25519Signer()
    key = staging / "policy.pub"
    key.write_text(signer.get_public_key_pem())
    policy = staging / "reflex.yaml"
    policy.write_text("mode: enforce\n")
    signature = sign_file(policy, signer)
    _install_as_root(key, root_dir / "policy.pub")
    _install_as_root(policy, root_dir / "reflex.yaml")
    _install_as_root(signature, root_dir / "reflex.yaml.sig")
    return root_dir / "reflex.yaml", root_dir / "policy.pub"


def test_root_owned_bootstrap_anchors_trust_and_cannot_be_changed(
    tmp_path: Path, root_dir: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, key = _signed_operator_policy(tmp_path, root_dir)
    bootstrap = tmp_path / "bootstrap.yaml"
    bootstrap.write_text(json.dumps({"require_signature": True, "public_key_path": str(key)}))
    system = _install_as_root(bootstrap, root_dir / "bootstrap.yaml")
    monkeypatch.setattr(config_module, "SYSTEM_BOOTSTRAP", system)

    assert load_bootstrap_config().operator_controlled
    assert load_config(policy).mode == "enforce"
    report = trust_report(policy)
    assert report["policy_protected_from_evaluating_user"] is True, report

    # Physical prevention: the agent's user can neither edit nor replace the bootstrap.
    with pytest.raises(PermissionError):
        system.write_text("require_signature: false\n")
    forged = tmp_path / "forged.yaml"
    forged.write_text("require_signature: false\n")
    with pytest.raises(PermissionError):
        os.replace(forged, system)
    assert load_bootstrap_config().require_signature is True


def test_root_owned_bootstrap_in_a_user_directory_is_replaceable(tmp_path: Path) -> None:
    directory = tmp_path / "user-owned"
    directory.mkdir()
    source = tmp_path / "bootstrap.yaml"
    source.write_text("require_signature: true\n")
    target = _install_as_root(source, directory / "bootstrap.yaml")
    try:
        assert not trust.operator_controlled(target)
        # Why: owning the directory lets the user rename a forged file over root's.
        forged = tmp_path / "forged.yaml"
        forged.write_text("require_signature: false\n")
        os.replace(forged, target)
        assert target.read_text() == "require_signature: false\n"
    finally:
        _sudo("rm", "-rf", str(directory))


def test_user_bootstrap_cannot_redirect_a_root_owned_policy(
    tmp_path: Path, root_dir: Path, isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config_module, "SYSTEM_BOOTSTRAP", root_dir / "absent.yaml")
    source = tmp_path / "reflex.yaml"
    source.write_text("mode: enforce\n")
    policy = _install_as_root(source, root_dir / "reflex.yaml")
    state = isolated_home / ".jev-reflex" / "state.json"
    weaker = ReflexConfig.model_validate({"mode": "advisory"})
    RolloutStore(state, BootstrapConfig()).stage(weaker, weaker)
    (isolated_home / ".jev-reflex" / "bootstrap.yaml").write_text(
        json.dumps({"rollout_state_path": str(state)})
    )

    with pytest.raises(ValueError, match="rewritten or replaced by the evaluating user"):
        load_config(policy)
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "cwd": str(tmp_path),
    }
    result = CliRunner().invoke(
        app, ["claude-code-hook", "--config", str(policy)], input=json.dumps(event)
    )
    assert '"permissionDecision":"deny"' in result.output.replace(" ", ""), result.output


def _grant_acl_write(path: Path) -> None:
    user = subprocess.run(["id", "-un"], check=True, capture_output=True, text=True).stdout.strip()
    if sys.platform == "darwin":
        _sudo("chmod", "+a", f"{user} allow write", str(path))
    elif shutil.which("setfacl"):
        _sudo("setfacl", "-m", f"u:{user}:rw", str(path))
    else:
        pytest.skip("setfacl is not installed")


def test_acl_write_grant_defeats_mode_bits(tmp_path: Path, root_dir: Path) -> None:
    source = tmp_path / "bootstrap.yaml"
    source.write_text("require_signature: true\n")
    target = _install_as_root(source, root_dir / "bootstrap.yaml")
    identity = trust.evaluator_identity()
    assert trust.protected_location(target, identity) == target

    _grant_acl_write(target)
    # Ownership and mode bits alone still look protected...
    mode_bits_only = trust.Identity(identity.uid, identity.groups)
    assert trust.protected_location(target, mode_bits_only) == target
    # ...but the kernel grants the write, and the check now asks it.
    assert trust.protected_location(target, identity) is None
    target.write_text("require_signature: false\n")
