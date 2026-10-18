"""Detached signing failures and optional real Cosign policy/audit integration."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from jev_reflex import config as config_module
from jev_reflex.audit import AuditLog
from jev_reflex.cli import app
from jev_reflex.config import BootstrapConfig, ReflexConfig, load_config
from jev_reflex.policy import decide
from jev_reflex.signing import CosignSigner, load_public_key, sign_file, verify_file


@pytest.mark.parametrize("failure", [FileNotFoundError, subprocess.TimeoutExpired])
def test_cosign_execution_errors_do_not_expose_diagnostics(tmp_path, monkeypatch, failure):
    key = tmp_path / "key.pem"
    key.write_text("fixture")

    def fail(*args, **kwargs):
        if failure is subprocess.TimeoutExpired:
            raise failure("password=private-fixture", 30)
        raise failure("password=private-fixture")

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="unavailable or exceeded") as error:
        CosignSigner(key).sign(b"private blob")
    assert "private-fixture" not in str(error.value)


@pytest.mark.parametrize("output", [b"", b"not base64!"])
def test_cosign_rejects_malformed_signatures(tmp_path, monkeypatch, output):
    key = tmp_path / "key.pem"
    key.write_text("fixture")
    directories = []

    def run(argv, **kwargs):
        blob = Path(argv[-1])
        directories.append(blob.parent)
        assert blob.read_bytes() == b"private data"
        assert blob.parent.stat().st_mode & 0o777 == 0o700
        assert "--tlog-upload=false" in argv
        assert "--use-signing-config=false" in argv
        assert kwargs["shell"] is False
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert "TYPESAFE_API_KEY" not in kwargs["env"]
        assert "JRX_ID_TOKEN" not in kwargs["env"]
        return subprocess.CompletedProcess(argv, 0, output, b"secret diagnostics")

    monkeypatch.setenv("TYPESAFE_API_KEY", "fixture-key")
    monkeypatch.setenv("JRX_ID_TOKEN", "fixture-token")
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(RuntimeError, match="invalid signature|empty signature"):
        CosignSigner(key).sign(b"private data")
    assert all(not directory.exists() for directory in directories)


def test_cosign_failed_verification_never_allows(tmp_path, monkeypatch):
    def run(argv, **kwargs):
        assert "--offline" in argv and "--insecure-ignore-tlog" in argv
        assert Path(argv[argv.index("--key") + 1]).read_bytes() == b"pinned PEM key"
        assert Path(argv[argv.index("--signature") + 1]).read_bytes() == base64.b64encode(
            b"raw sig"
        )
        return subprocess.CompletedProcess(argv, 1, b"", b"secret diagnostics")

    monkeypatch.setattr(subprocess, "run", run)
    assert not CosignSigner().verify(b"blob", b"raw sig", b"pinned PEM key")


@pytest.fixture
def real_cosign(tmp_path, monkeypatch):
    binary = os.environ.get("JRX_TEST_COSIGN_BINARY") or shutil.which("cosign")
    if not binary:
        pytest.skip("Cosign CLI unavailable; set JRX_TEST_COSIGN_BINARY for integration tests")
    binary = str(Path(binary).resolve(strict=True))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "cosign").symlink_to(binary)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("COSIGN_PASSWORD", "local-test-password")
    prefix = tmp_path / "cosign"
    subprocess.run(
        [binary, "generate-key-pair", "--output-key-prefix", str(prefix)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        check=True,
    )
    return prefix.with_suffix(".key"), prefix.with_suffix(".pub")


@pytest.mark.parametrize("data", [b"mode: enforce\n", b"", b"\x00\xff\x80"])
def test_real_cosign_round_trip_tampering_and_wrong_key(tmp_path, real_cosign, data):
    key, public = real_cosign
    signer = CosignSigner(key)
    blob = tmp_path / "policy.yaml"
    blob.write_bytes(data)
    signature_path = sign_file(blob, signer)
    pinned = load_public_key(public)
    assert verify_file(blob, signature_path, pinned, signer)
    assert not signer.verify(b"mode: advisory\n", signature_path.read_bytes(), pinned)
    assert not signer.verify(blob.read_bytes(), b"malformed signature", pinned)
    assert not signer.verify(blob.read_bytes(), signature_path.read_bytes(), b"wrong key")


def test_real_cosign_cli_policy_sign_verify_and_bootstrap(tmp_path, real_cosign, monkeypatch):
    key, public = real_cosign
    policy = tmp_path / "reflex.yaml"
    policy.write_text("mode: enforce\n")
    runner = CliRunner()
    signed = runner.invoke(
        app, ["policy", "sign", str(policy), "--key", str(key), "--signer-type", "cosign"]
    )
    assert signed.exit_code == 0, signed.output
    verified = runner.invoke(
        app,
        ["policy", "verify", str(policy), "--public-key", str(public), "--signer-type", "cosign"],
    )
    assert verified.exit_code == 0, verified.output
    monkeypatch.setattr(
        config_module,
        "load_bootstrap_config",
        lambda: BootstrapConfig(
            require_signature=True, public_key_path=str(public), signer_type="cosign"
        ),
    )
    assert load_config(policy).mode == "enforce"
    policy.write_text("mode: advisory\n")
    with pytest.raises(ValueError, match="Signature verification failed"):
        load_config(policy)
    rejected = runner.invoke(
        app,
        ["policy", "verify", str(policy), "--public-key", str(public), "--signer-type", "cosign"],
    )
    assert rejected.exit_code == 1


def test_real_cosign_audit_signatures(tmp_path, real_cosign):
    key, public = real_cosign
    config = ReflexConfig(
        audit={"enabled": True, "path": str(tmp_path / "audit.jsonl")},
        signing={"private_key_path": str(key), "signer_type": "cosign"},
    )
    audit = AuditLog(config)
    audit.write_entry("fixture action", [], {}, decide([], {}, config))
    valid, message = audit.verify(public)
    assert valid, message
    assert "signatures verified" in message


def test_real_cosign_bootstrap_verifies_captured_bytes(tmp_path, real_cosign, monkeypatch):
    key, public = real_cosign
    path = tmp_path / "reflex.yaml"
    path.write_bytes(b"mode: enforce\n")
    sign_file(path, CosignSigner(key))
    monkeypatch.setattr(
        config_module,
        "load_bootstrap_config",
        lambda: BootstrapConfig(
            require_signature=True, public_key_path=str(public), signer_type="cosign"
        ),
    )
    verify = CosignSigner.verify

    def replace_after_capture(self, data, signature, public_key):
        path.write_bytes(b"mode: advisory\n")
        return verify(self, data, signature, public_key)

    monkeypatch.setattr(CosignSigner, "verify", replace_after_capture)
    assert load_config(path).mode == "enforce"
