"""Tests for cryptographic signing functionality."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from jev_reflex.signing import (
    CosignSigner,
    Ed25519Signer,
    load_public_key,
    sign_file,
    verify_file,
)


def test_ed25519_signer_generates_keypair() -> None:
    """Test that Ed25519Signer can generate a new keypair."""
    signer = Ed25519Signer()
    public_key_bytes = signer.get_public_key_bytes()
    private_key_pem = signer.get_private_key_pem()
    public_key_pem = signer.get_public_key_pem()

    assert len(public_key_bytes) == 32  # Ed25519 public key is 32 bytes
    assert "-----BEGIN PRIVATE KEY-----" in private_key_pem
    assert "-----BEGIN PUBLIC KEY-----" in public_key_pem


def test_ed25519_sign_and_verify() -> None:
    """Test that Ed25519Signer can sign and verify data."""
    signer = Ed25519Signer()
    data = b"test data for signing"

    signature = signer.sign(data)
    public_key = signer.get_public_key_bytes()

    assert len(signature) == 64  # Ed25519 signature is 64 bytes
    assert signer.verify(data, signature, public_key) is True


def test_ed25519_verify_fails_on_tampered_data() -> None:
    """Test that verification fails when data is tampered."""
    signer = Ed25519Signer()
    data = b"original data"
    signature = signer.sign(data)
    public_key = signer.get_public_key_bytes()

    # Verify original data
    assert signer.verify(data, signature, public_key) is True

    # Verify tampered data
    assert signer.verify(b"tampered data", signature, public_key) is False


def test_ed25519_load_private_key() -> None:
    """Test loading a private key from a file."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pem") as f:
        # Generate a key and save it
        signer = Ed25519Signer()
        f.write(signer.get_private_key_pem().encode())
        temp_path = Path(f.name)

    try:
        # Load the key
        loaded_signer = Ed25519Signer(private_key_path=temp_path)
        data = b"test data"
        signature = loaded_signer.sign(data)
        public_key = loaded_signer.get_public_key_bytes()

        assert loaded_signer.verify(data, signature, public_key) is True
    finally:
        temp_path.unlink()


def test_ed25519_load_private_key_not_found() -> None:
    """Test that loading a non-existent private key raises an error."""
    with pytest.raises(FileNotFoundError):
        Ed25519Signer(private_key_path=Path("/nonexistent/key.pem"))


def test_sign_file() -> None:
    """Test signing a file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        test_file = tmpdir_path / "test.txt"
        test_file.write_text("test file content")

        signer = Ed25519Signer()
        signature_path = sign_file(test_file, signer)

        assert signature_path.exists()
        assert signature_path.suffix == ".sig"
        assert len(signature_path.read_bytes()) == 64


def test_verify_file() -> None:
    """Test verifying a file's signature."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        test_file = tmpdir_path / "test.txt"
        test_file.write_text("test file content")

        signer = Ed25519Signer()
        signature_path = sign_file(test_file, signer)
        public_key = signer.get_public_key_bytes()

        assert verify_file(test_file, signature_path, public_key, signer) is True


def test_verify_file_tampered() -> None:
    """Test that verification fails when file is tampered."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        test_file = tmpdir_path / "test.txt"
        test_file.write_text("original content")

        signer = Ed25519Signer()
        signature_path = sign_file(test_file, signer)
        public_key = signer.get_public_key_bytes()

        # Tamper with the file
        test_file.write_text("tampered content")

        assert verify_file(test_file, signature_path, public_key, signer) is False


def test_load_public_key() -> None:
    """Test loading a public key from a file."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pem") as f:
        signer = Ed25519Signer()
        f.write(signer.get_public_key_pem().encode())
        temp_path = Path(f.name)

    try:
        public_key = load_public_key(temp_path)
        assert len(public_key) > 0
    finally:
        temp_path.unlink()


def test_load_public_key_not_found() -> None:
    """Test that loading a non-existent public key raises an error."""
    with pytest.raises(FileNotFoundError):
        load_public_key(Path("/nonexistent/key.pem"))


def test_cosign_signer_not_implemented() -> None:
    """Test that CosignSigner raises NotImplementedError for sign/verify."""
    signer = CosignSigner()
    with pytest.raises(NotImplementedError):
        signer.sign(b"test data")

    with pytest.raises(NotImplementedError):
        signer.verify(b"test data", b"signature", b"public_key")


def test_policy_signing_round_trip() -> None:
    """Test signing and verifying a policy file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        policy_file = tmpdir_path / "reflex.yaml"
        policy_file.write_text("mode: enforce\nthresholds:\n  strong: 0.9\n")

        # Sign the policy
        signer = Ed25519Signer()
        signature_path = sign_file(policy_file, signer)
        public_key = signer.get_public_key_bytes()

        # Verify the signature
        assert verify_file(policy_file, signature_path, public_key, signer) is True

        # Tamper with the policy
        policy_file.write_text("mode: advisory\nthresholds:\n  strong: 0.5\n")

        # Verification should fail
        assert verify_file(policy_file, signature_path, public_key, signer) is False


def test_decision_signing_round_trip() -> None:
    """Test signing and verifying a decision hash."""
    signer = Ed25519Signer()
    entry_hash = "abc123def456"

    # Sign the hash
    signature = signer.sign(entry_hash.encode())
    public_key = signer.get_public_key_bytes()

    # Verify the signature
    assert signer.verify(entry_hash.encode(), signature, public_key) is True

    # Flip one byte and verify fails
    tampered_hash = "abc123def457"
    assert signer.verify(tampered_hash.encode(), signature, public_key) is False
