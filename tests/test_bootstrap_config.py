"""Tests for bootstrap configuration and policy signature verification."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from jev_reflex.config import BootstrapConfig, load_bootstrap_config, load_config
from jev_reflex.signing import Ed25519Signer, sign_file


def test_bootstrap_config_defaults() -> None:
    """Test that bootstrap config has safe defaults."""
    config = BootstrapConfig()
    assert config.require_signature is False
    assert config.public_key_path is None
    assert config.signer_type == "ed25519"


def test_load_bootstrap_config_nonexistent() -> None:
    """Test loading bootstrap config when it doesn't exist."""
    config = load_bootstrap_config(Path("/nonexistent/bootstrap.yaml"))
    assert config.require_signature is False


def test_load_bootstrap_config_from_file() -> None:
    """Test loading bootstrap config from a file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        bootstrap_file = tmpdir_path / "bootstrap.yaml"
        bootstrap_file.write_text(
            "require_signature: true\npublic_key_path: /path/to/key.pem\nsigner_type: ed25519\n"
        )

        config = load_bootstrap_config(bootstrap_file)
        assert config.require_signature is True
        assert config.public_key_path == "/path/to/key.pem"
        assert config.signer_type == "ed25519"


def test_load_config_without_signature() -> None:
    """Test that config loads without signature when not required."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        config_file = tmpdir_path / "reflex.yaml"
        config_file.write_text("mode: enforce\n")

        # Should load without error
        config = load_config(config_file)
        assert config.mode == "enforce"


def test_load_config_with_signature_required_missing() -> None:
    """Test that config fails to load when signature is required but missing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        config_file = tmpdir_path / "reflex.yaml"
        config_file.write_text("mode: enforce\n")

        bootstrap_file = tmpdir_path / "bootstrap.yaml"
        bootstrap_file.write_text(
            "require_signature: true\npublic_key_path: /path/to/key.pem\nsigner_type: ed25519\n"
        )

        # Patch load_bootstrap_config to return our test config
        from jev_reflex import config as config_module

        original_load = config_module.load_bootstrap_config
        config_module.load_bootstrap_config = lambda: load_bootstrap_config(bootstrap_file)

        try:
            with pytest.raises(
                ValueError, match="Signature verification required but signature file not found"
            ):
                load_config(config_file)
        finally:
            config_module.load_bootstrap_config = original_load


def test_load_config_with_signature_invalid() -> None:
    """Test that config fails to load when signature is invalid."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        config_file = tmpdir_path / "reflex.yaml"
        config_file.write_text("mode: enforce\n")

        # Create a public key
        signer = Ed25519Signer()
        public_key_file = tmpdir_path / "public_key.raw"
        public_key_file.write_bytes(signer.get_public_key_bytes())

        # Create an invalid signature
        signature_file = tmpdir_path / "reflex.yaml.sig"
        signature_file.write_bytes(b"invalid signature")

        bootstrap_file = tmpdir_path / "bootstrap.yaml"
        bootstrap_file.write_text(
            f"require_signature: true\npublic_key_path: {public_key_file}\nsigner_type: ed25519\n"
        )

        # Patch load_bootstrap_config to return our test config
        from jev_reflex import config as config_module

        original_load = config_module.load_bootstrap_config
        config_module.load_bootstrap_config = lambda: load_bootstrap_config(bootstrap_file)

        try:
            with pytest.raises(ValueError, match="Signature verification failed"):
                load_config(config_file)
        finally:
            config_module.load_bootstrap_config = original_load


def test_load_config_with_valid_signature() -> None:
    """Test that config loads successfully with a valid signature."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        config_file = tmpdir_path / "reflex.yaml"
        config_file.write_text("mode: enforce\n")

        # Sign the config
        signer = Ed25519Signer()
        sign_file(config_file, signer)

        # Save the public key in raw format for verification
        public_key_file = tmpdir_path / "public_key.raw"
        public_key_file.write_bytes(signer.get_public_key_bytes())

        bootstrap_file = tmpdir_path / "bootstrap.yaml"
        bootstrap_file.write_text(
            f"require_signature: true\npublic_key_path: {public_key_file}\nsigner_type: ed25519\n"
        )

        # Patch load_bootstrap_config to return our test config
        from jev_reflex import config as config_module

        original_load = config_module.load_bootstrap_config
        config_module.load_bootstrap_config = lambda: load_bootstrap_config(bootstrap_file)

        try:
            # Should load without error
            config = load_config(config_file)
            assert config.mode == "enforce"
        finally:
            config_module.load_bootstrap_config = original_load
