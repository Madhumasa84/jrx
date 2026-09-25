"""Policy parsing must consume exactly the authenticated byte snapshot."""

from pathlib import Path

import pytest
import yaml

from jev_reflex import config as config_module
from jev_reflex.config import BootstrapConfig, PolicySourceConfig, load_config
from jev_reflex.policy_source import PolicyFetcher, PolicySignatureError
from jev_reflex.signing import Ed25519Signer


@pytest.mark.parametrize("loader", ["config", "local"])
def test_file_replacement_cannot_authenticate_different_policy(tmp_path: Path, monkeypatch, loader):
    path = tmp_path / "reflex.yaml"
    trusted = b"mode: enforce\n"
    path.write_bytes(b"mode: advisory\n")
    signer = Ed25519Signer()
    path.with_suffix(".yaml.sig").write_bytes(signer.sign(trusted))
    key = tmp_path / "key.pem"
    key.write_text(signer.get_public_key_pem())
    original = yaml.safe_load

    def replace_after_parse(value):
        parsed = original(value)
        path.write_bytes(trusted)
        return parsed

    monkeypatch.setattr(yaml, "safe_load", replace_after_parse)
    if loader == "config":
        monkeypatch.setattr(
            config_module,
            "load_bootstrap_config",
            lambda: BootstrapConfig(require_signature=True, public_key_path=str(key)),
        )
        with pytest.raises(ValueError, match="Signature verification failed"):
            load_config(path)
    else:
        fetcher = PolicyFetcher(
            PolicySourceConfig(
                type="local", uri=str(path), pinned_signature_pubkey=signer.get_public_key_pem()
            ),
            cache_dir=tmp_path / "cache",
        )
        with pytest.raises(PolicySignatureError, match="signature verification failed"):
            fetcher.fetch()
