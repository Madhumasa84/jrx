"""Offline tests for signed policy fetches and last-known-good caching."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import requests
import yaml

from jev_reflex.config import PolicySourceConfig, ReflexConfig
from jev_reflex.policy_source import (
    PolicyFetcher,
    PolicyFetchError,
    PolicyReloader,
    PolicySignatureError,
)
from jev_reflex.signing import Ed25519Signer, sign_file


def _policy_text(mode: str = "enforce") -> str:
    return yaml.safe_dump(ReflexConfig(mode=mode).model_dump(mode="json"), sort_keys=True)


def _local_fetcher(path: Path, signer: Ed25519Signer, cache_dir: Path) -> PolicyFetcher:
    return PolicyFetcher(
        PolicySourceConfig(
            type="local",
            uri=str(path),
            pinned_signature_pubkey=signer.get_public_key_pem(),
        ),
        cache_dir=cache_dir,
    )


def test_fetch_local_policy_requires_and_checks_signature(tmp_path: Path) -> None:
    signer = Ed25519Signer()
    policy_path = tmp_path / "reflex.yaml"
    policy_path.write_text(_policy_text(), encoding="utf-8")
    sign_file(policy_path, signer)
    fetcher = _local_fetcher(policy_path, signer, tmp_path / "cache")

    policy, policy_hash = fetcher.fetch()

    assert policy.mode == "enforce"
    assert policy_hash == fetcher._compute_policy_hash(policy)

    policy_path.write_text(_policy_text("advisory"), encoding="utf-8")
    with pytest.raises(PolicySignatureError, match="verification failed"):
        fetcher.fetch()


def test_fetch_local_policy_rejects_missing_signature(tmp_path: Path) -> None:
    signer = Ed25519Signer()
    policy_path = tmp_path / "reflex.yaml"
    policy_path.write_text(_policy_text(), encoding="utf-8")
    fetcher = _local_fetcher(policy_path, signer, tmp_path / "cache")

    with pytest.raises(PolicySignatureError, match="signature file not found"):
        fetcher.fetch()


@pytest.mark.parametrize("invalid_policy", ["mode: [unclosed", "mode: unsupported"])
def test_fetch_local_policy_rejects_invalid_policy_data(
    tmp_path: Path, invalid_policy: str
) -> None:
    signer = Ed25519Signer()
    policy_path = tmp_path / "reflex.yaml"
    policy_path.write_text(invalid_policy, encoding="utf-8")
    sign_file(policy_path, signer)
    fetcher = _local_fetcher(policy_path, signer, tmp_path / "cache")

    with pytest.raises((yaml.YAMLError, ValueError)):
        fetcher.fetch()


def test_fetch_https_policy_verifies_downloaded_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = Ed25519Signer()
    policy_text = _policy_text()
    signature = signer.sign(policy_text.encode("utf-8"))
    responses = [
        _FakeResponse(text=policy_text),
        _FakeResponse(content=signature),
    ]
    requested: list[tuple[str, float]] = []

    def fake_get(uri: str, *, timeout: float) -> _FakeResponse:
        requested.append((uri, timeout))
        return responses.pop(0)

    monkeypatch.setattr("jev_reflex.policy_source.requests.get", fake_get)
    fetcher = PolicyFetcher(
        PolicySourceConfig(
            type="https",
            uri="https://policy.example.invalid/reflex.yaml",
            pinned_signature_pubkey=signer.get_public_key_pem(),
        ),
        cache_dir=tmp_path / "cache",
    )

    policy, _ = fetcher.fetch()

    assert policy.mode == "enforce"
    assert requested == [
        ("https://policy.example.invalid/reflex.yaml", 30),
        ("https://policy.example.invalid/reflex.yaml.sig", 30),
    ]


def test_fetch_https_policy_rejects_bad_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = Ed25519Signer()
    policy_text = _policy_text()
    monkeypatch.setattr(
        "jev_reflex.policy_source.requests.get",
        lambda _uri, **_kwargs: _FakeResponse(
            text=policy_text,
            content=b"not a valid signature",
        ),
    )
    fetcher = PolicyFetcher(
        PolicySourceConfig(
            type="https",
            uri="https://policy.example.invalid/reflex.yaml",
            pinned_signature_pubkey=signer.get_public_key_pem(),
        ),
        cache_dir=tmp_path / "cache",
    )

    with pytest.raises(PolicySignatureError, match="verification failed"):
        fetcher.fetch()


@pytest.mark.parametrize("failure", [requests.Timeout("timeout"), requests.HTTPError("503")])
def test_fetch_https_failure_is_reported_as_policy_fetch_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    signer = Ed25519Signer()

    def fail_get(_uri: str, **_kwargs: Any) -> _FakeResponse:
        raise failure

    monkeypatch.setattr("jev_reflex.policy_source.requests.get", fail_get)
    fetcher = PolicyFetcher(
        PolicySourceConfig(
            type="https",
            uri="https://policy.example.invalid/reflex.yaml",
            pinned_signature_pubkey=signer.get_public_key_pem(),
        ),
        cache_dir=tmp_path / "cache",
    )

    with pytest.raises(PolicyFetchError, match="Failed to fetch policy from HTTPS"):
        fetcher.fetch()


def test_fetch_git_policy_verifies_repository_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = Ed25519Signer()

    def fake_git_clone(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        clone_dir = Path(args[-1])
        policy_path = clone_dir / "reflex.yaml"
        policy_path.write_text(_policy_text(), encoding="utf-8")
        sign_file(policy_path, signer)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr("jev_reflex.policy_source.subprocess.run", fake_git_clone)
    fetcher = PolicyFetcher(
        PolicySourceConfig(
            type="git",
            uri="https://git.example.invalid/policy.git",
            ref="main",
            pinned_signature_pubkey=signer.get_public_key_pem(),
        ),
        cache_dir=tmp_path / "cache",
    )

    policy, policy_hash = fetcher.fetch()

    assert policy.mode == "enforce"
    assert len(policy_hash) == 64


@pytest.mark.parametrize(
    "error",
    [
        subprocess.TimeoutExpired(cmd="git clone", timeout=30),
        subprocess.CalledProcessError(128, "git clone", stderr=b"clone failed"),
    ],
)
def test_fetch_git_failure_is_reported_as_policy_fetch_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    signer = Ed25519Signer()

    def fail_clone(*_args: Any, **_kwargs: Any) -> None:
        raise error

    monkeypatch.setattr("jev_reflex.policy_source.subprocess.run", fail_clone)
    fetcher = PolicyFetcher(
        PolicySourceConfig(
            type="git",
            uri="https://git.example.invalid/policy.git",
            ref="main",
            pinned_signature_pubkey=signer.get_public_key_pem(),
        ),
        cache_dir=tmp_path / "cache",
    )

    with pytest.raises(PolicyFetchError, match="Git clone"):
        fetcher.fetch()


def test_fetch_with_cache_fails_closed_without_last_known_good_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = Ed25519Signer()
    fetcher = _local_fetcher(tmp_path / "unused.yaml", signer, tmp_path / "cache")

    def fail_fetch() -> tuple[ReflexConfig, str]:
        raise PolicyFetchError("offline")

    monkeypatch.setattr(fetcher, "fetch", fail_fetch)

    with pytest.raises(PolicyFetchError, match="offline"):
        fetcher.fetch_with_cache()


def test_reloader_keeps_last_known_good_policy_after_bad_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = Ed25519Signer()
    policy_path = tmp_path / "reflex.yaml"
    policy_path.write_text(_policy_text("enforce"), encoding="utf-8")
    sign_file(policy_path, signer)
    config = PolicySourceConfig(
        type="local",
        uri=str(policy_path),
        pinned_signature_pubkey=signer.get_public_key_pem(),
    )
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    reloader = PolicyReloader(config)

    reloader._reload_policy()
    original_policy = reloader.get_current_policy()
    original_hash = reloader.get_status()["policy_hash"]
    assert original_policy is not None
    assert original_policy.mode == "enforce"

    policy_path.write_text(_policy_text("advisory"), encoding="utf-8")
    sign_file(policy_path, signer)
    reloader._reload_policy()
    refreshed_policy = reloader.get_current_policy()
    refreshed_status = reloader.get_status()
    assert refreshed_policy is not None
    assert refreshed_policy.mode == "advisory"
    assert refreshed_status["policy_hash"] != original_hash

    policy_path.write_text(_policy_text("review"), encoding="utf-8")
    reloader._reload_policy()

    assert reloader.get_current_policy() == refreshed_policy
    assert reloader.get_status()["policy_hash"] == refreshed_status["policy_hash"]


class _FakeResponse:
    def __init__(
        self,
        *,
        text: str = "",
        content: bytes | None = None,
    ) -> None:
        self.text = text
        self.content = content if content is not None else text.encode("utf-8")

    def raise_for_status(self) -> None:
        return None


def test_https_signature_uses_original_bytes_not_http_text_decoding(tmp_path, monkeypatch):
    signer = Ed25519Signer()
    raw = "mode: enforce\n# café\n".encode()
    policy_response = requests.Response()
    policy_response.status_code = 200
    policy_response._content = raw
    policy_response.encoding = "iso-8859-1"
    signature_response = requests.Response()
    signature_response.status_code = 200
    signature_response._content = signer.sign(raw)
    responses = iter([policy_response, signature_response])
    monkeypatch.setattr("jev_reflex.policy_source.requests.get", lambda *a, **k: next(responses))
    fetcher = PolicyFetcher(
        PolicySourceConfig(
            type="https",
            uri="https://policy.example/reflex.yaml",
            pinned_signature_pubkey=signer.get_public_key_pem(),
        ),
        cache_dir=tmp_path / "cache",
    )
    policy, _ = fetcher.fetch()
    assert policy.mode == "enforce"


def test_successful_policy_reload_writes_auditable_event(tmp_path, monkeypatch):
    from jev_reflex.audit import AuditLog
    from jev_reflex.policy_source import PolicyReloader

    config = ReflexConfig(audit={"enabled": True, "path": str(tmp_path / "audit.log")})
    audit = AuditLog(config)
    reloader = PolicyReloader(PolicySourceConfig(), audit_log=audit)
    monkeypatch.setattr(
        reloader.fetcher,
        "fetch_with_cache",
        lambda: (ReflexConfig(), "a" * 64, True),
    )
    reloader._reload_policy()
    assert audit.verify() == (True, "chain intact, 1 entries")
    assert audit.tail(1)[0]["action_summary"] == "policy_reload"
