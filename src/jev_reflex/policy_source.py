"""Remote policy fetching and merge logic for central policy mode."""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import requests
import yaml

from .audit import AuditLog
from .config import PolicySourceConfig, ReflexConfig
from .signing import Ed25519Signer, load_public_key, verify_file

logger = logging.getLogger(__name__)


class PolicyFetchError(Exception):
    """Raised when policy fetching fails."""

    pass


class PolicySignatureError(Exception):
    """Raised when policy signature verification fails."""

    pass


class PolicyReloader:
    """Handles periodic policy fetching and hot-reloading."""

    def __init__(
        self,
        config: PolicySourceConfig,
        local_config_path: Path | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        """Initialize the policy reloader.

        Args:
            config: Policy source configuration.
            local_config_path: Path to local reflex.yaml for overrides.
            audit_log: Audit log for logging policy reloads.
        """
        self.config = config
        self.local_config_path = local_config_path
        self.audit_log = audit_log
        self.fetcher = PolicyFetcher(config)
        self._current_policy: ReflexConfig | None = None
        self._current_policy_hash: str | None = None
        self._last_fetch_time: float | None = None
        self._reload_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._has_cached_policy = False

    def start(self) -> None:
        """Start the policy reload thread."""
        if self.config.type is None:
            logger.info("No policy source configured, skipping policy reload")
            return

        # Initial fetch
        self._reload_policy()

        # Start reload thread
        self._reload_thread = threading.Thread(target=self._reload_loop, daemon=True)
        self._reload_thread.start()
        logger.info(
            f"Policy reload thread started with interval {self.config.poll_interval_seconds}s"
        )

    def stop(self) -> None:
        """Stop the policy reload thread."""
        self._stop_event.set()
        if self._reload_thread:
            self._reload_thread.join(timeout=5)
        logger.info("Policy reload thread stopped")

    def _reload_loop(self) -> None:
        """Periodically reload policy from remote source."""
        while not self._stop_event.wait(self.config.poll_interval_seconds):
            try:
                self._reload_policy()
            except Exception as e:
                logger.error(f"Failed to reload policy: {e}")

    def _reload_policy(self) -> None:
        """Reload policy from remote source."""
        try:
            central_policy, policy_hash, was_fetched = self.fetcher.fetch_with_cache()

            if not was_fetched:
                # Used cached policy, no change
                return

            # Load local override if present
            local_policy = None
            if self.local_config_path and self.local_config_path.exists():
                try:
                    with self.local_config_path.open("r", encoding="utf-8") as f:
                        local_data = yaml.safe_load(f)
                    local_policy = ReflexConfig.model_validate(local_data)
                except Exception as e:
                    logger.warning(f"Failed to load local policy override: {e}")

            # Merge policies
            merged_policy = PolicyMerger.merge_policies(central_policy, local_policy)

            with self._lock:
                self._current_policy = merged_policy
                self._current_policy_hash = policy_hash
                self._last_fetch_time = time.time()
                self._has_cached_policy = True

            # Log policy reload to audit
            if self.audit_log:
                try:
                    # Create a dummy entry for policy reload
                    from .models import PolicyDecision

                    self.audit_log.write_entry(
                        action_summary="policy_reload",
                        deterministic_findings=[],
                        jev_signals={},
                        policy_decision=PolicyDecision("ALLOW", (), ()),
                    )
                except Exception as e:
                    logger.warning(f"Failed to log policy reload to audit: {e}")

            logger.info(f"Policy reloaded successfully, hash: {policy_hash[:16]}...")

        except (PolicyFetchError, PolicySignatureError) as e:
            logger.error(f"Failed to fetch policy: {e}")
            # If we have no cached policy, fail closed
            with self._lock:
                if not self._has_cached_policy:
                    logger.critical(
                        "No cached policy available and fetch failed - refusing to start"
                    )
                    raise

    def get_current_policy(self) -> ReflexConfig | None:
        """Get the current merged policy.

        Returns:
            Current policy, or None if no policy is available.
        """
        with self._lock:
            return self._current_policy

    def get_status(self) -> dict[str, Any]:
        """Get the current status of the policy reloader.

        Returns:
            Dictionary with status information.
        """
        with self._lock:
            return {
                "policy_source_type": self.config.type,
                "policy_source_uri": self.config.uri,
                "last_fetch_time": self._last_fetch_time,
                "policy_hash": self._current_policy_hash,
                "has_cached_policy": self._has_cached_policy,
                "has_local_override": self.local_config_path is not None
                and self.local_config_path.exists(),
            }


class PolicyMerger:
    """Merges local policy overrides with central policy, enforcing tighten-only invariant."""

    @staticmethod
    def merge_policies(central: ReflexConfig, local: ReflexConfig | None) -> ReflexConfig:
        """Merge local policy with central policy, ensuring local can only tighten.

        The merge invariant:
        - Local cannot remove entries from central's hold_on or review_on
        - Local cannot raise thresholds above central's thresholds
        - Local can add new entries to hold_on or review_on
        - Local can lower thresholds (making them stricter)

        Args:
            central: The central policy from remote source.
            local: The local policy override (if present).

        Returns:
            Merged policy configuration.
        """
        if local is None:
            return central

        # Start with central policy as base
        merged_data = central.model_dump(mode="json")

        # Merge hold_on: local can add but not remove central entries
        central_hold_on = set(central.hold_on)
        local_hold_on = set(local.hold_on) if local.hold_on else set()
        merged_hold_on = central_hold_on.union(local_hold_on)

        # Log if local tried to remove a central hold_on entry
        removed_hold_on = central_hold_on - local_hold_on
        if removed_hold_on:
            logger.warning(
                f"Local policy attempted to remove hold_on entries from central policy: {removed_hold_on}. "
                "These entries will be retained to maintain the tighten-only invariant."
            )

        # Merge review_on: local can add but not remove central entries
        central_review_on = set(central.review_on)
        local_review_on = set(local.review_on) if local.review_on else set()
        merged_review_on = central_review_on.union(local_review_on)

        # Log if local tried to remove a central review_on entry
        removed_review_on = central_review_on - local_review_on
        if removed_review_on:
            logger.warning(
                f"Local policy attempted to remove review_on entries from central policy: {removed_review_on}. "
                "These entries will be retained to maintain the tighten-only invariant."
            )

        # Merge thresholds: local can only lower (make stricter), not raise
        # Strong threshold: local must be <= central (lower is stricter)
        merged_strong = min(central.thresholds.strong, local.thresholds.strong)
        if local.thresholds.strong > central.thresholds.strong:
            logger.warning(
                f"Local policy attempted to raise strong threshold from {central.thresholds.strong} to "
                f"{local.thresholds.strong}. "
                f"Central threshold {central.thresholds.strong} will be used to maintain the tighten-only invariant."
            )

        # Review threshold: local must be <= central (lower is stricter)
        merged_review = min(central.thresholds.review, local.thresholds.review)
        if local.thresholds.review > central.thresholds.review:
            logger.warning(
                f"Local policy attempted to raise review threshold from {central.thresholds.review} to "
                f"{local.thresholds.review}. "
                f"Central threshold {central.thresholds.review} will be used to maintain the tighten-only invariant."
            )

        # Apply merged values
        merged_data["hold_on"] = list(merged_hold_on)
        merged_data["review_on"] = list(merged_review_on)
        merged_data["thresholds"]["strong"] = merged_strong
        merged_data["thresholds"]["review"] = merged_review

        # Merge mode: enforce is stricter than review, which is stricter than advisory
        # Local can only move toward stricter mode
        mode_strictness = {"advisory": 0, "review": 1, "enforce": 2}
        central_strictness = mode_strictness[central.mode]
        local_strictness = mode_strictness[local.mode]

        if local_strictness > central_strictness:
            merged_data["mode"] = local.mode
        elif local_strictness < central_strictness:
            logger.warning(
                f"Local policy attempted to loosen mode from {central.mode} to {local.mode}. "
                f"Central mode {central.mode} will be used to maintain the tighten-only invariant."
            )
            merged_data["mode"] = central.mode
        else:
            merged_data["mode"] = central.mode

        return ReflexConfig.model_validate(merged_data)


class PolicyFetcher:
    """Fetches policy from remote sources (git, https, local)."""

    def __init__(self, config: PolicySourceConfig, cache_dir: Path | None = None) -> None:
        """Initialize the policy fetcher.

        Args:
            config: Policy source configuration.
            cache_dir: Directory for caching fetched policies.
        """
        self.config = config
        self.cache_dir = cache_dir or Path.home() / ".jev-reflex" / "policy-cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._last_fetch_time: float | None = None
        self._last_policy_hash: str | None = None
        self._cached_policy: ReflexConfig | None = None
        self._cached_policy_path: Path | None = None
        self._lock = threading.Lock()

    def _compute_policy_hash(self, policy: ReflexConfig) -> str:
        """Compute a hash of the policy configuration."""
        return hashlib.sha256(
            json.dumps(policy.model_dump(mode="json"), sort_keys=True).encode()
        ).hexdigest()

    def fetch(self) -> tuple[ReflexConfig, str]:
        """Fetch policy from the configured source.

        Returns:
            (policy, policy_hash) tuple.

        Raises:
            PolicyFetchError: If fetching fails.
            PolicySignatureError: If signature verification fails.
        """
        if self.config.type is None:
            raise PolicyFetchError("policy_source.type is not configured")

        if self.config.type == "git":
            return self._fetch_from_git()
        elif self.config.type == "https":
            return self._fetch_from_https()
        elif self.config.type == "local":
            return self._fetch_from_local()
        else:
            raise PolicyFetchError(f"Unsupported policy source type: {self.config.type}")

    def _fetch_from_git(self) -> tuple[ReflexConfig, str]:
        """Fetch policy from a git repository."""
        uri = self.config.uri
        ref = self.config.ref

        if not uri or not ref:
            raise PolicyFetchError("Git policy source requires uri and ref")

        # Create a temporary directory for the git clone
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Clone the repository
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", "--branch", ref, uri, str(tmpdir_path)],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.TimeoutExpired as e:
                raise PolicyFetchError("Git clone timed out") from e
            except subprocess.CalledProcessError as e:
                raise PolicyFetchError(f"Git clone failed: {e.stderr.decode()}") from e

            # Look for reflex.yaml in the repository
            policy_path = tmpdir_path / "reflex.yaml"
            if not policy_path.exists():
                raise PolicyFetchError("reflex.yaml not found in git repository")

            # Load the policy
            with policy_path.open("r", encoding="utf-8") as f:
                policy_data = yaml.safe_load(f)

            policy = ReflexConfig.model_validate(policy_data)

            # Verify signature
            signature_path = policy_path.with_suffix(policy_path.suffix + ".sig")
            if not signature_path.exists():
                raise PolicySignatureError("Policy signature file not found in git repository")

            if not self.config.pinned_signature_pubkey:
                raise PolicySignatureError(
                    "pinned_signature_pubkey is required for signature verification"
                )

            # Verify signature
            self._verify_signature(policy_path, signature_path, self.config.pinned_signature_pubkey)

            policy_hash = self._compute_policy_hash(policy)

            return policy, policy_hash

    def _fetch_from_https(self) -> tuple[ReflexConfig, str]:
        """Fetch policy from an HTTPS endpoint."""
        uri = self.config.uri

        if not uri:
            raise PolicyFetchError("HTTPS policy source requires uri")

        try:
            response = requests.get(uri, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            raise PolicyFetchError(f"Failed to fetch policy from HTTPS: {e}") from e

        # Load the policy
        policy_data = yaml.safe_load(response.text)
        policy = ReflexConfig.model_validate(policy_data)

        # For HTTPS, we expect the signature to be at <uri>.sig
        try:
            sig_response = requests.get(f"{uri}.sig", timeout=30)
            sig_response.raise_for_status()
        except requests.RequestException as e:
            raise PolicySignatureError(f"Failed to fetch policy signature: {e}") from e

        # Verify signature
        with tempfile.NamedTemporaryFile(delete=False) as policy_file:
            policy_file.write(response.text.encode())
            policy_file_path = Path(policy_file.name)

        with tempfile.NamedTemporaryFile(delete=False) as sig_file:
            sig_file.write(sig_response.content)
            sig_file_path = Path(sig_file.name)

        try:
            if not self.config.pinned_signature_pubkey:
                raise PolicySignatureError(
                    "pinned_signature_pubkey is required for signature verification"
                )

            self._verify_signature(
                policy_file_path, sig_file_path, self.config.pinned_signature_pubkey
            )
        finally:
            policy_file_path.unlink()
            sig_file_path.unlink()

        policy_hash = self._compute_policy_hash(policy)

        return policy, policy_hash

    def _fetch_from_local(self) -> tuple[ReflexConfig, str]:
        """Fetch policy from a local file."""
        uri = self.config.uri

        if not uri:
            raise PolicyFetchError("Local policy source requires uri")

        policy_path = Path(uri).expanduser()
        if not policy_path.exists():
            raise PolicyFetchError(f"Local policy file not found: {policy_path}")

        with policy_path.open("r", encoding="utf-8") as f:
            policy_data = yaml.safe_load(f)

        policy = ReflexConfig.model_validate(policy_data)

        # Verify signature
        signature_path = policy_path.with_suffix(policy_path.suffix + ".sig")
        if not signature_path.exists():
            raise PolicySignatureError("Policy signature file not found")

        if not self.config.pinned_signature_pubkey:
            raise PolicySignatureError(
                "pinned_signature_pubkey is required for signature verification"
            )

        self._verify_signature(policy_path, signature_path, self.config.pinned_signature_pubkey)

        policy_hash = self._compute_policy_hash(policy)

        return policy, policy_hash

    def _verify_signature(self, policy_path: Path, signature_path: Path, pubkey: str) -> None:
        """Verify the policy signature using the pinned public key."""
        # Write the public key to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as pubkey_file:
            pubkey_file.write(pubkey)
            pubkey_file_path = Path(pubkey_file.name)

        try:
            public_key = load_public_key(pubkey_file_path)
            signer = Ed25519Signer()

            if not verify_file(policy_path, signature_path, public_key, signer):
                raise PolicySignatureError("Policy signature verification failed")
        finally:
            pubkey_file_path.unlink()

    def fetch_with_cache(self) -> tuple[ReflexConfig, str, bool]:
        """Fetch policy, using cached version if available and unchanged.

        Returns:
            (policy, policy_hash, was_fetched) where was_fetched is True if
            a new policy was fetched, False if cached was used.
        """
        with self._lock:
            try:
                policy, policy_hash = self.fetch()
                self._cached_policy = policy
                self._last_policy_hash = policy_hash
                self._last_fetch_time = time.time()
                return policy, policy_hash, True
            except (PolicyFetchError, PolicySignatureError) as e:
                # If we have a cached policy, use it
                if self._cached_policy is not None:
                    logger.warning(f"Failed to fetch policy ({e}), using cached policy")
                    return self._cached_policy, self._last_policy_hash or "", False
                # No cached policy, fail closed
                raise

    def get_status(self) -> dict[str, Any]:
        """Get the current status of the policy fetcher.

        Returns:
            Dictionary with status information.
        """
        return {
            "policy_source_type": self.config.type,
            "policy_source_uri": self.config.uri,
            "last_fetch_time": self._last_fetch_time,
            "policy_hash": self._last_policy_hash,
            "has_cached_policy": self._cached_policy is not None,
        }
