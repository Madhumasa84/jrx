"""Offline policy replay and staged activation of signed remote policies."""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import io
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .audit import AuditLog
from .config import BootstrapConfig, ReflexConfig, parse_policy_bytes, verify_policy_signature
from .models import Decision, DeterministicFinding
from .policy import decide, execution_allowed
from .signing import verify_pinned_ed25519

SCHEMA = 2
TrustRoot = Literal["bootstrap", "policy_source"]


@dataclass(frozen=True)
class SignedPolicy:
    """Exact policy bytes with the detached signature they were verified from.

    ``bootstrap`` names ``public_key_path``/``signer_type`` (the signed local
    baseline); ``policy_source`` names ``policy_source.pinned_signature_pubkey``
    with Ed25519 (a fetched central candidate).
    """

    raw: bytes
    signature: bytes
    trust_root: TrustRoot


def policy_hash(config: ReflexConfig) -> str:
    canonical = json.dumps(config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _executes(decision: Decision, config: ReflexConfig, degraded: bool) -> bool:
    return execution_allowed(
        decision,
        mode=config.mode,
        degraded=degraded,
        strict_review=config.strict_review_required,
    )


def enforcement_relaxations(baseline: ReflexConfig, candidate: ReflexConfig) -> list[str]:
    """Decision classes that run under ``candidate`` but were blocked under ``baseline``.

    This compares effective enforcement, so a mode downgrade (for example enforce to
    advisory) is a relaxation even when every replayed decision label stays the same.
    """
    relaxed = []
    decisions: tuple[Decision, ...] = ("ALLOW", "REVIEW", "HOLD")
    for decision in decisions:
        for degraded in (False, True):
            if not _executes(decision, baseline, degraded) and _executes(
                decision, candidate, degraded
            ):
                relaxed.append(f"{decision} (degraded)" if degraded else decision)
    return relaxed


def simulate(
    audit_path: Path,
    baseline: ReflexConfig,
    candidate: ReflexConfig,
    *,
    public_key: Path | None = None,
) -> dict[str, Any]:
    """Replay policy decisions over recorded findings, not original actions."""
    # Audit records cannot reconstruct raw commands, context, semantic samples,
    # or enforcement side effects. Only the pure decision inputs may change.
    replayable = {
        "mode",
        "thresholds",
        "hold_on",
        "review_on",
        "rule_modes",
        "stability",
        "stability_policy",
    }
    baseline_data = baseline.model_dump(mode="json")
    candidate_data = candidate.model_dump(mode="json")
    unsupported = sorted(
        name
        for name in baseline_data.keys() | candidate_data.keys()
        if name not in replayable and baseline_data.get(name) != candidate_data.get(name)
    )
    if baseline.stability_policy.mode != candidate.stability_policy.mode and "majority" in {
        baseline.stability_policy.mode,
        candidate.stability_policy.mode,
    }:
        unsupported.append("stability_policy.majority")
    if baseline.evaluator.provider == candidate.evaluator.provider != "jev":
        from .local_evaluator import active_local_signals, requires_hybrid_resolution

        baseline_signals = active_local_signals(baseline)
        if baseline_signals != active_local_signals(candidate):
            unsupported.append("evaluator.active_signals")
        elif baseline.evaluator.provider == "hybrid" and any(
            requires_hybrid_resolution(name, baseline)
            != requires_hybrid_resolution(name, candidate)
            for name in baseline_signals
        ):
            unsupported.append("evaluator.hybrid_fallback_signals")
    if unsupported:
        raise ValueError("cannot replay configuration changes: " + ", ".join(unsupported))
    public_key = AuditLog.verification_key(baseline, public_key)
    snapshot = audit_path.read_text(encoding="utf-8")
    AuditLog.verify_snapshot(baseline, snapshot, public_key_path=public_key)
    report: dict[str, Any] = {
        "baseline_hash": policy_hash(baseline),
        "candidate_hash": policy_hash(candidate),
        "total": 0,
        "replayed": 0,
        "skipped_legacy": 0,
        "skipped_policy_mismatch": 0,
        "skipped_decision_mismatch": 0,
        "changes": {
            "ALLOW_to_REVIEW": 0,
            "ALLOW_to_HOLD": 0,
            "REVIEW_to_ALLOW": 0,
            "REVIEW_to_HOLD": 0,
            "HOLD_to_ALLOW": 0,
            "HOLD_to_REVIEW": 0,
        },
        "examples": [],
        # Replayed decisions the candidate newly lets run: they become ALLOW, or the
        # candidate's mode executes a decision the baseline's mode blocked.
        "newly_executable": 0,
        # Decision classes the candidate's mode executes and the baseline's blocked,
        # whether or not the audit history contains such a decision.
        "enforcement_relaxations": enforcement_relaxations(baseline, candidate),
    }
    with io.StringIO(snapshot) as handle:
        for line in handle:
            entry = json.loads(line)
            if entry.get("event_type", "policy_decision") != "policy_decision":
                continue
            report["total"] += 1
            if not all(key in entry for key in ("risk_choice", "degraded", "forced_review")):
                report["skipped_legacy"] += 1
                continue
            if entry.get("policy_version_hash") != report["baseline_hash"]:
                report["skipped_policy_mismatch"] += 1
                continue
            findings = [
                DeterministicFinding.model_validate(item) for item in entry["hard_rule_findings"]
            ]
            arguments = {
                "risk_choice": entry["risk_choice"],
                "risk_confidence": entry.get("risk_confidence"),
                "degraded": entry["degraded"],
            }
            baseline_result = decide(findings, entry["jev_signals"], baseline, **arguments).decision
            if entry["forced_review"] and baseline_result != "HOLD":
                baseline_result = "REVIEW"
            if baseline_result != entry.get("policy_decision"):
                report["skipped_decision_mismatch"] += 1
                continue
            candidate_result = decide(
                findings, entry["jev_signals"], candidate, **arguments
            ).decision
            if entry["forced_review"] and candidate_result != "HOLD":
                candidate_result = "REVIEW"
            report["replayed"] += 1
            degraded = entry["degraded"] is True
            if (baseline_result != "ALLOW" and candidate_result == "ALLOW") or (
                not _executes(baseline_result, baseline, degraded)
                and _executes(candidate_result, candidate, degraded)
            ):
                report["newly_executable"] += 1
            if baseline_result != candidate_result:
                label = f"{baseline_result}_to_{candidate_result}"
                report["changes"][label] += 1
                if len(report["examples"]) < 100:
                    report["examples"].append(
                        {
                            "seq": entry["seq"],
                            "before": baseline_result,
                            "after": candidate_result,
                        }
                    )
    report["new_allows"] = report["changes"]["REVIEW_to_ALLOW"] + report["changes"]["HOLD_to_ALLOW"]
    report["new_holds"] = report["changes"]["ALLOW_to_HOLD"] + report["changes"]["REVIEW_to_HOLD"]
    return report


def _evaluator_identity() -> tuple[int, frozenset[int]]:
    """The effective uid and groups whose writes evaluation cannot trust."""
    return os.geteuid(), frozenset({os.getegid(), *os.getgroups()})


def _writable(details: os.stat_result, uid: int, groups: frozenset[int]) -> bool:
    if details.st_uid == uid:
        return True  # an owner can always chmod and then write
    if details.st_mode & stat.S_IWOTH:
        return True
    return bool(details.st_mode & stat.S_IWGRP) and details.st_gid in groups


def _protected_location(
    path: Path, uid: int, groups: frozenset[int], depth: int = 0
) -> Path | None:
    """Return the real path when ``uid`` can neither rewrite nor replace it, else None.

    Every component is checked from the root: the uid must not own it, and its directory
    must not let the uid rename or unlink entries (a sticky directory protects entries
    the uid does not own). Symlinks are followed only after that check, so the uid cannot
    re-point them. A missing final component is protected when its directory is, since
    the uid could then neither have removed it nor create it. Root can change anything,
    and ACLs or capabilities beyond the mode bits are not modelled.
    """
    if uid == 0 or depth > 32 or not path.is_absolute() or ".." in path.parts:
        return None
    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, name in enumerate(parts):
        directory = os.stat(current)
        child_path = current / name
        if directory.st_uid == uid:
            return None
        try:
            child = os.lstat(child_path)
        except FileNotFoundError:
            # Absent, and the uid cannot create it unless the directory is writable.
            return None if _writable(directory, uid, groups) else Path(current, *parts[index:])
        if child.st_uid == uid:
            return None
        if _writable(directory, uid, groups) and not directory.st_mode & stat.S_ISVTX:
            return None
        if stat.S_ISLNK(child.st_mode):
            target = Path(os.readlink(child_path))
            resolved = _protected_location(
                target if target.is_absolute() else current / target, uid, groups, depth + 1
            )
            if resolved is None:
                return None
            current = resolved
        else:
            current = child_path
    # A symlink target may be an intermediate directory; only the full path names a file.
    if depth == 0 and current.exists():
        final = os.stat(current)
        if not stat.S_ISREG(final.st_mode) or _writable(final, uid, groups):
            return None
    return current


class RolloutStore:
    """Atomic local activation state for a previously verified remote candidate.

    Every signed snapshot carries the exact policy bytes and detached signature
    it was verified from, and is verified again against the bootstrap trust
    roots on every read. Signatures only authenticate a policy's contents: which
    revision is active, the canary percentage, and rollbacks are trusted only
    because the evaluating user cannot rewrite or replace the state file. While
    ``bootstrap.require_signature`` is true, :meth:`select` therefore refuses
    state that the evaluating user could change (see ``_protected_location``).
    Unsigned snapshots are accepted only when signatures are not required.
    """

    def __init__(self, path: Path, bootstrap: BootstrapConfig | None = None) -> None:
        self.path = path.expanduser()
        self.bootstrap = bootstrap if bootstrap is not None else BootstrapConfig()
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def _load(self) -> tuple[dict[str, Any], dict[str, ReflexConfig]] | None:
        """Read the state and every snapshot's verified policy."""
        if not self.path.exists():
            return None
        details = self.path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_mode & 0o022:
            raise ValueError("rollout state must be a regular file without group or world write")
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("schema") not in (1, SCHEMA):
            raise ValueError("unsupported rollout state")
        percent = data.get("percent")
        if (
            not isinstance(data.get("active"), dict)
            or type(percent) is not int
            or not 0 <= percent <= 100
        ):
            raise ValueError("invalid rollout state")
        policies = {
            field: self._snapshot_policy(data[field])
            for field in ("active", "candidate", "previous")
            if data.get(field) is not None
        }
        return data, policies

    def _read(self) -> dict[str, Any] | None:
        loaded = self._load()
        return None if loaded is None else loaded[0]

    def _unsigned_error(self) -> ValueError:
        return ValueError(
            f"rollout state {self.path} contains a policy snapshot without signature "
            "material, but bootstrap require_signature is true. Remove the rollout state "
            "file and re-stage the policy with `jrx policy rollout stage`."
        )

    def _verify_signature(self, raw: bytes, signature: bytes, trust_root: Any) -> None:
        if trust_root == "bootstrap":
            verify_policy_signature(raw, signature, self.bootstrap)
            return
        if trust_root == "policy_source":
            pem = self.bootstrap.policy_source.pinned_signature_pubkey
            if pem and signature and verify_pinned_ed25519(raw, signature, pem):
                return
            raise ValueError("rollout snapshot signature verification failed")
        raise ValueError("rollout snapshot names an unknown trust root")

    def _snapshot_policy(self, entry: Any) -> ReflexConfig:
        """Return a snapshot's policy only after verifying its integrity."""
        if not isinstance(entry, dict):
            raise ValueError("invalid rollout snapshot")
        keys = set(entry)
        if keys == {"hash", "policy"}:
            # Schema 1, or a baseline staged while signatures were not required.
            if self.bootstrap.require_signature:
                raise self._unsigned_error()
            policy = ReflexConfig.model_validate(entry["policy"])
        elif keys == {"hash", "raw", "signature", "trust_root"}:
            try:
                raw = base64.b64decode(entry["raw"], validate=True)
                signature = base64.b64decode(entry["signature"], validate=True)
            except (TypeError, ValueError, binascii.Error):
                raise ValueError("invalid rollout snapshot encoding") from None
            self._verify_signature(raw, signature, entry["trust_root"])
            # Parse the authenticated bytes exactly as load_config parses reflex.yaml.
            policy = parse_policy_bytes(raw)
        else:
            raise ValueError("invalid rollout snapshot")
        if policy_hash(policy) != entry["hash"]:
            raise ValueError("rollout snapshot hash mismatch")
        return policy

    def _snapshot(self, policy: ReflexConfig | SignedPolicy) -> dict[str, Any]:
        """Build a state entry that a later read will accept."""
        if isinstance(policy, SignedPolicy):
            self._verify_signature(policy.raw, policy.signature, policy.trust_root)
            return {
                "hash": policy_hash(parse_policy_bytes(policy.raw)),
                "raw": base64.b64encode(policy.raw).decode("ascii"),
                "signature": base64.b64encode(policy.signature).decode("ascii"),
                "trust_root": policy.trust_root,
            }
        if self.bootstrap.require_signature:
            raise ValueError(
                "bootstrap require_signature is true; only signed policies can be staged"
            )
        return {"hash": policy_hash(policy), "policy": policy.model_dump(mode="json")}

    def status(self) -> dict[str, Any]:
        data = self._read()
        if data is None:
            return {
                "active_hash": None,
                "candidate_hash": None,
                "previous_hash": None,
                "percent": 0,
            }
        return {
            "active_hash": data["active"]["hash"],
            "candidate_hash": data["candidate"]["hash"] if data.get("candidate") else None,
            "previous_hash": data["previous"]["hash"] if data.get("previous") else None,
            "percent": data["percent"],
        }

    def _require_operator_controlled(self) -> None:
        uid, groups = _evaluator_identity()
        if _protected_location(self.path, uid, groups) is None:
            raise ValueError(
                f"rollout state {self.path} can be rewritten or replaced by the evaluating "
                f"user (uid {uid}), so it cannot authorize which signed policy is active "
                "while bootstrap require_signature is true. Keep it in a directory only the "
                "operator can write (for example a root-owned /var/lib/jrx with mode 0755), "
                "set bootstrap rollout_state_path there, and re-run `jrx policy rollout "
                "stage` as that operator; or remove rollout_state_path to use the signed "
                "reflex.yaml directly."
            )

    def select(self, scope: str) -> ReflexConfig | None:
        if self.bootstrap.require_signature:
            # Checked before reading so a missing file is trusted only when the
            # evaluating user could not have removed it either.
            self._require_operator_controlled()
        loaded = self._load()
        if loaded is None:
            return None
        data, policies = loaded
        selected = "active"
        if data.get("candidate") and data["percent"] > 0:
            bucket = int.from_bytes(hashlib.sha256(scope.encode()).digest()[:8], "big") % 100
            if bucket < data["percent"]:
                selected = "candidate"
        return policies[selected]

    def _write(self, data: dict[str, Any]) -> None:
        # Evaluators often run as another user than the operator, so new state is
        # readable by default; an operator's narrower mode is kept on rewrite.
        try:
            mode = stat.S_IMODE(self.path.stat().st_mode) & 0o644
        except FileNotFoundError:
            mode = 0o644
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self.path.parent, prefix=".rollout-", delete=False
        ) as handle:
            temporary = Path(handle.name)
            os.chmod(temporary, mode)
            json.dump(data, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    def _change(self, callback):
        # Only operator commands create the directory; evaluation never does.
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(descriptor, "r+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            data = self._read()
            changed = callback(data)
            # Schema 1 entries are unsigned schema 2 entries; upgrade on write.
            changed["schema"] = SCHEMA
            self._write(changed)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def stage(
        self, active: ReflexConfig | SignedPolicy, candidate: ReflexConfig | SignedPolicy
    ) -> None:
        """Stage a candidate over ``active``.

        Pass :class:`SignedPolicy` values to keep the verified bytes and
        signature; a plain ``ReflexConfig`` is stored unsigned and is refused
        while ``bootstrap.require_signature`` is true.
        """
        active_entry = self._snapshot(active)
        candidate_entry = self._snapshot(candidate)

        def change(data):
            if data is None:
                data = {
                    "schema": SCHEMA,
                    "active": active_entry,
                    "candidate": None,
                    "previous": None,
                    "percent": 0,
                }
            elif data["active"]["hash"] != active_entry["hash"]:
                raise ValueError("baseline policy differs from active rollout policy")
            if data.get("candidate") is not None or data["percent"]:
                raise ValueError("finish or roll back the current candidate first")
            data["candidate"] = candidate_entry
            return data

        self._change(change)

    def promote(self, percent: int) -> None:
        if not 1 <= percent <= 100:
            raise ValueError("rollout percentage must be 1 through 100")

        def change(data):
            if data is None or data["candidate"] is None:
                raise ValueError("no staged candidate")
            if percent < data["percent"]:
                raise ValueError("use rollback to reduce exposure")
            if percent == 100:
                data["previous"] = data["active"]
                data["active"] = data["candidate"]
                data["candidate"] = None
                data["percent"] = 0
            else:
                data["percent"] = percent
            return data

        self._change(change)

    def rollback(self) -> None:
        def change(data):
            if data is None:
                raise ValueError("no rollout state")
            if data["candidate"] is not None:
                data["candidate"] = None
                data["percent"] = 0
            elif data["previous"] is not None:
                data["active"], data["previous"] = data["previous"], None
            else:
                raise ValueError("no candidate or prior policy to restore")
            return data

        self._change(change)
