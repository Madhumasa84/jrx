"""Offline policy replay and staged activation of signed remote policies."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .config import ReflexConfig
from .models import DeterministicFinding
from .policy import decide


def policy_hash(config: ReflexConfig) -> str:
    canonical = json.dumps(config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def simulate(audit_path: Path, baseline: ReflexConfig, candidate: ReflexConfig) -> dict[str, Any]:
    """Replay stored deterministic inputs without contacting a semantic model."""
    valid, reason = AuditLog(
        baseline.model_copy(
            update={"audit": baseline.audit.model_copy(update={"path": str(audit_path)})}
        )
    ).verify()
    if not valid:
        raise ValueError(f"audit chain verification failed: {reason}")
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
    }
    if not audit_path.exists():
        raise ValueError("audit log does not exist")
    baseline_version = AuditLog(baseline)._compute_policy_version_hash(baseline)
    with audit_path.open(encoding="utf-8") as handle:
        for line in handle:
            entry = json.loads(line)
            if (
                entry.get("event_type", "policy_decision") != "policy_decision"
                or entry.get("action_summary") == "policy_reload"
            ):
                continue
            report["total"] += 1
            if not all(key in entry for key in ("risk_choice", "degraded", "forced_review")):
                report["skipped_legacy"] += 1
                continue
            if entry.get("policy_version_hash") != baseline_version:
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
            if baseline_result != candidate_result:
                label = f"{baseline_result}_to_{candidate_result}"
                report["changes"][label] += 1
                if len(report["examples"]) < 100:
                    report["examples"].append(
                        {
                            "seq": entry["seq"],
                            "before": baseline_result,
                            "after": candidate_result,
                            "action": entry["action_summary"],
                        }
                    )
    report["new_allows"] = report["changes"]["REVIEW_to_ALLOW"] + report["changes"]["HOLD_to_ALLOW"]
    report["new_holds"] = report["changes"]["ALLOW_to_HOLD"] + report["changes"]["REVIEW_to_HOLD"]
    return report


class RolloutStore:
    """Atomic local activation state for a previously verified remote candidate."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def _read(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        details = self.path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_mode & 0o077
        ):
            raise ValueError("rollout state must be an owner-only regular file")
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if data.get("schema") != 1:
            raise ValueError("unsupported rollout state")
        for field in ("active", "candidate", "previous"):
            if data.get(field) is not None:
                policy = ReflexConfig.model_validate(data[field]["policy"])
                if policy_hash(policy) != data[field]["hash"]:
                    raise ValueError("rollout snapshot hash mismatch")
        return data

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
            "candidate_hash": data["candidate"]["hash"] if data["candidate"] else None,
            "previous_hash": data["previous"]["hash"] if data["previous"] else None,
            "percent": data["percent"],
        }

    def select(self, scope: str) -> ReflexConfig | None:
        data = self._read()
        if data is None:
            return None
        selected = data["active"]
        if data["candidate"] and data["percent"] > 0:
            bucket = int.from_bytes(hashlib.sha256(scope.encode()).digest()[:8], "big") % 100
            if bucket < data["percent"]:
                selected = data["candidate"]
        return ReflexConfig.model_validate(selected["policy"])

    def _write(self, data: dict[str, Any]) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self.path.parent, prefix=".rollout-", delete=False
        ) as handle:
            temporary = Path(handle.name)
            os.chmod(temporary, 0o600)
            json.dump(data, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    def _change(self, callback):
        descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(descriptor, "r+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            data = self._read()
            changed = callback(data)
            self._write(changed)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def stage(self, active: ReflexConfig, candidate: ReflexConfig) -> None:
        def change(data):
            if data is None:
                data = {
                    "schema": 1,
                    "active": {
                        "hash": policy_hash(active),
                        "policy": active.model_dump(mode="json"),
                    },
                    "candidate": None,
                    "previous": None,
                    "percent": 0,
                }
            elif data["active"]["hash"] != policy_hash(active):
                raise ValueError("baseline policy differs from active rollout policy")
            if data["candidate"] is not None or data["percent"]:
                raise ValueError("finish or roll back the current candidate first")
            data["candidate"] = {
                "hash": policy_hash(candidate),
                "policy": candidate.model_dump(mode="json"),
            }
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
