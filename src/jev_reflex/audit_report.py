"""Aggregate a captured, verified audit log without exposing action payloads."""

from __future__ import annotations

import fcntl
import hashlib
import io
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .audit import GENESIS_HASH, AuditLog, record_event_type
from .config import ReflexConfig
from .redaction import redact_text

MAX_REPORT_BYTES = 128 * 1024 * 1024


def parse_report_time(value: str) -> datetime:
    """Interpret dates and naive ISO timestamps as UTC, like audit overrides."""
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            result = result.replace(tzinfo=UTC)
        return result.astimezone(UTC)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("Report dates must use YYYY-MM-DD or ISO 8601.") from None


def build_audit_report(
    path: Path,
    config: ReflexConfig,
    *,
    public_key: Path | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, Any]:
    """Verify every record before applying the inclusive UTC time range."""
    start = parse_report_time(since) if since is not None else None
    end = parse_report_time(until) if until is not None else None
    if start is not None and end is not None and start > end:
        raise ValueError("Report start must not be after its end.")
    public_key = AuditLog.verification_key(config, public_key)
    # Match the writer's locking protocol so a concurrently appended record is
    # either fully present or absent from this immutable report snapshot.
    with path.expanduser().open("rb") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
        try:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Audit report input exceeds 128 MiB; use a retained log segment.")
    snapshot = raw.decode("utf-8")
    signatures_verified = AuditLog.verify_snapshot(config, snapshot, public_key_path=public_key)

    decisions = {"ALLOW": 0, "REVIEW": 0, "HOLD": 0}
    original_decisions = {"ALLOW": 0, "REVIEW": 0, "HOLD": 0}
    checks: Counter[str] = Counter()
    policies: Counter[str] = Counter()
    total = selected = degraded = unknown_degraded = overrides = other_events = 0
    first = last = None
    tip = GENESIS_HASH
    # Use the verifier's newline framing. Unicode line separators are valid
    # inside JSON strings and do not delimit audit records. Verification already
    # parsed every line strictly (unique members, canonical bytes), so decode
    # without serializing each record again.
    for line in io.StringIO(snapshot, newline="\n"):
        entry = json.loads(line)
        total += 1
        tip = entry["entry_hash"]
        timestamp = entry.get("timestamp_utc") or entry.get("timestamp")
        if not isinstance(timestamp, str):
            raise ValueError("Audit record has no valid timestamp.")
        moment = parse_report_time(timestamp)
        if (start is not None and moment < start) or (end is not None and moment > end):
            continue
        selected += 1
        first = moment if first is None else min(first, moment)
        last = moment if last is None else max(last, moment)
        version = entry.get("policy_version_hash", "")
        if (
            not isinstance(version, str)
            or len(version) != 64
            or any(c not in "0123456789abcdef" for c in version)
        ):
            raise ValueError("Audit record has an invalid policy hash.")
        policies[version] += 1
        event = record_event_type(entry)
        if event == "human_override":
            original = entry.get("original_decision")
            if not isinstance(original, str) or original not in original_decisions:
                raise ValueError("Audit override has an invalid original decision.")
            overrides += 1
            original_decisions[original] += 1
        elif event == "policy_decision":
            decision = entry.get("policy_decision")
            if not isinstance(decision, str) or decision not in decisions:
                raise ValueError("Audit record has an invalid policy decision.")
            decisions[decision] += 1
            state = entry.get("degraded")
            if state is True:
                degraded += 1
            elif state is None:
                unknown_degraded += 1
            elif state is not False:
                raise ValueError("Audit record has an invalid degraded state.")
            findings = entry.get("hard_rule_findings", [])
            if not isinstance(findings, list) or any(
                not isinstance(item, dict) for item in findings
            ):
                raise ValueError("Audit record has invalid local findings.")
            for finding in findings:
                if finding.get("triggered") is True:
                    name = finding.get("check")
                    if not isinstance(name, str):
                        raise ValueError("Audit record has an invalid check name.")
                    safe_name = redact_text(name)
                    # A plugin can supply check names. Keep payload text and
                    # terminal control sequences out of the aggregate labels.
                    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", safe_name):
                        safe_name = "other"
                    checks[safe_name] += 1
        else:
            other_events += 1

    return {
        "verification": {
            "chain_verified": True,
            "signatures_verified": signatures_verified,
            "snapshot_sha256": hashlib.sha256(raw).hexdigest(),
            "chain_tip": tip,
            "records_verified": total,
        },
        "range": {
            "since": start.isoformat() if start else None,
            "until": end.isoformat() if end else None,
            "first_event": first.isoformat() if first else None,
            "last_event": last.isoformat() if last else None,
        },
        "records_selected": selected,
        "decisions": decisions,
        "degraded_evaluations": degraded,
        "legacy_unknown_degraded": unknown_degraded,
        "human_overrides": overrides,
        "override_original_decisions": original_decisions,
        "other_events": other_events,
        "triggered_checks": dict(sorted(checks.items())),
        "policy_versions": dict(sorted(policies.items())),
    }
