from pathlib import Path

import pytest

from jev_reflex.audit import AuditLog
from jev_reflex.config import ReflexConfig
from jev_reflex.policy import decide
from jev_reflex.policy_rollout import simulate


def _record(config: ReflexConfig) -> None:
    signals = {"destructive": 0.91}
    AuditLog(config).write_entry(
        "recorded action",
        [],
        signals,
        decide([], signals, config),
        risk_choice="low",
        degraded=False,
        forced_review=False,
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"stability_policy": {"mode": "conservative"}, "stability": {"boundary_margin": 0.05}},
        {"session": {"enabled": True}},
        {"policy": {"allow_hold_override": True}},
        {"mcp": {"use_jev": False}},
    ],
)
def test_policy_version_tracks_effective_configuration(updates: dict) -> None:
    baseline = ReflexConfig()
    candidate = ReflexConfig.model_validate(baseline.model_dump() | updates)
    audit = AuditLog(baseline)
    assert audit._compute_policy_version_hash(baseline) != audit._compute_policy_version_hash(
        candidate
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"session": {"enabled": True}},
        {"policy": {"allow_hold_override": True}},
        {"jev": {"samples": 3}},
    ],
)
def test_replay_rejects_changes_not_reconstructible_from_audit(
    tmp_path: Path, updates: dict
) -> None:
    baseline = ReflexConfig(audit={"enabled": True, "path": str(tmp_path / "audit.jsonl")})
    _record(baseline)
    candidate = ReflexConfig.model_validate(baseline.model_dump() | updates)
    with pytest.raises(ValueError, match="cannot replay"):
        simulate(Path(baseline.audit.path), baseline, candidate)


def test_replay_does_not_accept_a_different_stability_baseline(tmp_path: Path) -> None:
    original = ReflexConfig(audit={"enabled": True, "path": str(tmp_path / "audit.jsonl")})
    _record(original)
    baseline = original.model_copy(
        update={"stability": original.stability.model_copy(update={"boundary_margin": 0.01})}
    )
    report = simulate(Path(original.audit.path), baseline, baseline)
    assert report["replayed"] == 0
    assert report["skipped_policy_mismatch"] == 1


def test_replay_uses_the_verified_snapshot(tmp_path: Path, monkeypatch) -> None:
    baseline = ReflexConfig(audit={"enabled": True, "path": str(tmp_path / "audit.jsonl")})
    _record(baseline)
    path = Path(baseline.audit.path)
    verify = AuditLog.verify

    def replace_after_verification(self, *args, **kwargs):
        result = verify(self, *args, **kwargs)
        path.write_text("")
        return result

    monkeypatch.setattr(AuditLog, "verify", replace_after_verification)
    report = simulate(path, baseline, baseline)
    assert report["replayed"] == 1
