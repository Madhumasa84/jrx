"""Tests for policy merge logic enforcing tighten-only invariant."""

from __future__ import annotations

from jev_reflex.config import ReflexConfig, ThresholdConfig
from jev_reflex.policy_source import PolicyMerger


def test_merge_local_can_add_hold_on_entries() -> None:
    """Test that local policy can add new hold_on entries."""
    central = ReflexConfig(hold_on=["destructive", "secret_exposure"])
    local = ReflexConfig(hold_on=["destructive", "secret_exposure", "new_rule"])

    merged = PolicyMerger.merge_policies(central, local)

    assert "new_rule" in merged.hold_on
    assert "destructive" in merged.hold_on
    assert "secret_exposure" in merged.hold_on


def test_merge_local_cannot_remove_hold_on_entries() -> None:
    """Test that local policy cannot remove central hold_on entries."""
    central = ReflexConfig(hold_on=["destructive", "secret_exposure", "irreversible"])
    local = ReflexConfig(
        hold_on=["destructive"]
    )  # Attempts to remove secret_exposure and irreversible

    merged = PolicyMerger.merge_policies(central, local)

    # Central entries should be retained
    assert "destructive" in merged.hold_on
    assert "secret_exposure" in merged.hold_on
    assert "irreversible" in merged.hold_on


def test_merge_local_can_add_review_on_entries() -> None:
    """Test that local policy can add new review_on entries."""
    central = ReflexConfig(review_on=["security_sensitive"])
    local = ReflexConfig(review_on=["security_sensitive", "new_rule"])

    merged = PolicyMerger.merge_policies(central, local)

    assert "new_rule" in merged.review_on
    assert "security_sensitive" in merged.review_on


def test_merge_local_cannot_remove_review_on_entries() -> None:
    """Test that local policy cannot remove central review_on entries."""
    central = ReflexConfig(review_on=["security_sensitive", "persistence_sensitive"])
    local = ReflexConfig(
        review_on=["security_sensitive"]
    )  # Attempts to remove persistence_sensitive

    merged = PolicyMerger.merge_policies(central, local)

    # Central entries should be retained
    assert "security_sensitive" in merged.review_on
    assert "persistence_sensitive" in merged.review_on


def test_merge_local_can_lower_strong_threshold() -> None:
    """Test that local policy can lower strong threshold (make it stricter)."""
    central = ReflexConfig(thresholds=ThresholdConfig(strong=0.9, review=0.7))
    local = ReflexConfig(thresholds=ThresholdConfig(strong=0.8, review=0.7))

    merged = PolicyMerger.merge_policies(central, local)

    # Lower threshold (stricter) should be used
    assert merged.thresholds.strong == 0.8


def test_merge_local_cannot_raise_strong_threshold() -> None:
    """Test that local policy cannot raise strong threshold (make it looser)."""
    central = ReflexConfig(thresholds=ThresholdConfig(strong=0.8, review=0.7))
    local = ReflexConfig(thresholds=ThresholdConfig(strong=0.9, review=0.7))

    merged = PolicyMerger.merge_policies(central, local)

    # Central threshold should be retained
    assert merged.thresholds.strong == 0.8


def test_merge_local_can_lower_review_threshold() -> None:
    """Test that local policy can lower review threshold (make it stricter)."""
    central = ReflexConfig(thresholds=ThresholdConfig(strong=0.9, review=0.7))
    local = ReflexConfig(thresholds=ThresholdConfig(strong=0.9, review=0.6))

    merged = PolicyMerger.merge_policies(central, local)

    # Lower threshold (stricter) should be used
    assert merged.thresholds.review == 0.6


def test_merge_local_cannot_raise_review_threshold() -> None:
    """Test that local policy cannot raise review threshold (make it looser)."""
    central = ReflexConfig(thresholds=ThresholdConfig(strong=0.9, review=0.6))
    local = ReflexConfig(thresholds=ThresholdConfig(strong=0.9, review=0.7))

    merged = PolicyMerger.merge_policies(central, local)

    # Central threshold should be retained
    assert merged.thresholds.review == 0.6


def test_merge_local_can_tighten_mode() -> None:
    """Test that local policy can tighten mode (advisory -> review -> enforce)."""
    central = ReflexConfig(mode="advisory")
    local = ReflexConfig(mode="enforce")

    merged = PolicyMerger.merge_policies(central, local)

    # Stricter mode should be used
    assert merged.mode == "enforce"


def test_merge_local_cannot_loosen_mode() -> None:
    """Test that local policy cannot loosen mode."""
    central = ReflexConfig(mode="enforce")
    local = ReflexConfig(mode="advisory")

    merged = PolicyMerger.merge_policies(central, local)

    # Central mode should be retained
    assert merged.mode == "enforce"


def test_merge_complex_scenario() -> None:
    """Test a complex merge scenario with multiple fields."""
    central = ReflexConfig(
        mode="review",
        hold_on=["destructive", "secret_exposure"],
        review_on=["security_sensitive"],
        thresholds=ThresholdConfig(strong=0.9, review=0.7),
    )
    local = ReflexConfig(
        mode="enforce",  # Tighten
        hold_on=["destructive"],  # Attempts to remove secret_exposure
        review_on=["security_sensitive", "new_rule"],  # Add new rule
        thresholds=ThresholdConfig(
            strong=0.95, review=0.6
        ),  # Attempt to loosen strong, tighten review
    )

    merged = PolicyMerger.merge_policies(central, local)

    # Mode should be enforced (stricter)
    assert merged.mode == "enforce"

    # Central hold_on entries should be retained
    assert "destructive" in merged.hold_on
    assert "secret_exposure" in merged.hold_on

    # Both review_on entries should be present
    assert "security_sensitive" in merged.review_on
    assert "new_rule" in merged.review_on

    # Central strong threshold should be retained (local tried to loosen)
    assert merged.thresholds.strong == 0.9

    # Local review threshold should be used (local tightened it)
    assert merged.thresholds.review == 0.6


def test_merge_local_none_returns_central() -> None:
    """Test that when local is None, central is returned unchanged."""
    central = ReflexConfig(hold_on=["destructive"])
    local = None

    merged = PolicyMerger.merge_policies(central, local)

    assert merged.hold_on == central.hold_on
    assert merged.mode == central.mode
