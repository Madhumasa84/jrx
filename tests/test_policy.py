from jev_reflex.config import ReflexConfig, StabilityConfig, StabilityPolicyConfig, ThresholdConfig
from jev_reflex.models import DeterministicFinding
from jev_reflex.policy import Policy, decide, execution_allowed


def test_destructive_signal_holds() -> None:
    result = Policy().decide(
        {"destructive": 0.98, "irreversible": 0.76},
        risk_choice="high",
        config=ReflexConfig(),
    )
    assert result.decision == "HOLD"
    assert "destructive >= 0.90" in result.triggered_rules


def test_safe_signal_allows() -> None:
    result = Policy().decide(
        {"destructive": 0.02, "security_sensitive": 0.04},
        risk_choice="low",
        config=ReflexConfig(),
    )
    assert result.decision == "ALLOW"
    assert result.triggered_rules == ()


def test_uncertain_security_change_requires_review() -> None:
    result = Policy().decide(
        {"security_sensitive": 0.78},
        risk_choice="medium",
        config=ReflexConfig(),
    )
    assert result.decision == "REVIEW"
    assert any("security_sensitive" in rule for rule in result.triggered_rules)


def test_low_jev_confidence_requires_review() -> None:
    result = Policy().decide(
        {"destructive": 0.02},
        risk_choice="low",
        risk_confidence=0.45,
        config=ReflexConfig(),
    )
    assert result.decision == "REVIEW"
    assert "risk_confidence < 0.70" in result.triggered_rules


def test_custom_thresholds_are_applied() -> None:
    config = ReflexConfig(
        thresholds=ThresholdConfig(strong=0.97, review=0.80),
        hold_on=["destructive"],
    )
    review = Policy().decide(
        {"destructive": 0.92},
        risk_choice="low",
        config=config,
    )
    hold = Policy().decide(
        {"destructive": 0.98},
        risk_choice="low",
        config=config,
    )
    assert review.decision == "REVIEW"
    assert hold.decision == "HOLD"


def test_execution_modes_are_distinct() -> None:
    assert execution_allowed("HOLD", mode="advisory")
    assert not execution_allowed("REVIEW", mode="review")
    assert not execution_allowed("HOLD", mode="enforce")
    assert execution_allowed("REVIEW", mode="enforce")
    assert not execution_allowed("ALLOW", mode="enforce", degraded=True)


def test_pure_policy_decision_is_repeatable() -> None:
    signals = {"security_sensitive": 0.78, "human_review": 0.12}
    config = ReflexConfig()
    first = decide([], signals, config, risk_choice="medium")
    second = decide([], signals, config, risk_choice="medium")
    assert first == second
    assert first.decision == "REVIEW"


def test_hard_deterministic_finding_overrides_low_jev_risk() -> None:
    finding = DeterministicFinding(
        check="repo_boundary",
        triggered=True,
        severity="high",
        reason_code="TARGET_OUTSIDE_REPO",
        blocking=True,
    )
    result = decide(
        [finding],
        {"destructive": 0.01, "secret_exposure": 0.01},
        ReflexConfig(),
    )
    assert result.decision == "HOLD"
    assert "repo_boundary:TARGET_OUTSIDE_REPO" in result.triggered_rules


def test_hold_threshold_alias_is_supported() -> None:
    config = ReflexConfig(thresholds=ThresholdConfig(review=0.70, hold=0.95))
    assert config.thresholds.strong == 0.95
    assert (
        Policy().decide({"destructive": 0.94}, risk_choice="low", config=config).decision
        == "REVIEW"
    )
    assert (
        Policy().decide({"destructive": 0.96}, risk_choice="low", config=config).decision == "HOLD"
    )


def test_conservative_boundary_does_not_hold_semantic_signal_alone() -> None:
    config = ReflexConfig(
        hold_on=["destructive"],
        stability=StabilityConfig(boundary_margin=0.03),
        stability_policy=StabilityPolicyConfig(mode="conservative"),
    )
    result = decide([], {"destructive": 0.905}, config)
    assert result.decision == "REVIEW"
    assert any("BOUNDARY_UNCERTAIN" in rule for rule in result.triggered_rules)


def test_semantic_wrong_repo_alias_is_a_default_hold() -> None:
    result = decide([], {"wrong_repo_semantic": 0.95}, ReflexConfig())
    assert result.decision == "HOLD"
