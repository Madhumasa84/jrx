from pathlib import Path

import pytest

from jev_reflex.config import ReflexConfig, load_config


def test_defaults_are_advisory() -> None:
    config = ReflexConfig()
    assert config.mode == "advisory"
    assert config.thresholds.strong == 0.90
    assert "destructive" in config.hold_on
    assert config.jev.samples == 1
    assert config.stability_policy.mode == "strict"


def test_yaml_configuration_and_mode_override(tmp_path: Path) -> None:
    path = tmp_path / "reflex.yaml"
    path.write_text(
        "mode: enforce\nthresholds:\n  strong: 0.95\n  review: 0.65\ncontext:\n  max_diff_chars: 123\n",
        encoding="utf-8",
    )
    config = load_config(path, mode_override="review")
    assert config.mode == "review"
    assert config.thresholds.strong == 0.95
    assert config.context.max_diff_chars == 123


def test_invalid_thresholds_fail() -> None:
    with pytest.raises(ValueError):
        ReflexConfig.model_validate({"thresholds": {"strong": 0.6, "review": 0.7}})


def test_missing_config_uses_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_config().mode == "advisory"


def test_missing_explicit_config_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Configuration file not found"):
        load_config(tmp_path / "missing.yaml")


def test_new_threshold_and_stability_configuration_is_loaded(tmp_path: Path) -> None:
    path = tmp_path / "reflex.yaml"
    path.write_text(
        "thresholds:\n  review: 0.65\n  hold: 0.92\n"
        "jev:\n  samples: 3\n  aggregation: max\n"
        "stability:\n  boundary_margin: 0.03\n"
        "stability_policy:\n  mode: conservative\n",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.thresholds.review == 0.65
    assert config.thresholds.strong == 0.92
    assert config.thresholds.hold == 0.92
    assert config.jev.samples == 3
    assert config.jev.aggregation == "max"
    assert config.stability.boundary_margin == 0.03
    assert config.stability_policy.mode == "conservative"


def test_invalid_yaml_is_reported_without_parser_details(tmp_path: Path) -> None:
    path = tmp_path / "reflex.yaml"
    path.write_text("mode: [not valid", encoding="utf-8")
    with pytest.raises(ValueError, match="configuration YAML is invalid"):
        load_config(path)
