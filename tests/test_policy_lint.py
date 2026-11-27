"""Offline policy authoring diagnostics and CLI exit semantics."""

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from jev_reflex.cli import app
from jev_reflex.policy_lint import lint_policy
from jev_reflex.serialization import safe_yaml_load


def lint(tmp_path, text):
    path = tmp_path / "candidate.yaml"
    path.write_text(text)
    return lint_policy(path)


def codes(report):
    return {issue["code"] for issue in report["issues"]}


def test_valid_policy_has_no_diagnostics(tmp_path):
    assert lint(tmp_path, "mode: enforce\naudit: {enabled: true}\n") == {
        "valid": True,
        "errors": 0,
        "warnings": 0,
        "issues": [],
    }
    # The legacy privacy switch also enables decision persistence.
    assert not lint(tmp_path, "mode: enforce\nprivacy: {store_requests: true}\n")["issues"]


def test_repository_example_is_valid():
    assert lint_policy(Path(__file__).parents[1] / "reflex.example.yaml")["valid"]


@pytest.mark.parametrize(
    "text, code",
    [
        ("mode: enforce\nmode: advisory\n", "duplicate_key"),
        ("thresholds: {review: 0.7, review: 0.8}", "duplicate_key"),
        ("mode: [broken", "invalid_yaml"),
        ("- enforce", "invalid_structure"),
        ("? [a, b]\n: bad", "invalid_structure"),
        ("mcp: &cycle {tools: [*cycle]}", "invalid_structure"),
        ("thresholds: {review: 0.99, hold: 0.5}", "invalid_value"),
        ("mode: password=private-fixture", "invalid_value"),
        ("signing: {signer_type: unsupported}", "unknown_signer"),
        ("hold_on: [destructve]", "unknown_signal"),
    ],
)
def test_invalid_candidates_are_rejected_without_input_values(tmp_path, text, code):
    report = lint(tmp_path, text)
    assert not report["valid"]
    assert code in codes(report)
    assert "private-fixture" not in json.dumps(report)


def test_unknown_fields_include_nested_models_but_not_json_schema(tmp_path):
    report = lint(
        tmp_path,
        """
mod: enforce
privacy: {redact_secret: true}
access:
  issuer: https://example.com
  audience: jrx
  jwks_uri: https://example.com/keys
  environment: test
  rules:
    - role: admin
      actions: [admin]
      repositories: ['*']
      environments: [test]
      typo: true
mcp:
  tools:
    - server: data
      name: read
      effect: read
      argument_schema:
        type: object
        properties: {arbitrary_name: {type: string}}
""",
    )
    paths = {issue["path"] for issue in report["issues"] if issue["code"] == "unknown_field"}
    assert paths == {"mod", "privacy.redact_secret", "access.rules[0].typo"}


def test_yaml_merge_keys_are_rejected_like_the_runtime_loader(tmp_path):
    # The runtime loader rejects merge keys, so a lint-clean policy using one
    # would stop enforcement once signed and deployed.
    report = lint(
        tmp_path,
        """
mode: enforce
audit: {enabled: true}
thresholds:
  <<: &defaults {review: 0.7, strong: 0.9}
  strong: 0.95
""",
    )
    assert not report["valid"]
    assert codes(report) == {"invalid_yaml"}


def test_warnings_and_duplicate_authorization_rules(tmp_path):
    report = lint(
        tmp_path,
        """
mode: advisory
policy: {allow_hold_override: true}
privacy: {redact_secrets: false}
thresholds: {hold: 0.9, strong: 0.95}
hold_on: [destructive, destructive]
review_on: [destructive]
stability: {boundary_margin: 0.03}
session: {enabled: true, max_semantic_spend_usd: 0.001}
mcp:
  tools:
    - {server: data, name: read, effect: read}
    - {server: data, name: read, effect: write}
""",
    )
    assert codes(report) >= {
        "advisory_mode",
        "hold_override_enabled",
        "redaction_disabled",
        "audit_disabled",
        "threshold_alias_conflict",
        "duplicate_rule",
        "overlapping_rules",
        "inactive_boundary_margin",
        "unusable_semantic_budget",
        "duplicate_mcp_tool",
    }
    assert report["errors"] == 1


def test_missing_oversized_and_invalid_utf8_files(tmp_path, monkeypatch):
    path = tmp_path / "policy.yaml"
    assert codes(lint_policy(path)) == {"unreadable_file"}
    path.write_bytes(b"x" * 1_048_577)
    assert codes(lint_policy(path)) == {"invalid_structure"}
    path.write_bytes(b"\xff")
    assert codes(lint_policy(path)) == {"invalid_yaml"}

    def forbidden(*args, **kwargs):
        pytest.fail("Policy lint must not execute YAML object constructors")

    monkeypatch.setattr("os.system", forbidden)
    path.write_text("!!python/object/apply:os.system ['fixture-command']")
    assert codes(lint_policy(path)) == {"invalid_yaml"}


def test_cli_is_offline_and_strict_warnings_fail(tmp_path, monkeypatch):
    import jev_reflex.config as config_module

    def forbidden(*args, **kwargs):
        pytest.fail("Lint must not load or activate runtime policies")

    # Patch the source module: commands import load_config lazily from it.
    monkeypatch.setattr(config_module, "load_config", forbidden)
    path = tmp_path / "policy.yaml"
    path.write_text("mode: advisory\n")
    result = CliRunner().invoke(app, ["policy", "lint", "-c", str(path), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["warnings"] == 2
    strict = CliRunner().invoke(app, ["policy", "lint", "-c", str(path), "--strict"])
    assert strict.exit_code == 1
    path.write_text("mod: enforce\n")
    assert CliRunner().invoke(app, ["policy", "lint", "-c", str(path)]).exit_code == 1


def test_custom_evaluator_signals_are_flagged_as_builtin_incompatible(tmp_path):
    report = lint(tmp_path, "hold_on: [custom_signal]")
    assert "unknown_signal" in codes(report)


@pytest.mark.parametrize(
    "text",
    [
        "<<: {mode: enforce, mode: advisory}\n",
        "<<: {mode: enforce}\n<<: {mode: advisory}\n",
        "thresholds: {<<: {review: 0.7, review: 0.8}}\n",
    ],
)
def test_duplicate_keys_are_detected_before_yaml_merge_flattening(tmp_path, text):
    report = lint(tmp_path, text)
    assert not report["valid"]
    assert "duplicate_key" in codes(report)


def test_aliases_and_explicit_merge_overrides_are_rejected_like_the_runtime_loader(tmp_path):
    report = lint(
        tmp_path,
        """
<<: {<<: {mode: advisory}, mode: enforce}
audit: {enabled: true}
mcp:
  tools:
    - &first {server: data, name: first, effect: read}
    - <<: *first
      name: second
""",
    )
    assert not report["valid"]
    aliases_only = lint(
        tmp_path,
        "mode: enforce\nhold_on: &h [destructive]\nreview_on: *h\naudit: {enabled: true}\n",
    )
    assert not aliases_only["valid"]
    assert codes(aliases_only) == {"invalid_structure"}


def test_merge_alias_expansion_is_bounded_before_construction(tmp_path):
    fragment = "&base {mode: enforce}"
    name = "base"
    for index in range(12):
        fragment = f"&level{index} {{<<: [{fragment}, *{name}]}}"
        name = f"level{index}"
    report = lint(tmp_path, "<<: " + fragment)
    assert not report["valid"]
    assert "invalid_structure" in codes(report)


@pytest.mark.parametrize(
    "tag,value",
    [(tag, "password=private-fixture") for tag in ("bool", "timestamp", "int", "float")]
    + [("int", ""), ("float", "")],
)
@pytest.mark.parametrize("as_key", [False, True])
def test_malformed_typed_scalars_are_rejected_without_exposing_values(tmp_path, tag, value, as_key):
    scalar = f"!!{tag} {value}"
    text = f"{scalar}: enforce\n" if as_key else f"mode: {scalar}\n"
    report = lint(tmp_path, text)
    assert not report["valid"]
    assert codes(report) == {"invalid_yaml"}
    assert "private-fixture" not in json.dumps(report)

    path = tmp_path / "candidate.yaml"
    result = CliRunner().invoke(app, ["policy", "lint", "-c", str(path), "--json"])
    assert result.exit_code == 1, result.output
    assert json.loads(result.stdout) == report
    assert "private-fixture" not in result.output


@pytest.mark.parametrize(
    "tag, code",
    [
        ("seq", "invalid_structure"),
        ("map", "invalid_structure"),
        # Non-core tags are rejected outright, as at runtime.
        ("set", "invalid_yaml"),
        ("pairs", "invalid_yaml"),
        ("omap", "invalid_yaml"),
    ],
)
def test_collection_tags_cannot_turn_scalar_keys_into_unhashable_values(tmp_path, tag, code):
    report = lint(tmp_path, f"!!{tag} password=private-fixture: enforce\n")
    assert not report["valid"]
    assert codes(report) == {code}
    assert "private-fixture" not in json.dumps(report)


@pytest.mark.parametrize(
    "value",
    [
        "!!omap [{git_risk: enforce}]",
        "!!pairs [{git_risk: enforce}]",
        "!!omap []",
        "!!pairs []",
        "!!set {git_risk: null}",
    ],
)
def test_well_formed_non_core_collections_are_rejected_by_tag(tmp_path, value):
    # Well-formed values pass the constructors' shape checks, so only the tag
    # filter itself rejects them; the key-position cases above would also fail
    # on shape alone.
    report = lint(tmp_path, f"mode: enforce\naudit: {{enabled: true}}\nrule_modes: {value}\n")
    assert not report["valid"]
    assert codes(report) == {"invalid_yaml"}


@pytest.mark.parametrize("value", [".inf", "-.Inf", ".NaN", "!!float .inf", "1.0e+400"])
def test_non_finite_floats_are_rejected_like_the_runtime_loader(tmp_path, value):
    # JSON has no infinity or NaN: such a value would reach the policy hash as null.
    text = f"""
mode: enforce
audit: {{enabled: true}}
mcp:
  tools:
    - server: data
      name: query
      effect: read
      argument_schema: {{type: object, properties: {{limit: {{const: {value}}}}}}}
"""
    report = lint(tmp_path, text)
    assert not report["valid"]
    assert codes(report) == {"invalid_yaml"}
    with pytest.raises(yaml.YAMLError):
        safe_yaml_load(text)
    finite = lint(tmp_path, text.replace(value, "1.5"))
    assert finite["valid"], finite
