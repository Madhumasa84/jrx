"""Offline diagnostics for a candidate policy, without activating it."""

from __future__ import annotations

from pathlib import Path
from typing import Any, get_args

import yaml
from pydantic import BaseModel, ValidationError

from .config import PolicyProfile, ReflexConfig, known_semantic_rules
from .production import production_issues
from .serialization import MAX_CONFIG_BYTES, read_config_bytes


class _DuplicateKey(ValueError):
    pass


class _PolicyLoader(yaml.SafeLoader):
    def construct_object(self, node, deep=False):
        try:
            return super().construct_object(node, deep=deep)
        except (ValueError, TypeError, LookupError, AttributeError, OverflowError):
            # Explicit YAML tags can raise built-in exceptions containing the
            # input value rather than a YAMLError. Keep diagnostics value-free.
            raise yaml.constructor.ConstructorError(
                None, None, "Invalid YAML value.", node.start_mark
            ) from None

    def construct_document(self, node):
        # PyYAML flattens merges before constructing their mappings. Validate
        # the original node graph first, while duplicate source keys remain.
        self._check_node(node, set(), {})
        return super().construct_document(node)

    def _check_node(
        self, node: yaml.Node, active: set[int], memo: dict[int, tuple[int, int]]
    ) -> tuple[int, int]:
        if id(node) in active:
            raise ValueError("Recursive YAML aliases are not supported.")
        if id(node) in memo:
            return memo[id(node)]
        active.add(id(node))
        children: list[yaml.Node] = []
        if isinstance(node, yaml.MappingNode):
            seen = set()
            merge_key = object()
            for key_node, value_node in node.value:
                if not isinstance(key_node, yaml.ScalarNode):
                    raise ValueError("YAML mapping keys must be scalar values.")
                key = (
                    merge_key
                    if key_node.tag == "tag:yaml.org,2002:merge"
                    else self.construct_object(key_node)
                )
                try:
                    hash(key)
                except TypeError:
                    raise ValueError("YAML mapping keys must be scalar values.") from None
                if key in seen:
                    raise _DuplicateKey(
                        f"Duplicate YAML key at line {key_node.start_mark.line + 1}."
                    )
                seen.add(key)
                children.extend((key_node, value_node))
        elif isinstance(node, yaml.SequenceNode):
            children = node.value
        size = height = 1
        for child in children:
            child_size, child_height = self._check_node(child, active, memo)
            size += child_size
            height = max(height, child_height + 1)
            # Count the expanded cost of every alias, even when its subtree
            # was already visited. This bounds work before merge expansion.
            if size > 10_000 or height > 64:
                raise ValueError("Policy structure exceeds the linting limit.")
        active.remove(id(node))
        memo[id(node)] = size, height
        return size, height


def _model_type(annotation: Any) -> type[BaseModel] | None:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    for argument in get_args(annotation):
        if model := _model_type(argument):
            return model
    return None


def _unknown_fields(
    value: Any, model: type[BaseModel], path: str, issues: list, *, omit_keys: bool
) -> None:
    if not isinstance(value, dict):
        return
    for name, child in value.items():
        if name not in model.model_fields:
            label = "<unknown>" if omit_keys else str(name)
            location = f"{path}.{label}" if path else label
            issues.append(
                _issue("error", "unknown_field", location, "Unknown configuration field.")
            )
            continue
        location = f"{path}.{name}" if path else str(name)
        nested = _model_type(model.model_fields[name].annotation)
        if nested is not None:
            if isinstance(child, list):
                for index, item in enumerate(child):
                    _unknown_fields(
                        item, nested, f"{location}[{index}]", issues, omit_keys=omit_keys
                    )
            else:
                _unknown_fields(child, nested, location, issues, omit_keys=omit_keys)


def _issue(severity: str, code: str, path: str, message: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "path": path, "message": message}


def lint_policy(path: Path | bytes, *, profile: PolicyProfile = "standard") -> dict[str, Any]:
    """Check the literal candidate file; never fetch policies, keys, or credentials."""
    issues: list[dict[str, str]] = []
    config = None
    try:
        raw = path if isinstance(path, bytes) else read_config_bytes(path)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError("Policy file exceeds the 1 MiB linting limit.")
        loader = _PolicyLoader(raw.decode("utf-8"))
        try:
            data = loader.get_single_data()
        finally:
            loader.dispose()
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ValueError("Policy root must be a YAML mapping.")
        production = profile == "production" or data.get("profile") == "production"
        _unknown_fields(data, ReflexConfig, "", issues, omit_keys=production)
        try:
            config = ReflexConfig.model_validate(data)
        except ValidationError as exc:
            for error in exc.errors(include_input=False, include_context=False):
                parts = error["loc"]
                if production and parts[:1] == ("rule_modes",):
                    parts = parts[:1]
                location = ".".join(str(part) for part in parts)
                issue_type = error["type"]
                if issue_type in {"unknown_rule", "host_guard_mode"}:
                    issues.append(_issue("error", issue_type, location, error["msg"]))
                elif issue_type != "extra_forbidden":
                    issues.append(
                        _issue(
                            "error",
                            "invalid_value",
                            location,
                            "Invalid configuration value or combination.",
                        )
                    )
    except _DuplicateKey as exc:
        issues.append(_issue("error", "duplicate_key", "", str(exc)))
    except (yaml.YAMLError, UnicodeError, RecursionError):
        issues.append(
            _issue("error", "invalid_yaml", "", "Policy YAML is invalid or too deeply nested.")
        )
    except OSError:
        issues.append(_issue("error", "unreadable_file", "", "Policy file cannot be read."))
    except ValueError as exc:
        issues.append(_issue("error", "invalid_structure", "", str(exc)))

    if config is not None:
        if production:
            issues.extend(production_issues(config))
            if config.profile == "standard":
                issues.append(
                    _issue(
                        "warning",
                        "production_profile_inactive",
                        "profile",
                        "Set profile: production to activate production validation at runtime.",
                    )
                )
        known_signals = known_semantic_rules(config.evaluator)
        for field in ("hold_on", "review_on"):
            rules = getattr(config, field)
            for index, rule in enumerate(rules):
                if rule not in known_signals:
                    issues.append(
                        _issue(
                            "error",
                            "unknown_signal",
                            f"{field}[{index}]",
                            "Signal is not produced by the built-in evaluator.",
                        )
                    )
            if len(rules) != len(set(rules)):
                issues.append(
                    _issue(
                        "warning",
                        "duplicate_rule",
                        field,
                        "Repeated signals add no policy coverage.",
                    )
                )
        if set(config.hold_on) & set(config.review_on):
            issues.append(
                _issue(
                    "warning",
                    "overlapping_rules",
                    "review_on",
                    "Some signals are also in hold_on; their strong hold rule takes precedence.",
                )
            )
        if config.signing.signer_type not in {"ed25519", "cosign"}:
            issues.append(
                _issue(
                    "error",
                    "unknown_signer",
                    "signing.signer_type",
                    "Supported signers are ed25519 and cosign.",
                )
            )
        if isinstance(data.get("thresholds"), dict):
            thresholds = data["thresholds"]
            if (
                thresholds.get("hold") is not None
                and "strong" in thresholds
                and thresholds["strong"] != thresholds["hold"]
            ):
                issues.append(
                    _issue(
                        "warning",
                        "threshold_alias_conflict",
                        "thresholds",
                        "hold overrides the conflicting legacy strong threshold.",
                    )
                )
        tools = [(tool.server, tool.name) for tool in config.mcp.tools]
        if len(tools) != len(set(tools)):
            issues.append(
                _issue(
                    "error",
                    "duplicate_mcp_tool",
                    "mcp.tools",
                    "Each server/tool pair must have one authorization rule.",
                )
            )
        warnings = [
            (
                config.mode == "advisory",
                "advisory_mode",
                "mode",
                "Advisory mode reports policy decisions without blocking execution.",
            ),
            (
                not config.privacy.redact_secrets,
                "redaction_disabled",
                "privacy.redact_secrets",
                "Secret redaction is disabled.",
            ),
            (
                not config.audit.enabled and not config.privacy.store_requests,
                "audit_disabled",
                "audit.enabled",
                "Decision persistence is disabled.",
            ),
            (
                config.policy.allow_hold_override,
                "hold_override_enabled",
                "policy.allow_hold_override",
                "HOLD decisions can be overridden where the execution flow permits it.",
            ),
            (
                config.stability.boundary_margin > 0
                and config.stability_policy.mode != "conservative",
                "inactive_boundary_margin",
                "stability.boundary_margin",
                "Boundary margin only takes effect in conservative mode.",
            ),
            (
                config.session.enabled
                and config.session.reserved_cost_per_evaluation_usd
                > config.session.max_semantic_spend_usd,
                "unusable_semantic_budget",
                "session.max_semantic_spend_usd",
                "The session cannot reserve even one semantic evaluation.",
            ),
        ]
        issues.extend(
            _issue("warning", code, location, message)
            for condition, code, location, message in warnings
            if condition
        )

    errors = sum(issue["severity"] == "error" for issue in issues)
    warnings_count = sum(issue["severity"] == "warning" for issue in issues)
    return {"valid": errors == 0, "errors": errors, "warnings": warnings_count, "issues": issues}
