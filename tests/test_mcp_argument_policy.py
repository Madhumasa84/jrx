from __future__ import annotations

from io import BytesIO

import pytest
from pydantic import ValidationError

from jev_reflex.config import MCPToolRule, ReflexConfig
from jev_reflex.mcp_gateway import MCPGateway


@pytest.mark.parametrize(
    "settings",
    [
        {
            "server": "data",
            "name": "db.read",
            "effect": "read",
            "argument_schema": {"type": "made-up"},
        },
        {
            "server": "data",
            "name": "db.read",
            "effect": "read",
            "argument_schema": {"$ref": "https://example.invalid/schema.json"},
        },
        {
            "server": "data",
            "name": "db.read",
            "effect": "read",
            "argument_constraints": {"database": ["development"]},
        },
        {
            "server": "data",
            "name": "db.read",
            "effect": "read",
            "argument_constraints": {"/database~2name": ["development"]},
        },
        {
            "server": "data",
            "name": "db.read",
            "effect": "read",
            "argument_constraints": {"/database": []},
        },
        {
            "server": "data",
            "name": "db.read",
            "effect": "read",
            "expected_input_schema_sha256": "not-a-hash",
        },
    ],
)
def test_mcp_argument_policy_rejects_invalid_schema_or_constraint(settings: dict) -> None:
    with pytest.raises(ValidationError):
        MCPToolRule.model_validate(settings)


def test_mcp_argument_policy_accepts_local_schema_refs_and_json_pointers() -> None:
    rule = MCPToolRule.model_validate(
        {
            "server": "data",
            "name": "db.read",
            "effect": "read",
            "argument_schema": {
                "type": "object",
                "properties": {"database": {"$ref": "#/$defs/database"}},
                "$defs": {"database": {"type": "string"}},
            },
            "argument_constraints": {"/database": ["development"]},
        }
    )
    assert rule.argument_constraints == {"/database": ["development"]}
    gateway = MCPGateway(
        ReflexConfig.model_validate({"mcp": {"tools": [rule]}}), "data", ["unused"]
    )
    assert gateway._arguments_match_policy(rule, {"database": "development"})
    assert not gateway._arguments_match_policy(rule, {"database": 42})


def test_mcp_argument_policy_limits_nested_resource_values() -> None:
    config = ReflexConfig.model_validate(
        {
            "mcp": {
                "tools": [
                    {
                        "server": "cloud",
                        "name": "resource.list",
                        "effect": "read",
                        "argument_schema": {
                            "type": "object",
                            "required": ["operations"],
                            "properties": {
                                "operations": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["account"],
                                        "properties": {"account": {"type": "string"}},
                                        "additionalProperties": False,
                                    },
                                }
                            },
                            "additionalProperties": False,
                        },
                        "argument_constraints": {"/operations/0/account": ["development"]},
                    }
                ]
            }
        }
    )
    gateway = MCPGateway(config, "cloud", ["unused"], source=BytesIO(), sink=BytesIO())
    rule = config.mcp.tools[0]

    assert gateway._arguments_match_policy(rule, {"operations": [{"account": "development"}]})
    assert not gateway._arguments_match_policy(rule, {"operations": [{"account": "production"}]})
    assert not gateway._arguments_match_policy(
        rule, {"operations": [{"account": "development"}, {}]}
    )
    assert not gateway._arguments_match_policy(
        rule, {"operations": [{"account": "development"}], "extra": 1}
    )
