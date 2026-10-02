"""Bounded, unambiguous parsing at security configuration boundaries."""

from __future__ import annotations

from typing import Any

import yaml

MAX_CONFIG_BYTES = 1_048_576


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


class SecurityLoader(yaml.SafeLoader):
    def __init__(self, stream: str | bytes) -> None:
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise ValueError("YAML aliases are not supported in security configuration")
        self._depth += 1
        self._nodes += 1
        try:
            if self._depth > 64 or self._nodes > 20_000:
                raise ValueError("configuration exceeds structural limits")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("configuration keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def safe_yaml_load(raw: str | bytes) -> Any:
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("configuration exceeds size limit")
    loader = SecurityLoader(raw)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()
