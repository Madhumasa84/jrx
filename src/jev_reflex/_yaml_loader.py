"""Bounded YAML loader for security configuration."""

from __future__ import annotations

from typing import Any

import yaml

# JSON-compatible core schema only. ``!!set`` yields hash-seed-dependent order,
# ``!!omap``/``!!pairs`` yield tuples, ``!!binary`` bytes and ``!!timestamp``
# dates: none has one canonical JSON form, so none may reach a policy hash.
_CORE_TAGS = frozenset(
    "tag:yaml.org,2002:" + name for name in ("null", "bool", "int", "float", "str", "seq", "map")
)


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

    def construct_object(self, node: Any, deep: bool = False) -> Any:
        # Also rejects merge keys (``<<``) and application-specific tags. The
        # message carries no input value or source snippet.
        if node.tag not in _CORE_TAGS:
            raise yaml.constructor.ConstructorError(
                None, None, "YAML tag is not supported in security configuration", None
            )
        return super().construct_object(node, deep=deep)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("configuration keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result
