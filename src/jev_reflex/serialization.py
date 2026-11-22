"""Bounded, unambiguous parsing at security configuration boundaries."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._yaml_loader import SecurityLoader as SecurityLoader

MAX_CONFIG_BYTES = 1_048_576


def read_config_bytes(path: Path) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("Configuration exceeds the 1 MiB size limit.")
    return raw


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def __getattr__(name: str) -> Any:
    if name == "SecurityLoader":
        from ._yaml_loader import SecurityLoader

        return SecurityLoader
    raise AttributeError(name)


def safe_yaml_load(raw: str | bytes) -> Any:
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("configuration exceeds size limit")
    from ._yaml_loader import SecurityLoader

    loader = SecurityLoader(raw)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()
