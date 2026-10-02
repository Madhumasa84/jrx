"""Authenticated bounded host state for optional agent controls.

The host must protect the key and containing directory from agent access.
HMAC does not detect rollback of the entire database to a valid old snapshot.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .serialization import unique_object


class ControlError(ValueError):
    """Missing, invalid, exhausted or unauthorized agent control state."""


def identifier(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,128}", value):
        raise ControlError("invalid control identifier")
    return value


def canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def private_file(path: Path, flags: int) -> int:
    path = path.expanduser().absolute()
    if path.parent.resolve() != path.parent:
        raise ControlError("control storage must not use symlink directories")
    descriptor = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        os.close(descriptor)
        raise ControlError("control storage must be an owner-only regular file")
    return descriptor


def create_host_key(path: Path) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = private_file(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(os.urandom(32))
        handle.flush()
        os.fsync(handle.fileno())


def scopes(values: list[str]) -> list[str]:
    if not values or len(values) > 128:
        raise ControlError("resource scopes must contain 1 to 128 literal relative paths")
    result = []
    for value in values:
        path = Path(value)
        if (
            not value
            or path.is_absolute()
            or ".." in path.parts
            or any(char in value for char in "*?[]\\\x00\n\r")
            or len(value) > 1024
        ):
            raise ControlError("resource scopes must be literal relative paths")
        result.append(path.as_posix())
    return sorted(set(result))


def contained(resource: str, prefixes: list[str]) -> bool:
    path = Path(resource)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and any(path.is_relative_to(Path(prefix)) for prefix in prefixes)
    )


def resources_within(repository: str, resources: list[str], prefixes: list[str]) -> bool:
    root = Path(repository).resolve()
    for value in resources:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            return False
        try:
            relative = (root / path).resolve().relative_to(root).as_posix()
        except (ValueError, OSError, RuntimeError):
            return False
        if not contained(relative, prefixes):
            return False
    return bool(resources)


CAPABILITIES = {"read", "modify", "test", "deploy", "publish", "secrets", "iam", "unknown"}


def capabilities(values: list[str]) -> list[str]:
    if not values or not set(values) <= CAPABILITIES:
        raise ControlError("invalid or empty capability set; approval/admin cannot be delegated")
    return sorted(set(values))


class AuthenticatedStore:
    def __init__(self, path: str, key_path: str, max_records: int) -> None:
        self.path = Path(path).expanduser().absolute()
        self.key_path = Path(key_path).expanduser().absolute()
        self.max_records = max_records

    def _key(self) -> bytes:
        descriptor = private_file(self.key_path, os.O_RDONLY)
        with os.fdopen(descriptor, "rb") as handle:
            key = handle.read(33)
        if len(key) != 32:
            raise ControlError("host control key must contain exactly 32 bytes")
        return key

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self._key()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = private_file(self.path, os.O_RDWR | os.O_CREAT)
        os.close(descriptor)
        # Parent directory protection is required for SQLite's pathname open and
        # journal lifecycle; descriptor checks alone cannot confine same-UID writers.
        parent = self.path.parent.stat()
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise ControlError("control database directory must be owner-only")
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS objects (namespace TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL, mac TEXT NOT NULL, PRIMARY KEY(namespace,id))"
            )
            yield connection
            connection.commit()
        except (sqlite3.Error, OSError, ValueError) as exc:
            connection.rollback()
            if isinstance(exc, ControlError):
                raise
            raise ControlError("agent control state operation failed") from exc
        finally:
            connection.close()

    def _mac(self, namespace: str, object_id: str, payload: str) -> str:
        return hmac.new(
            self._key(), (namespace + "\0" + object_id + "\0" + payload).encode(), hashlib.sha256
        ).hexdigest()

    def get(self, connection: sqlite3.Connection, namespace: str, object_id: str) -> dict[str, Any]:
        row = connection.execute(
            "SELECT payload,mac FROM objects WHERE namespace=? AND id=?", (namespace, object_id)
        ).fetchone()
        if row is None:
            raise ControlError("agent control record missing")
        payload, mac = row
        if len(payload) > 65536 or not hmac.compare_digest(
            mac, self._mac(namespace, object_id, payload)
        ):
            raise ControlError("agent control record authentication failed")
        data = json.loads(payload, object_pairs_hook=unique_object)
        if not isinstance(data, dict):
            raise ControlError("invalid agent control record")
        return data

    def put(
        self,
        connection: sqlite3.Connection,
        namespace: str,
        object_id: str,
        data: dict[str, Any],
        *,
        new: bool = False,
    ) -> None:
        payload = canonical(data)
        if len(payload) > 65536:
            raise ControlError("agent control record exceeds size limit")
        if (
            new
            and connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0] >= self.max_records
        ):
            raise ControlError("agent control storage limit reached")
        if new:
            connection.execute(
                "INSERT INTO objects VALUES (?,?,?,?)",
                (namespace, object_id, payload, self._mac(namespace, object_id, payload)),
            )
        else:
            count = connection.execute(
                "UPDATE objects SET payload=?,mac=? WHERE namespace=? AND id=?",
                (payload, self._mac(namespace, object_id, payload), namespace, object_id),
            ).rowcount
            if count != 1:
                raise ControlError("agent control record missing")

    def ids(self, connection: sqlite3.Connection, namespace: str) -> list[str]:
        return [
            row[0]
            for row in connection.execute(
                "SELECT id FROM objects WHERE namespace=? ORDER BY rowid", (namespace,)
            )
        ]
