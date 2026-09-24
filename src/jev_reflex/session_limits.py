"""Atomic per-agent session limits and administrator stop state."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import time
from contextlib import closing
from pathlib import Path

from .config import SessionLimitsConfig


class SessionLimitError(ValueError):
    """A session is stopped or has exhausted a configured limit."""


class SessionStore:
    def __init__(self, config: SessionLimitsConfig) -> None:
        self.config = config
        self.path = Path(config.path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _connect(self) -> sqlite3.Connection:
        if not self.path.exists():
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        details = self.path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_mode & 0o077
            or details.st_nlink != 1
        ):
            raise SessionLimitError("session database must be an owner-only regular file")
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, started REAL NOT NULL, "
            "stopped INTEGER NOT NULL, calls INTEGER NOT NULL, semantic INTEGER NOT NULL, "
            "reserved_usd REAL NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS risky_attempts (session_id TEXT NOT NULL, "
            "fingerprint TEXT NOT NULL, count INTEGER NOT NULL, "
            "PRIMARY KEY (session_id, fingerprint))"
        )
        return connection

    @staticmethod
    def _id(session_id: str) -> str:
        if (
            not session_id
            or len(session_id) > 128
            or not all(char.isalnum() or char in "_-:." for char in session_id)
        ):
            raise SessionLimitError("a valid host-provided session ID is required")
        return session_id

    def reserve(self, session_id: str, *, semantic: int, tool_calls: int = 1) -> None:
        """Reserve a whole call and its maximum configured semantic spend before work."""
        session_id = self._id(session_id)
        if semantic < 0 or tool_calls < 0:
            raise SessionLimitError("invalid session reservation")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = time.time()
            connection.execute(
                "INSERT OR IGNORE INTO sessions VALUES (?, ?, 0, 0, 0, 0)",
                (session_id, now),
            )
            started, stopped, calls, evaluations, spent = connection.execute(
                "SELECT started, stopped, calls, semantic, reserved_usd FROM sessions WHERE id=?",
                (session_id,),
            ).fetchone()
            if stopped:
                raise SessionLimitError("session stopped by administrator")
            if now - started >= self.config.max_elapsed_seconds:
                raise SessionLimitError("session time limit reached")
            if calls + tool_calls > self.config.max_tool_calls:
                raise SessionLimitError("session tool-call limit reached")
            if evaluations + semantic > self.config.max_semantic_evaluations:
                raise SessionLimitError("session semantic-evaluation limit reached")
            next_spend = spent + semantic * self.config.reserved_cost_per_evaluation_usd
            if next_spend > self.config.max_semantic_spend_usd + 1e-9:
                raise SessionLimitError("session semantic-spend reservation limit reached")
            connection.execute(
                "UPDATE sessions SET calls=?, semantic=?, reserved_usd=? WHERE id=?",
                (calls + tool_calls, evaluations + semantic, next_spend, session_id),
            )
            connection.commit()

    def record_risky(self, session_id: str, action: str) -> None:
        session_id = self._id(session_id)
        fingerprint = hashlib.sha256(action.encode()).hexdigest()
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT stopped FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
            if row is None or row[0]:
                raise SessionLimitError("session stopped or missing")
            connection.execute(
                "INSERT INTO risky_attempts VALUES (?, ?, 1) "
                "ON CONFLICT(session_id, fingerprint) DO UPDATE SET count=count+1",
                (session_id, fingerprint),
            )
            count = connection.execute(
                "SELECT count FROM risky_attempts WHERE session_id=? AND fingerprint=?",
                (session_id, fingerprint),
            ).fetchone()[0]
            if count >= self.config.max_risky_attempts:
                # Commit the stop together with the counter so subsequent calls and
                # execution watchers observe the exhausted limit across processes.
                connection.execute("UPDATE sessions SET stopped=1 WHERE id=?", (session_id,))
            connection.commit()
        if count >= self.config.max_risky_attempts:
            raise SessionLimitError("repeated risky-action limit reached")

    def stop(self, session_id: str) -> None:
        session_id = self._id(session_id)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO sessions VALUES (?, ?, 1, 0, 0, 0) "
                "ON CONFLICT(id) DO UPDATE SET stopped=1",
                (session_id, time.time()),
            )
            connection.commit()

    def status(self, session_id: str) -> dict[str, object]:
        session_id = self._id(session_id)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT started, stopped, calls, semantic, reserved_usd FROM sessions WHERE id=?",
                (session_id,),
            ).fetchone()
        if row is None:
            raise SessionLimitError("session not found")
        return {
            "session_id": session_id,
            "started": row[0],
            "stopped": bool(row[1]),
            "tool_calls": row[2],
            "semantic_evaluations": row[3],
            "reserved_spend_usd": row[4],
        }
