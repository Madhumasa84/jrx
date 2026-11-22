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

MAX_SESSION_OFFSET = 2**63 - 1
MAX_TAINTS_PER_SESSION = 256


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
        try:
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
        except sqlite3.Error:
            connection.close()
            raise
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

    @staticmethod
    def _taint_tables(connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS session_taint_salts (session_id TEXT PRIMARY KEY, "
            "salt BLOB NOT NULL, overflow INTEGER NOT NULL DEFAULT 0)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS session_taints (session_id TEXT NOT NULL, "
            "kind TEXT NOT NULL, fingerprint BLOB NOT NULL, "
            "PRIMARY KEY (session_id, kind, fingerprint))"
        )

    @staticmethod
    def _taint_hash(salt: bytes, kind: str, value: str) -> bytes:
        return hashlib.sha256(
            salt + kind.encode() + b"\0" + value.encode("utf-8", "surrogatepass")
        ).digest()

    def record_taints(
        self, session_id: str, secrets: set[str], paths: set[str], *, truncated: bool = False
    ) -> None:
        session_id = self._id(session_id)
        if not (secrets or paths or truncated):
            return
        with closing(self._connect()) as connection:
            self._taint_tables(connection)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO session_taint_salts (session_id, salt) VALUES (?, ?)",
                (session_id, os.urandom(32)),
            )
            (salt,) = connection.execute(
                "SELECT salt FROM session_taint_salts WHERE session_id=?", (session_id,)
            ).fetchone()
            records = {
                (kind, self._taint_hash(salt, kind, value))
                for kind, values in (("secret", secrets), ("path", paths))
                for value in values
            }
            existing = set(
                connection.execute(
                    "SELECT kind, fingerprint FROM session_taints WHERE session_id=?", (session_id,)
                )
            )
            pending = sorted(records - existing)
            remaining = MAX_TAINTS_PER_SESSION - len(existing)
            connection.executemany(
                "INSERT INTO session_taints VALUES (?, ?, ?)",
                ((session_id, kind, fingerprint) for kind, fingerprint in pending[:remaining]),
            )
            if truncated or len(pending) > remaining:
                connection.execute(
                    "UPDATE session_taint_salts SET overflow=1 WHERE session_id=?", (session_id,)
                )
            connection.commit()

    def check_taints(self, session_id: str, candidates: set[str]) -> tuple[bool, bool, bool]:
        session_id = self._id(session_id)
        with closing(self._connect()) as connection:
            self._taint_tables(connection)
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT salt, overflow FROM session_taint_salts WHERE session_id=?", (session_id,)
            ).fetchone()
            if row is None:
                return False, False, False
            salt, overflow = row
            fingerprints = {
                row[0]
                for row in connection.execute(
                    "SELECT fingerprint FROM session_taints WHERE session_id=? AND kind='secret'",
                    (session_id,),
                )
            }
            matched = bool(fingerprints) and any(
                self._taint_hash(salt, "secret", value) in fingerprints for value in candidates
            )
            return True, matched, bool(overflow)

    def check_integrity(self, session_id: str, scope: bytes, manifest: str) -> bool:
        """Pin the first observed manifest atomically and leave it intact on drift."""
        session_id = self._id(session_id)
        with closing(self._connect()) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS session_integrity (session_id TEXT NOT NULL, "
                "scope BLOB NOT NULL, manifest TEXT NOT NULL, PRIMARY KEY (session_id, scope))"
            )
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO session_integrity VALUES (?, ?, ?)",
                (session_id, scope, manifest),
            )
            (pinned,) = connection.execute(
                "SELECT manifest FROM session_integrity WHERE session_id=? AND scope=?",
                (session_id, scope),
            ).fetchone()
            connection.commit()
            return pinned == manifest

    def status(self, session_id: str) -> dict[str, object]:
        session_id = self._id(session_id)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT started, stopped, calls, semantic, reserved_usd FROM sessions WHERE id=?",
                (session_id,),
            ).fetchone()
        if row is None:
            raise SessionLimitError("session not found")
        return self._status_row(session_id, row, time.time())

    def _status_row(self, session_id: str, row: tuple, now: float) -> dict[str, object]:
        elapsed = max(0.0, now - row[0])
        reasons = []
        if row[1]:
            reasons.append("session_stopped")
        if elapsed >= self.config.max_elapsed_seconds:
            reasons.append("elapsed_time_exhausted")
        if row[2] >= self.config.max_tool_calls:
            reasons.append("tool_calls_exhausted")
        if row[3] >= self.config.max_semantic_evaluations:
            reasons.append("semantic_evaluations_exhausted")
        if (
            row[4] + self.config.reserved_cost_per_evaluation_usd
            > self.config.max_semantic_spend_usd + 1e-9
        ):
            reasons.append("semantic_spend_insufficient")
        state = (
            "stopped"
            if row[1]
            else "expired"
            if "elapsed_time_exhausted" in reasons
            else "exhausted"
            if reasons
            else "active"
        )
        return {
            "session_id": session_id,
            "started": row[0],
            "stopped": bool(row[1]),
            "tool_calls": row[2],
            "semantic_evaluations": row[3],
            "reserved_spend_usd": row[4],
            "state": state,
            "limit_reasons": reasons,
            "elapsed_seconds": elapsed,
            "remaining": {
                "tool_calls": max(0, self.config.max_tool_calls - row[2]),
                "semantic_evaluations": max(0, self.config.max_semantic_evaluations - row[3]),
                "semantic_spend_usd": max(0.0, self.config.max_semantic_spend_usd - row[4]),
                "elapsed_seconds": max(0.0, self.config.max_elapsed_seconds - elapsed),
            },
            # These refer to single reservations; actual calls may reserve a
            # larger semantic sample count. Reserved spend is never billing.
            "can_reserve_one_tool_call": not any(
                reason in reasons
                for reason in (
                    "session_stopped",
                    "elapsed_time_exhausted",
                    "tool_calls_exhausted",
                )
            )
            and row[3] <= self.config.max_semantic_evaluations
            and row[4] <= self.config.max_semantic_spend_usd + 1e-9,
            "can_reserve_one_semantic_evaluation": not any(
                reason in reasons
                for reason in (
                    "session_stopped",
                    "elapsed_time_exhausted",
                    "semantic_evaluations_exhausted",
                    "semantic_spend_insufficient",
                )
            )
            and row[2] <= self.config.max_tool_calls,
        }

    def list_sessions(
        self, *, state: str | None = None, limit: int = 50, offset: int = 0
    ) -> list[dict[str, object]]:
        """Return a bounded page, newest first, without reserving or resetting budgets."""
        if state not in {None, "active", "stopped", "expired", "exhausted"}:
            raise SessionLimitError("invalid session state filter")
        if (
            type(limit) is not int
            or not 1 <= limit <= 500
            or type(offset) is not int
            or not 0 <= offset <= MAX_SESSION_OFFSET
        ):
            raise SessionLimitError("invalid session page")
        if not self.path.exists():
            return []
        now = time.time()
        cutoff = now - self.config.max_elapsed_seconds
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT id, started, stopped, calls, semantic, reserved_usd FROM sessions"
                " WHERE ? IS NULL OR ? = CASE"
                " WHEN stopped != 0 THEN 'stopped'"
                " WHEN started <= ? THEN 'expired'"
                " WHEN calls >= ? OR semantic >= ? OR reserved_usd + ? > ? THEN 'exhausted'"
                " ELSE 'active' END"
                " ORDER BY started DESC, id ASC LIMIT ? OFFSET ?",
                (
                    state,
                    state,
                    cutoff,
                    self.config.max_tool_calls,
                    self.config.max_semantic_evaluations,
                    self.config.reserved_cost_per_evaluation_usd,
                    self.config.max_semantic_spend_usd + 1e-9,
                    limit,
                    offset,
                ),
            ).fetchall()
        return [self._status_row(row[0], row[1:], now) for row in rows]
