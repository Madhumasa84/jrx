"""Real SQLite connections must close when schema initialization fails."""

import sqlite3
from functools import partial

import pytest

from jev_reflex.config import AccessConfig, SessionLimitsConfig
from jev_reflex.enterprise import ApprovalStore, Identity
from jev_reflex.session_limits import SessionStore


@pytest.mark.parametrize("kind", ["approval", "session"])
def test_invalid_database_closes_connection_and_can_recover(tmp_path, monkeypatch, kind):
    path = tmp_path / "state.sqlite3"
    path.write_bytes(b"invalid database" * 20)
    path.chmod(0o600)
    connections = []
    connect = sqlite3.connect

    def tracked_connect(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", tracked_connect)
    if kind == "approval":
        store = ApprovalStore(
            AccessConfig(
                issuer="https://idp.example",
                audience="jrx",
                jwks_uri="https://idp.example/jwks",
                environment="development",
                approval_db=str(path),
                rules=[
                    {
                        "role": "reviewer",
                        "actions": ["review"],
                        "repositories": ["*"],
                        "environments": ["*"],
                    }
                ],
            )
        )
        operation = partial(store.pending, Identity("reviewer", frozenset({"reviewer"})))
    else:
        store = SessionStore(SessionLimitsConfig(path=str(path)))
        operation = partial(store.reserve, "session", semantic=0)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            operation()
        assert len(connections) == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connections[0].execute("SELECT 1")
        # A repaired file remains usable by the same store instance.
        path.write_bytes(b"")
        operation()
    finally:
        for connection in connections:
            connection.close()
