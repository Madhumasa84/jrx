"""Ordinary tests never inherit real TypeSafe credentials from the invoking shell."""

import pytest


@pytest.fixture(autouse=True)
def isolate_live_credentials(request, monkeypatch):
    if request.node.path.name != "test_live_broker.py":
        monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def isolate_ambient_repository(request, tmp_path, monkeypatch):
    # These tests exercise real default context collection. Their inputs must not
    # include whichever source-code diff the developer happens to be editing.
    if request.node.path.name in {
        "test_cli.py",
        "test_broker.py",
        "test_harness_adapters.py",
        "test_mcp_schema_pin.py",
        "test_mcp_session.py",
    }:
        monkeypatch.chdir(tmp_path)
