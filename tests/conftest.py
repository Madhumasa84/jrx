"""Ordinary tests never inherit real TypeSafe credentials from the invoking shell."""

import pytest


@pytest.fixture(autouse=True)
def isolate_live_credentials(request, monkeypatch):
    if request.node.path.name != "test_live_broker.py":
        monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
