from __future__ import annotations

from typing import Any

from jev_reflex.integrations.typesafe import TypeSafeIntegration, TypeSafeIntegrationError


class FakeClient:
    def __init__(self, calls: list[tuple[dict[str, Any], dict[str, Any]]], **kwargs: Any) -> None:
        self.calls = calls
        self.kwargs = kwargs

    def system_one(self, *, state: dict[str, Any], questions: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((state, questions))
        return {"answers": {}}

    def close(self) -> None:
        pass


def test_integration_passes_only_the_explicit_api_key_to_client(monkeypatch: Any) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-key")
    calls: list[tuple[dict[str, Any], dict[str, Any]]] = []
    created: list[FakeClient] = []

    def factory(**kwargs: Any) -> FakeClient:
        client = FakeClient(calls, **kwargs)
        created.append(client)
        return client

    TypeSafeIntegration(client_factory=factory).system_one(
        {
            "safe": True,
            "password": "do-not-send",
            "proposed_action": {"argv": ["tool", "--token", "do-not-send"]},
        },
        {"q": object()},
    )
    assert created[0].kwargs == {"api_key": "test-key"}
    assert calls[0][0] == {
        "safe": True,
        "password": "<REDACTED_SECRET>",
        "proposed_action": {"argv": ["tool", "--token", "<REDACTED_SECRET>"]},
    }


def test_missing_api_key_is_a_generic_failure(monkeypatch: Any) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    try:
        TypeSafeIntegration(client_factory=lambda **_: None).system_one({}, {})
    except TypeSafeIntegrationError as error:
        assert "test-key" not in str(error)
    else:
        raise AssertionError("missing key did not fail")
