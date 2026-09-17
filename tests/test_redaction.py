from jev_reflex.models import EvaluationResult, RiskInfo
from jev_reflex.redaction import REDACTED_SECRET, redact_obj, redact_text


def test_common_secret_patterns_are_redacted() -> None:
    original = (
        "Authorization: Bearer bearer-value-123456 "
        "TYPESAFE_API_KEY=super-secret-value "
        "ghp_abcdefghijklmnopqrstuvwxyz123456 "
        "AKIAIOSFODNN7EXAMPLE"
    )
    result = redact_text(original)
    assert REDACTED_SECRET in result
    for secret in (
        "bearer-value-123456",
        "super-secret-value",
        "ghp_abcdefghijklmnopqrstuvwxyz123456",
    ):
        assert secret not in result
    assert "AKIAIOSFODNN7EXAMPLE" not in result


def test_private_key_and_quoted_assignment_are_redacted() -> None:
    private_key = "-----BEGIN PRIVATE KEY-----\nsecret body\n-----END PRIVATE KEY-----"
    result = redact_text(f'password="open-sesame" key={private_key}')
    assert "open-sesame" not in result
    assert "secret body" not in result
    assert REDACTED_SECRET in result


def test_secret_looking_object_keys_are_redacted() -> None:
    result = redact_obj({"token": "raw-token", "nested": {"password": "raw-password"}})
    assert result == {"token": REDACTED_SECRET, "nested": {"password": REDACTED_SECRET}}


def test_shell_variable_reference_is_not_treated_as_secret_value() -> None:
    result = redact_text("echo $TYPESAFE_API_KEY")
    assert result == "echo $TYPESAFE_API_KEY"


def test_quoted_authorization_headers_keep_shell_boundaries() -> None:
    value = "curl -H 'Authorization: Bearer demo-token-123456789' https://example.invalid"
    assert (
        redact_text(value) == "curl -H 'Authorization: <REDACTED_SECRET>' https://example.invalid"
    )


def test_authorization_schemes_and_camel_case_secret_keys_are_redacted() -> None:
    assert redact_text("Authorization: Basic abc123") == "Authorization: <REDACTED_SECRET>"
    assert redact_obj({"apiKey": "raw-key", "Authorization": "raw-auth"}) == {
        "apiKey": REDACTED_SECRET,
        "Authorization": REDACTED_SECRET,
    }


def test_public_result_redacts_manually_constructed_action() -> None:
    result = EvaluationResult(
        decision="ALLOW",
        risk=RiskInfo(choice="low"),
        action='curl -H "Authorization: Bearer raw-secret-value"',
    )
    assert "raw-secret-value" not in str(result.to_public_dict())
    assert "raw-secret-value" not in result.reason_summary()
