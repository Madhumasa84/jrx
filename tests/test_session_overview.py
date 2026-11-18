"""Session discovery, remaining budgets, pagination and administrator access."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml
from typer.testing import CliRunner

from jev_reflex.cli import app
from jev_reflex.config import SessionLimitsConfig
from jev_reflex.enterprise import AccessDenied, Identity
from jev_reflex.session_limits import SessionLimitError, SessionStore


def store(tmp_path, **fields):
    return SessionStore(
        SessionLimitsConfig.model_validate(
            {
                "enabled": True,
                "path": str(tmp_path / "sessions.sqlite3"),
                **fields,
            }
        )
    )


def test_overview_is_empty_without_creating_a_database(tmp_path):
    ledger = store(tmp_path)
    assert ledger.list_sessions() == []
    assert not ledger.path.exists()


def test_remaining_budgets_and_single_reservation_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr("jev_reflex.session_limits.time.time", lambda: 1000.0)
    ledger = store(
        tmp_path,
        max_tool_calls=3,
        max_semantic_evaluations=5,
        max_semantic_spend_usd=0.025,
        max_elapsed_seconds=20,
    )
    ledger.reserve("run-1", semantic=2)
    monkeypatch.setattr("jev_reflex.session_limits.time.time", lambda: 1005.0)
    status = ledger.status("run-1")
    assert status["state"] == "exhausted"
    assert status["remaining"]["tool_calls"] == 2
    assert status["remaining"]["semantic_evaluations"] == 3
    assert status["remaining"]["semantic_spend_usd"] == pytest.approx(0.005)
    assert status["remaining"]["elapsed_seconds"] == 15
    assert status["limit_reasons"] == ["semantic_spend_insufficient"]
    assert status["can_reserve_one_tool_call"]
    assert not status["can_reserve_one_semantic_evaluation"]
    assert ledger.list_sessions(state="exhausted")[0] == status
    # Reading an overview does not reserve or stop a session.
    assert ledger.status("run-1")["tool_calls"] == 1
    assert not ledger.status("run-1")["stopped"]
    ledger.reserve("run-1", semantic=0)
    # A newly tightened policy also constrains existing reservations, including
    # a zero-semantic call when prior spend already exceeds the new budget.
    tighter = SessionStore(ledger.config.model_copy(update={"max_semantic_spend_usd": 0.015}))
    assert not tighter.status("run-1")["can_reserve_one_tool_call"]
    with pytest.raises(SessionLimitError, match="spend"):
        tighter.reserve("run-1", semantic=0)


@pytest.mark.parametrize(
    "field, reason",
    [
        ("max_tool_calls", "tool_calls_exhausted"),
        ("max_semantic_evaluations", "semantic_evaluations_exhausted"),
    ],
)
def test_exhaustion_reasons(tmp_path, field, reason):
    ledger = store(tmp_path, **{field: 1})
    ledger.reserve("run", semantic=1)
    status = ledger.status("run")
    assert status["state"] == "exhausted"
    assert reason in status["limit_reasons"]
    assert len(ledger.list_sessions(state="exhausted")) == 1
    assert not ledger.list_sessions(state="active")


def test_exact_float_budget_uses_same_tolerance_as_reservations(tmp_path):
    ledger = store(tmp_path, max_semantic_spend_usd=0.03)
    ledger.reserve("run", semantic=2)
    assert ledger.status("run")["state"] == "active"
    ledger.reserve("run", semantic=1)
    assert ledger.status("run")["state"] == "exhausted"
    assert ledger.status("run")["remaining"]["semantic_spend_usd"] == 0


def test_state_filters_precedence_and_stable_pagination(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr("jev_reflex.session_limits.time.time", lambda: clock[0])
    ledger = store(tmp_path, max_tool_calls=2, max_elapsed_seconds=10)
    ledger.reserve("expired", semantic=0)
    clock[0] = 1010.0
    ledger.reserve("z-active", semantic=0)
    ledger.reserve("a-active", semantic=0)
    ledger.reserve("exhausted", semantic=0, tool_calls=2)
    ledger.stop("stopped")
    for state, expected in [
        ("active", ["a-active", "z-active"]),
        ("expired", ["expired"]),
        ("exhausted", ["exhausted"]),
        ("stopped", ["stopped"]),
    ]:
        rows = ledger.list_sessions(state=state)
        assert [row["session_id"] for row in rows] == expected
        assert all(row["state"] == state for row in rows)
    all_ids = [row["session_id"] for row in ledger.list_sessions()]
    assert all_ids == ["a-active", "exhausted", "stopped", "z-active", "expired"]
    assert [row["session_id"] for row in ledger.list_sessions(limit=2, offset=1)] == all_ids[1:3]
    clock[0] = 1020.0
    assert not ledger.list_sessions(state="active")
    assert not ledger.list_sessions(state="exhausted")
    assert len(ledger.list_sessions(state="expired")) == 4
    assert ledger.status("stopped")["state"] == "stopped"
    assert ledger.status("expired")["remaining"]["elapsed_seconds"] == 0


@pytest.mark.parametrize(
    "options",
    [
        {"state": "invalid"},
        {"state": "' OR 1=1 --"},
        {"limit": 0},
        {"limit": 501},
        {"limit": True},
        {"offset": -1},
        {"offset": False},
    ],
)
def test_invalid_page_inputs_are_rejected(tmp_path, options):
    with pytest.raises(SessionLimitError):
        store(tmp_path).list_sessions(**options)


def test_unsafe_database_and_connection_cleanup(tmp_path):
    ledger = store(tmp_path)
    ledger.reserve("run", semantic=0)
    ledger.path.chmod(0o644)
    with pytest.raises(SessionLimitError, match="owner-only"):
        ledger.list_sessions()
    ledger.path.chmod(0o600)
    assert ledger.list_sessions()[0]["session_id"] == "run"
    # A report leaves no open transaction or connection lock.
    with sqlite3.connect(ledger.path, timeout=0.1) as connection:
        connection.execute("BEGIN EXCLUSIVE")
        connection.execute("UPDATE sessions SET stopped=1 WHERE id='run'")
    assert ledger.status("run")["stopped"]


def test_listing_during_parallel_reservations_does_not_change_accounting(tmp_path):
    ledger = store(tmp_path)
    ledger.reserve("run", semantic=0, tool_calls=0)

    def work(index):
        if index % 2:
            ledger.reserve("run", semantic=1)
        else:
            assert ledger.list_sessions()[0]["session_id"] == "run"

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(work, range(40)))
    assert ledger.status("run")["tool_calls"] == 20
    assert ledger.status("run")["semantic_evaluations"] == 20


def write_config(tmp_path, ledger, **fields):
    path = tmp_path / "reflex.yaml"
    path.write_text(yaml.safe_dump({"session": ledger.config.model_dump(), **fields}))
    return path


def test_cli_human_json_filters_pagination_and_status(tmp_path):
    ledger = store(tmp_path)
    ledger.reserve("active", semantic=1)
    ledger.stop("stopped")
    config = write_config(tmp_path, ledger)
    args = ["session", "list", "--config", str(config)]
    result = CliRunner().invoke(app, [*args, "--state", "active", "--json"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert len(report["sessions"]) == 1
    assert report["sessions"][0]["state"] == "active"
    human = CliRunner().invoke(app, args)
    assert human.exit_code == 0, human.output
    assert "CALLS LEFT" in human.output and "not provider billing" in human.output
    missing = CliRunner().invoke(app, [*args, "--offset", "100"])
    assert missing.exit_code == 0 and "No sessions" in missing.output
    bad = CliRunner().invoke(app, [*args, "--state", "wrong"])
    assert bad.exit_code == 2 and not bad.stdout
    status = CliRunner().invoke(app, ["session", "status", "active", "--config", str(config)])
    assert status.exit_code == 0
    assert json.loads(status.stdout)["remaining"]["tool_calls"] == 999


def test_cli_preserves_oidc_admin_authorization(tmp_path, monkeypatch):
    import jev_reflex.cli as cli

    ledger = store(tmp_path)
    ledger.reserve("private-session", semantic=1)
    config = write_config(
        tmp_path,
        ledger,
        access={
            "issuer": "https://sso.example",
            "audience": "jrx",
            "jwks_uri": "https://sso.example/keys",
            "environment": "production",
            "rules": [
                {
                    "role": "operator",
                    "actions": ["admin"],
                    "repositories": ["*"],
                    "environments": ["production"],
                }
            ],
        },
    )
    args = ["session", "list", "--config", str(config), "--json"]

    # Missing identity is denied before the database is enumerated.
    def denied(*args, **kwargs):
        raise AccessDenied("private-error-fixture")

    monkeypatch.setattr(cli, "verified_identity", denied)
    missing = CliRunner().invoke(app, args)
    assert missing.exit_code == 2 and "private-" not in missing.output
    monkeypatch.setattr(
        cli, "verified_identity", lambda _: Identity("user", frozenset({"developer"}))
    )
    assert CliRunner().invoke(app, args).exit_code == 2
    monkeypatch.setattr(
        cli, "verified_identity", lambda _: Identity("admin", frozenset({"operator"}))
    )
    allowed = CliRunner().invoke(app, args)
    assert allowed.exit_code == 0, allowed.output
    assert json.loads(allowed.stdout)["sessions"][0]["session_id"] == "private-session"


def test_cli_refuses_disabled_session_controls(tmp_path):
    config = tmp_path / "policy.yaml"
    config.write_text("session: {enabled: false}")
    result = CliRunner().invoke(app, ["session", "list", "--config", str(config)])
    assert result.exit_code == 2


def test_session_offset_overflow_is_rejected_before_database_access(tmp_path):
    ledger = store(tmp_path)
    ledger.reserve("run", semantic=0)
    with pytest.raises(SessionLimitError, match="page"):
        ledger.list_sessions(offset=2**63)
    config = write_config(tmp_path, ledger)
    result = CliRunner().invoke(
        app, ["session", "list", "--config", str(config), "--offset", str(2**63), "--json"]
    )
    assert result.exit_code == 2
    assert not result.stdout
    assert ledger.status("run")["tool_calls"] == 1
