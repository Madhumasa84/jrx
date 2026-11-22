"""Ordinary tests never inherit real TypeSafe credentials from the invoking shell."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from jev_reflex.audit import AuditLog
from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig
from jev_reflex.policy import decide

PRIVATE_ACTION = "PRIVATE-CANARY: unreleased deployment"


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


@pytest.fixture
def write_impact_entry():
    def write(data, signals=None):
        config = ReflexConfig.model_validate(data)
        if signals is None:
            signals = {"unsafe": 0.6}
        AuditLog(config).write_entry(
            PRIVATE_ACTION,
            [],
            signals,
            decide([], signals, config),
            risk_choice="low",
            risk_confidence=0.95,
            degraded=False,
            forced_review=False,
        )

    return write


@pytest.fixture
def impact_case(tmp_path, write_impact_entry):
    audit = tmp_path / "PRIVATE-CANARY-audit.jsonl"
    baseline = tmp_path / "base.yaml"
    candidate = tmp_path / "candidate.yaml"
    data = {
        "mode": "enforce",
        "audit": {"enabled": True, "path": str(audit)},
        "thresholds": {"review": 0.5, "strong": 0.9},
    }
    baseline.write_text(json.dumps(data))
    write_impact_entry(data)
    data["thresholds"]["review"] = 0.7
    candidate.write_text(json.dumps(data))

    def run(*args):
        result = CliRunner().invoke(
            app,
            [
                "policy",
                "impact",
                "--audit",
                str(audit),
                "--baseline",
                str(baseline),
                "--candidate",
                str(candidate),
                *args,
            ],
        )
        assert "PRIVATE-CANARY" not in result.output
        if "--github-output" in args:
            output = Path(args[args.index("--github-output") + 1])
            if output.is_file():
                assert "PRIVATE-CANARY" not in output.read_text()
        return result

    return audit, baseline, candidate, run
