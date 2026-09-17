"""Opt-in paid host test. The hook subprocess explicitly has no TypeSafe key."""

import json
import os
import subprocess
import sys
import time

import pytest

from jev_reflex.broker import BrokerClient
from jev_reflex.config import ReflexConfig
from jev_reflex.models import EvaluationContext, ProposedAction

pytestmark = pytest.mark.skipif(
    os.environ.get("JEV_REFLEX_LIVE_TEST") != "1" or not os.environ.get("TYPESAFE_API_KEY"),
    reason="requires explicit live opt-in and host TypeSafe credentials",
)


def test_live_broker_and_keyless_hook(tmp_path):
    path = tmp_path / "live" / "reflex.sock"
    config = ReflexConfig(jev={"transport": "broker", "socket": str(path)})
    process = subprocess.Popen(
        [sys.executable, "-m", "jev_reflex", "broker", "run", "--socket", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    client = BrokerClient(config)
    try:
        for _ in range(100):
            if client.health()["running"]:
                break
            time.sleep(0.05)
        assert client.health()["running"]
        result = client.evaluate(
            EvaluationContext(
                proposed_action=ProposedAction(command="pip install --upgrade some-package")
            )
        )
        assert result.source == "broker/live" and not result.degraded
        assert result.probabilities["dependency_risk"] >= 0.7
        config_path = tmp_path / "reflex.json"
        config_path.write_text(config.model_dump_json())
        environment = {
            name: value for name, value in os.environ.items() if name != "TYPESAFE_API_KEY"
        }
        hook = subprocess.run(
            [sys.executable, "-m", "jev_reflex", "codex-hook", "--config", str(config_path)],
            input=json.dumps(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "pip install --upgrade some-package"},
                    "cwd": str(tmp_path),
                }
            ),
            text=True,
            capture_output=True,
            env=environment,
            timeout=30,
        )
        assert hook.returncode == 0
        assert "LIVE JEV VIA BROKER" in hook.stdout
        assert "REVIEW" in hook.stdout
    finally:
        process.terminate()
        process.wait(timeout=5)
