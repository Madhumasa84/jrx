from __future__ import annotations

import json
import math
import os
import socket
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from jev_reflex.cli import _check_exit_code, app
from jev_reflex.config import ReflexConfig
from jev_reflex.evaluator import evaluate_context
from jev_reflex.models import EvaluationContext, ProposedAction, RiskInfo, SemanticSignals
from onnx_runtime_fixture import DIGEST, install_runtime


def configure(**settings):
    return ReflexConfig.model_validate(
        {
            "mode": "enforce",
            "hold_on": ["prompt_injection"],
            "review_on": [],
            "logging": {"enabled": False},
            "evaluator": {"provider": "local", **settings},
        }
    )


def context(text=""):
    return EvaluationContext(
        proposed_action=ProposedAction(command="git status"),
        repository_root="/private/projects/project",
        working_directory="/private/projects/project/src",
        external_content=text,
    )


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    return install_runtime(monkeypatch, tmp_path)


def test_local_masks_survive_512_token_truncation_and_probability_is_calibrated(runtime):
    from jev_reflex.local_evaluator import LocalONNXModel, LocalSemanticEvaluator

    evaluation = LocalSemanticEvaluator(configure())
    result = evaluation.evaluate(context("evidence [MASK] " * 1024))
    assert result.source == "local" and result.model_digest == DIGEST
    assert not result.degraded and result.truncated
    assert set(result.probabilities) == {"prompt_injection"}
    assert math.isclose(result.probabilities["prompt_injection"], 1 / (1 + math.exp(-4)))
    assert runtime.feeds["qtype"] == [2]
    ids = runtime.feeds["input_ids"][0]
    assert len(ids) == 512 and ids[-1] == 102
    assert [ids[i] for i in runtime.feeds["marker_pos"][0]] == [104, 104]
    assert ids.count(104) == 2
    assert runtime.sessions == 1
    assert evaluation.evaluate(context("evidence [MASK] " * 1024)) == result
    assert runtime.sessions == 1 and runtime.calls == 2
    assert LocalONNXModel(configure()).digest == DIGEST


@pytest.mark.parametrize("problem", ["dependency", "weights", "bad_contract"])
def test_local_backend_fail_closed(monkeypatch, runtime, problem):
    from jev_reflex import local_evaluator as local
    from jev_reflex.model_files import ModelError

    if problem == "dependency":
        monkeypatch.setitem(sys.modules, "onnxruntime", None)
    elif problem == "weights":

        def missing(*_):
            raise ModelError("Model files missing")

        monkeypatch.setattr(local, "verify_model", missing)
    else:
        runtime.verified.decision.write_text("{}")
    config = configure()
    result = evaluate_context(context(), config=config)
    assert result.degraded and result.decision == "REVIEW"
    assert _check_exit_code(result, config) == 2
    command = 'pip install "jev-reflex[local]"' if problem == "dependency" else "jrx model pull"
    assert command in " ".join(result.warnings)


def test_hybrid_uses_key_only_for_uncertainty_or_truncation(monkeypatch, runtime):
    from jev_reflex.local_evaluator import LocalSemanticEvaluator

    hosted = SemanticSignals(
        source="jev", probabilities={"prompt_injection": 0.12}, risk=RiskInfo(choice="low")
    )
    called = []
    fallback = SimpleNamespace(evaluate=lambda ctx: called.append(ctx) or hosted)
    evaluator = LocalSemanticEvaluator(configure(provider="hybrid"), fallback=fallback)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    runtime.logits = (0, 0)
    result = evaluator.evaluate(context())
    assert result.risk.choice == "medium" and result.degraded and not called
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only")
    assert evaluator.evaluate(context()) == hosted
    runtime.logits = (3, 0)
    assert evaluator.evaluate(context()).source == "local"
    assert evaluator.evaluate(context("evidence " * 1024)) == hosted
    assert len(called) == 2


def test_hybrid_advisory_only_signal_does_not_require_fallback(monkeypatch, runtime):
    from jev_reflex.local_evaluator import LocalSemanticEvaluator

    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    config = configure(provider="hybrid")
    config.rule_modes = {"prompt_injection": "advisory"}
    runtime.logits = (0, 0)
    result = evaluate_context(
        context(), config=config, semantic_evaluator=LocalSemanticEvaluator(config)
    )
    assert not result.degraded and result.decision == "ALLOW"


def test_hybrid_retains_local_only_hold_when_hosted_fallback_succeeds(monkeypatch):
    from jev_reflex.local_evaluator import LocalSemanticEvaluator

    config = configure(provider="hybrid")
    config.hold_on.append("goal_hijack_diff")
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only")
    evaluator = LocalSemanticEvaluator(
        config,
        fallback=SimpleNamespace(
            evaluate=lambda _: SemanticSignals(
                source="jev", probabilities={"prompt_injection": 0.05}, risk=RiskInfo(choice="low")
            )
        ),
    )
    monkeypatch.setattr(
        evaluator,
        "_evaluate_local",
        lambda _: SemanticSignals(
            source="local",
            model_digest=DIGEST,
            probabilities={"prompt_injection": 0.5, "goal_hijack_diff": 0.99},
            risk=RiskInfo(choice="low"),
        ),
    )
    state = context().model_copy(update={"git_diff": "+more text"})
    result = evaluate_context(state, config=config, semantic_evaluator=evaluator)
    assert result.decision == "HOLD" and not result.degraded
    assert result.semantic_source == "hybrid" and result.model_digest is None
    assert result.semantic_contributors is not None
    assert {(item.source, item.model_digest) for item in result.semantic_contributors} == {
        ("local", DIGEST),
        ("jev", None),
    }
    assert result.signals == {"prompt_injection": 0.05, "goal_hijack_diff": 0.99}


def test_check_with_local_config_writes_provenance(runtime, tmp_path, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    config = tmp_path / "reflex.yaml"
    audit = tmp_path / "audit.log"
    config.write_text(f"evaluator:\n  provider: local\naudit:\n  enabled: true\n  path: {audit}\n")
    result = CliRunner().invoke(
        app,
        [
            "check",
            "--config",
            str(config),
            "--command",
            "git status",
            "--cwd",
            str(tmp_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    record = json.loads(result.stdout)
    entry = json.loads(audit.read_text())
    assert record["semantic_source"] == entry["source"] == "local"
    assert record["model_digest"] == entry["model_digest"] == DIGEST
    assert record["decision_id"] == entry["decision_id"]
    # A subsequent append also verifies the hashes of the extended entry.
    assert (
        CliRunner()
        .invoke(
            app,
            ["check", "--config", str(config), "--command", "git status", "--cwd", str(tmp_path)],
        )
        .exit_code
        == 0
    )
    assert len(audit.read_text().splitlines()) == 2


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_local_system_one_uses_no_credentials_or_proxy(monkeypatch, host):
    import httpx2

    from jev_reflex.local_evaluator import LocalSemanticEvaluator

    class Response:
        status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def aiter_bytes(self, chunk_size):
            assert chunk_size > 0
            yield b'{"answers":{"prompt_injection":{"type":"noul","noul":0.15}}}'

    class Session:
        def __init__(self, *, timeout, trust_env, follow_redirects):
            assert timeout > 0 and not trust_env and not follow_redirects

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        def stream(self, method, url, *, json, headers=None):
            assert method == "POST" and url == "http://127.0.0.1:11435/v1/systemone"
            if host == "localhost":
                assert headers == {"Host": "localhost:11435"}
            assert json["model"] == "coba:68m-ternary"
            assert json["questions"]["prompt_injection"]["type"] == "noul"
            assert "/private/projects" not in json["state"]
            assert "cwd: src" in json["state"]
            return Response()

    monkeypatch.setattr(httpx2, "AsyncClient", Session)
    monkeypatch.setitem(sys.modules, "onnxruntime", None)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    evaluator = LocalSemanticEvaluator(configure(local_base_url=f"http://{host}:11435"))
    result = evaluator.evaluate(context())
    assert result.source == "local" and not result.degraded
    assert result.probabilities == {"prompt_injection": 0.15}


def test_local_system_one_checks_runtime_url_before_connecting(monkeypatch):
    import httpx2

    from jev_reflex.local_evaluator import LocalSemanticEvaluator

    config = configure(local_base_url="http://127.0.0.1:11435")
    config.evaluator.local_base_url = "http://example.invalid"

    def no_network(**_):
        pytest.fail("non-loopback HTTP request reached the client")

    monkeypatch.setattr(httpx2, "AsyncClient", no_network)
    assert LocalSemanticEvaluator(config).evaluate(context()).degraded


def test_hybrid_does_not_send_irrecoverably_truncated_state(monkeypatch):
    from jev_reflex.local_evaluator import LocalSemanticEvaluator

    config = configure(provider="hybrid")
    calls = []

    def hosted(state):
        calls.append(state)
        return SemanticSignals(
            source="jev", probabilities={"prompt_injection": 0.05}, risk=RiskInfo(choice="low")
        )

    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only")
    evaluator = LocalSemanticEvaluator(config, fallback=SimpleNamespace(evaluate=hosted))
    monkeypatch.setattr(
        evaluator,
        "_evaluate_local",
        lambda _: SemanticSignals(
            source="local",
            model_digest=DIGEST,
            probabilities={"prompt_injection": 0.50},
            risk=RiskInfo(choice="low"),
            truncated=True,
        ),
    )
    state = context().model_copy(update={"semantic_state_truncated": True})
    result = evaluator.evaluate(state)
    assert result.degraded
    assert calls == []
    assert evaluator.last_api_requests == 0


def test_context_provider_marks_actual_truncation_independently_of_marker_text(tmp_path):
    from jev_reflex.context import RepositoryContextProvider

    provider = RepositoryContextProvider(
        cwd=tmp_path, include_git_diff=False, include_changed_files=False, max_context_chars=64
    )
    input_state = {"user_task": "", "proposed_action": ProposedAction(command="git status")}
    truncated = provider.build(**input_state, external_content="x" * 65)
    assert truncated.semantic_state_truncated
    assert "semantic_state_truncated" not in truncated.to_jev_state()
    assert not provider.build(
        **input_state, external_content="...[truncated by jev-reflex]..."
    ).semantic_state_truncated


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="Linux socket credentials required")
def test_local_broker_client_checks_connected_uid_before_sending(monkeypatch):
    from jev_reflex import broker

    sent = []

    class ForeignPeer:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def settimeout(self, _):
            pass

        def connect(self, _):
            pass

        def getsockopt(self, level, option, size):
            assert (level, option) == (socket.SOL_SOCKET, socket.SO_PEERCRED)
            assert size == struct.calcsize("iII")
            return struct.pack("iII", 1, os.getuid() ^ 1, 0)

        def sendall(self, message):
            sent.append(message)

        def recv(self, _):
            return b""

    monkeypatch.setattr(broker, "verify_socket", lambda _: None)
    monkeypatch.setattr(socket, "socket", lambda *_: ForeignPeer())
    assert broker.BrokerClient(configure()).evaluate(context()).degraded
    assert not sent


def test_local_broker_rejects_unmatched_endpoint_before_dispatch(monkeypatch):
    import asyncio

    from jev_reflex import broker

    client_config = configure(local_base_url="http://127.0.0.1:11435")
    calls = []
    service = broker.BrokerServer(
        configure(local_base_url="http://127.0.0.1:11436"),
        evaluator=SimpleNamespace(evaluate=lambda state: calls.append(state)),
    )

    def request(operation, **fields):
        async def handle():
            reader = asyncio.StreamReader()
            reader.feed_data(
                broker.encode(
                    dict(protocol_version=1, request_id="req", operation=operation, **fields)
                )
            )
            response = []

            async def drain():
                pass

            await service.handle(
                reader,
                SimpleNamespace(
                    get_extra_info=lambda _: None,
                    write=response.append,
                    drain=drain,
                    close=lambda: None,
                ),
            )
            return json.loads(response[0])

        return asyncio.run(handle())

    client = broker.BrokerClient(client_config)
    monkeypatch.setattr(client, "request", request)
    assert client.evaluate(context()).degraded
    assert not calls


def test_cli_import_and_no_jev_do_not_load_ml(tmp_path):
    (tmp_path / "reflex.yaml").write_text("evaluator:\n  provider: local\n")
    script = """
import sys
from jev_reflex.cli import app
from typer.testing import CliRunner
blocked = {'onnxruntime', 'numpy', 'tokenizers', 'huggingface_hub'}
assert blocked.isdisjoint(sys.modules)
result = CliRunner().invoke(app, ['check', '--no-jev', '--command', 'git status'])
assert result.exit_code == 0, result.output
assert blocked.isdisjoint(sys.modules)
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env={**os.environ, "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_active_question_window_is_verified_before_loading_graph(runtime):
    result = evaluate_context(context(), config=configure(max_tokens=10))
    assert result.degraded and result.signals == {}
    assert runtime.sessions == 0


def test_required_audit_failure_publishes_only_final_advisory_decision(tmp_path, monkeypatch):
    from jev_reflex import evaluator
    from jev_reflex.audit import AuditLog

    events = []

    def fail_audit(self, **kwargs):
        events.append(("audit", kwargs["policy_decision"].decision))
        raise OSError("fixture failure")

    def log(*, event, fields, **kwargs):
        if event == "policy_decision":
            events.append(("log", fields["decision"], fields["degraded"]))

    monkeypatch.setattr(AuditLog, "write_entry", fail_audit)
    monkeypatch.setattr(evaluator, "log_structured", log)
    monkeypatch.setattr(
        evaluator.decisions_total,
        "inc",
        lambda **labels: events.append(("count", labels["decision"])),
    )
    monkeypatch.setattr(
        evaluator.degraded_evaluations_total,
        "inc",
        lambda **labels: events.append(("degraded", labels["reason"])),
    )
    config = ReflexConfig(
        mode="advisory",
        audit={"enabled": True, "fail_closed": True, "path": str(tmp_path / "audit")},
    )
    result = evaluate_context(context(), config=config, use_jev=False)
    assert result.decision == "HOLD" and result.degraded
    assert events == [
        ("audit", "ALLOW"),
        ("count", "HOLD"),
        ("degraded", "audit_unavailable"),
        ("log", "HOLD", True),
    ]


def test_mixed_samples_record_every_contributor_in_audit(tmp_path):
    from jev_reflex.audit import AuditLog

    other = "b" * 64
    samples = iter(
        [
            SemanticSignals(source="local", model_digest=DIGEST, risk=RiskInfo(choice="low")),
            SemanticSignals(source="local", model_digest=other, risk=RiskInfo(choice="low")),
            SemanticSignals(source="jev", risk=RiskInfo(choice="low")),
        ]
    )
    audit = tmp_path / "audit.jsonl"
    config = ReflexConfig(audit={"enabled": True, "path": str(audit)})
    result = evaluate_context(
        context(),
        config=config,
        samples=3,
        semantic_evaluator=SimpleNamespace(evaluate=lambda _: next(samples)),
    )
    assert result.semantic_source == "hybrid" and result.model_digest is None
    entry = json.loads(audit.read_text())
    assert entry["source"] == "hybrid" and entry.get("model_digest") is None
    assert entry["semantic_contributors"] == [
        {"source": "local", "model_digest": DIGEST},
        {"source": "local", "model_digest": other},
        {"source": "jev"},
    ]
    assert AuditLog(config).verify()[0]


def test_hybrid_broker_checks_bounds_and_round_trips_mixed_models(monkeypatch):
    from jev_reflex.broker import BrokerClient
    from jev_reflex.local_evaluator import LocalSemanticEvaluator
    from test_broker import running_broker

    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only")
    config = configure(provider="hybrid", local_base_url="http://127.0.0.1:11435")
    config.hold_on.append("goal_hijack_diff")
    calls = []
    local = LocalSemanticEvaluator(
        config,
        fallback=SimpleNamespace(
            evaluate=lambda _: SemanticSignals(
                probabilities={"prompt_injection": 0.05}, risk=RiskInfo(choice="low")
            )
        ),
    )

    def score(ctx):
        calls.append(ctx)
        return SemanticSignals(
            source="local",
            model_digest=DIGEST,
            risk=RiskInfo(choice="low"),
            probabilities={"prompt_injection": 0.5, "goal_hijack_diff": 0.99},
        )

    monkeypatch.setattr(local, "_evaluate_local", score)
    state = context().model_copy(update={"git_diff": "+more text"})
    with running_broker(evaluator=local, config=config) as (broker, _):
        for change in ({"hybrid_uncertain_low": 0.25}, {"hybrid_uncertain_high": 0.75}):
            mismatched = broker.model_copy(
                update={"evaluator": broker.evaluator.model_copy(update=change)}
            )
            assert BrokerClient(mismatched).evaluate(state).degraded
        assert not calls
        result = BrokerClient(broker).evaluate(state)
    assert len(calls) == 1 and not result.degraded
    assert result.source == "hybrid" and result.model_digest is None
    assert {(item.source, item.model_digest) for item in result.contributors} == {
        ("local", DIGEST),
        ("jev", None),
    }
