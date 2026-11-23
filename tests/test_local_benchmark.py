import json
import os
import platform
import resource
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from benchmarks import run
from benchmarks.datasets import CommandCase, CommandInput
from benchmarks.harnesses import evaluation, latency

from jev_reflex import redaction
from onnx_runtime_fixture import DIGEST, install_runtime


def synthetic_cases():
    common = {
        "surface": "command",
        "split": "eval",
        "notes": "Synthetic benchmark control.",
    }
    return [
        CommandCase(
            **common,
            id="synthetic_benign",
            input=CommandInput(command="git status", cwd="."),
            suite="benign_dev",
            owasp_asi=None,
            attack_family="synthetic_benign",
            expected_min_decision="ALLOW",
            expected_signals=[],
        ),
        CommandCase(
            **common,
            id="synthetic_risk",
            input=CommandInput(command="git status", cwd=".", external_content="SYNTHETIC_RISK"),
            suite="owasp_asi",
            owasp_asi="ASI01",
            attack_family="synthetic_risk",
            expected_min_decision="HOLD",
            expected_signals=["prompt_injection"],
        ),
    ]


@pytest.mark.parametrize(
    ("backend", "warm_mode"), [("local", "warm_in_process"), ("local-broker", "warm_broker")]
)
def test_local_runner_and_report(backend, warm_mode, monkeypatch, tmp_path):
    cases = synthetic_cases()
    hashes = {"synthetic.jsonl": "a" * 64}

    def load_datasets(directory, *, verify):
        assert verify is True
        return cases, hashes

    def historical_reports():
        result = {"splits": {"eval": evaluation.summarize([(case, "ALLOW") for case in cases])}}
        report = {"evaluation": result, "latency": None, "environment": {"dataset_sha256": hashes}}
        return report, report

    model_cache = tmp_path / "synthetic-model-cache"
    model_cache.mkdir()
    if backend == "local":
        install_runtime(monkeypatch, model_cache, risk_text="SYNTHETIC_RISK")
    else:
        (tmp_path / "sitecustomize.py").write_text(
            "from pathlib import Path\n"
            "from pytest import MonkeyPatch\n"
            "from onnx_runtime_fixture import install_runtime\n"
            f"install_runtime(MonkeyPatch(), Path({str(model_cache)!r}), risk_text='SYNTHETIC_RISK')\n",
            encoding="utf-8",
        )

    def start_broker(command, **options):
        options["env"]["PYTHONPATH"] = os.pathsep.join(
            (str(tmp_path), str(Path(__file__).resolve().parent))
        )
        return subprocess.Popen(command, **options)

    def measured_latency(backend, workspace, environment, *, backend_name):
        health = backend.evaluator.health()
        if backend_name == "local-broker":
            assert health["jev_configured"] is False
            assert stat.S_IMODE(Path(health["socket"]).stat().st_mode) == 0o600
        status = health.get("local_evaluator", health)
        assert status["warm"] and status["inference_count"] == len(cases)
        measured = latency.measure_latency(
            backend, workspace, environment, backend_name=backend_name
        )
        health = backend.evaluator.health()
        status = health.get("local_evaluator", health)
        assert status["inference_count"] == len(cases) + latency.WARMUPS + latency.ITERATIONS
        assert status["inference_latency_ms"] > 0
        return measured

    monkeypatch.setenv("TYPESAFE_API_KEY", "synthetic-should-be-cleared")
    monkeypatch.setattr(redaction, "_GITLEAKS_AVAILABLE", True)
    host_redactor = redaction.GitleaksRedactor()
    monkeypatch.setattr(redaction, "_gitleaks_redactor", host_redactor)
    monkeypatch.setattr(run, "load_datasets", load_datasets)
    monkeypatch.setattr(run, "historical_reports", historical_reports)
    monkeypatch.setattr(run, "default_model_dir", lambda: model_cache)
    monkeypatch.setattr(evaluation, "Popen", start_broker)
    monkeypatch.setattr(resource, "getrusage", lambda _: SimpleNamespace(ru_maxrss=0))
    monkeypatch.setattr(latency, "WARMUPS", 1)
    monkeypatch.setattr(latency, "ITERATIONS", 2)
    monkeypatch.setattr(run, "measure_latency", measured_latency)

    output = tmp_path / "report.json"
    summary = tmp_path / "report.md"
    assert (
        run.main(
            [
                "--backend",
                backend,
                "--verify-hashes",
                "--out",
                str(output),
                "--render-md",
                str(summary),
            ]
        )
        == 0
    )
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["backend"] == backend
    assert report["model"]["sha256"] == DIGEST
    assert report["environment"]["dataset_sha256"] == hashes
    assert report["evaluation"]["cases"] == [
        {"id": "synthetic_benign", "decision": "ALLOW"},
        {"id": "synthetic_risk", "decision": "HOLD"},
    ]
    assert report["latency"][warm_mode]["p50_ms"] > 0
    assert report["latency"]["cold_cli"]["p50_ms"] > 0
    markdown = summary.read_text(encoding="utf-8")
    assert (
        "| Metric | v0.2.0 deterministic | Step 3 deterministic | Step 3 + local ONNX (coba-68m-ternary) |"
        in markdown
    )
    assert "| ASI01 recall | 0.00% (0/1)" in markdown
    assert "100.00% (1/1)" in markdown
    if backend == "local-broker":
        assert "| Warm broker p50 / p95 | — | — |" in markdown
        peak_rss = report["latency"]["warm_broker"]["peak_rss_mb"]
        if platform.system() == "Linux":
            assert peak_rss > 0
        else:
            assert peak_rss is None
    assert str(tmp_path) not in output.read_text(encoding="utf-8")
    assert redaction._gitleaks_redactor is host_redactor
