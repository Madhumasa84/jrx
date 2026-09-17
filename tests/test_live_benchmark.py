from jev_reflex.config import ReflexConfig
from jev_reflex.evaluator import DemoSemanticEvaluator
from jev_reflex.live_benchmark import FIXTURES, run_benchmark, summarize


def test_benchmark_reproducible_metrics_without_context():
    config = ReflexConfig()
    report = run_benchmark(config, 3, evaluator=DemoSemanticEvaluator(config))
    assert report["total_cases"] == 19
    assert report["completed_evaluations"] == 57
    assert report["summary"] == summarize(report["rows"])
    for arm in report["summary"]["arms"].values():
        assert arm["final_decision_consistency"] == 1
        assert arm["decision_flip_rate"] == 0
    for row in report["rows"]:
        assert "command" not in row and "git_diff" not in row and "context" not in row
    assert {fixture[2] for fixture in FIXTURES} == {"ALLOW", "REVIEW", "HOLD"}


def test_known_flip_and_false_decision_metrics():
    config = ReflexConfig()
    report = run_benchmark(
        config, 2, evaluator=DemoSemanticEvaluator(config), cases=["dependency-upgrade"]
    )
    rows = report["rows"]
    rows[0]["combined"] = "ALLOW"
    rows[1]["combined"] = "HOLD"
    rows[0]["signals"]["needs_tests"] = 0.69
    rows[1]["signals"]["needs_tests"] = 0.71
    summary = summarize(rows)
    assert summary["arms"]["combined"] == {
        "final_decision_consistency": 0.5,
        "decision_flip_rate": 1,
        "accuracy": 0,
        "false_allow_rate": 0.5,
        "false_hold_rate": 0.5,
    }
    stats = summary["signals"]["dependency-upgrade"]["needs_tests"]
    assert stats["threshold_crossings"]["review"]["rate"] == 1
    assert abs(stats["variance"] - 0.0001) < 1e-10


def test_benchmark_cli_artifact_and_no_overwrite(tmp_path, monkeypatch):
    import json

    from typer.testing import CliRunner

    from jev_reflex.cli import app

    monkeypatch.setattr("jev_reflex.live_benchmark.semantic_backend", DemoSemanticEvaluator)
    output = tmp_path / "results.json"
    args = [
        "benchmark",
        "live",
        "--runs",
        "2",
        "--case",
        "dependency-upgrade",
        "--output",
        str(output),
    ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.stdout
    report = json.loads(output.read_text())
    assert report["summary"] == summarize(report["rows"])
    assert report["completed_evaluations"] == 2
    assert report["summary"]["api_request_count"] == 0
    assert CliRunner().invoke(app, args).exit_code == 2
