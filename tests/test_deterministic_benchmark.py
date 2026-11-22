import copy
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from benchmarks.datasets import ASI_CATEGORIES, CASE_SCHEMA, DATASETS, load_datasets, read_cases
from benchmarks.harnesses.evaluation import intervention_delta, rate, wilson_95
from benchmarks.reporting import regressions
from benchmarks.run import DATASET_DIRECTORY
from pydantic import ValidationError

ROOT = DATASET_DIRECTORY.parents[1]
BASELINE = ROOT / "benchmarks" / "results" / "v0.2.0-deterministic.json"


def test_dataset_coverage_and_holdout():
    cases, hashes = load_datasets(DATASET_DIRECTORY, verify=True)
    assert set(hashes) == DATASETS.keys()
    assert len({case.id for case in cases}) == len(cases)
    assert Counter(case.suite for case in cases) == {
        "benign_dev": 120,
        "owasp_asi": 120,
        "bypass_obfuscation": 60,
    }
    clean = [case for case in cases if case.suite == "owasp_asi"]
    assert Counter(case.owasp_asi for case in clean) == dict.fromkeys(ASI_CATEGORIES, 20)
    for group in [
        *([case for case in cases if case.suite == suite] for suite in DATASETS.values()),
        *([case for case in clean if case.owasp_asi == category] for category in ASI_CATEGORIES),
        *(
            [case for case in cases if case.attack_family == name]
            for name in {c.attack_family for c in cases}
        ),
    ]:
        holdout = sum(case.split == "eval" for case in group)
        assert 5 * holdout >= 2 * len(group)
        assert holdout < len(group)
    assert {case.surface for case in cases} == {"command", "stdin_diff", "mcp_call"}


@pytest.mark.parametrize(
    "changes",
    [
        {"extra": True},
        {"surface": "stdin_diff"},
        {"expected_min_decision": "REVIEW"},
        {"owasp_asi": "ASI07"},
        {"expected_signals": "none"},
        {"id": "../outside"},
        {"input": {"command": "git status", "cwd": "/absolute"}},
        {"input": {"command": "git status", "cwd": "../../outside"}},
        {"input": {"command": "git status", "cwd": ".", "unrecognized": True}},
        {
            "surface": "mcp_call",
            "input": {"server": "fixture", "tool": "inspect", "arguments": ["not", "an", "object"]},
        },
    ],
)
def test_schema_rejects_invalid_cases(changes):
    source = (DATASET_DIRECTORY / "benign_dev_v1.jsonl").read_text(encoding="utf-8")
    row = json.loads(source.splitlines()[0])
    with pytest.raises(ValidationError):
        CASE_SCHEMA.validate_python(row | changes)


def test_jsonl_rejects_duplicate_members_and_blank_lines():
    name = "benign_dev_v1.jsonl"
    first_row = (DATASET_DIRECTORY / name).read_bytes().splitlines()[0]
    with pytest.raises(ValueError, match="line 1"):
        read_cases(name, b'{"id":"duplicate",' + first_row[1:])
    with pytest.raises(ValueError, match="line 2"):
        read_cases(name, first_row + b"\n\n")


def test_checksum_verification_and_duplicate_id_detection():
    with TemporaryDirectory() as directory:
        copy_dir = Path(directory) / "datasets"
        shutil.copytree(DATASET_DIRECTORY, copy_dir)
        dataset = copy_dir / "benign_dev_v1.jsonl"
        with dataset.open("ab") as handle:
            handle.write(dataset.read_bytes().splitlines()[0] + b"\n")
        with pytest.raises(ValueError, match="dataset checksum mismatch: benign_dev_v1.jsonl"):
            load_datasets(copy_dir, verify=True)
        with pytest.raises(ValueError, match="IDs must be globally unique"):
            load_datasets(copy_dir, verify=False)


@pytest.mark.parametrize(
    ("count", "total", "expected"),
    [
        (0, 10, (0.0, 0.2775327998628892)),
        (5, 10, (0.236593090512564, 0.763406909487436)),
        (10, 10, (0.7224672001371107, 1.0)),
        (1, 100, (0.00176743206414065, 0.0544861961787053)),
    ],
)
def test_wilson_intervals(count, total, expected):
    assert wilson_95(count, total) == pytest.approx(expected, abs=1e-12)


def test_rate_edge_cases_and_recall_delta():
    assert wilson_95(0, 0) is None
    with pytest.raises(ValueError):
        wilson_95(3, 2)
    delta = intervention_delta(rate(0, 10), rate(10, 10))
    assert delta["clean_minus_obfuscated"] == -1
    assert delta["newcombe_95"] == pytest.approx((-1, -0.6075094489741269))


def test_offline_reports_are_sanitized_and_match_baseline():
    with TemporaryDirectory() as directory:
        scratch = Path(directory)
        private_home = scratch / "benchmark-private-user"
        private_home.mkdir()
        env = os.environ | {
            "HOME": str(private_home),
            "USERNAME": private_home.name,
            "HOSTNAME": "benchmark-private-hostname",
            "TYPESAFE_API_KEY": "benchmark-private-key",
        }
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "benchmarks" / "run.py"),
                "--verify-hashes",
                "--skip-latency",
                "--out",
                "run.json",
                "--render-md",
                "run.md",
                "--baseline",
                str(BASELINE),
                "--fail-on-regression",
            ],
            cwd=scratch,
            env=env,
            capture_output=True,
            check=True,
            timeout=25,
        )
        assert b"No holdout Hard FPR or attack recall regression." in completed.stdout
        json_report = (scratch / "run.json").read_text(encoding="utf-8")
        markdown = (scratch / "run.md").read_text(encoding="utf-8")
        report = json.loads(json_report)
        assert report["latency"] is None
        assert set(report["environment"]) == {
            "os",
            "python_version",
            "cpu_logical_count",
            "jrx_version",
            "dataset_sha256",
            "redaction",
        }
        assert set(report["evaluation"]["cases"][0]) == {"id", "decision"}
        for private in (
            str(scratch),
            str(ROOT),
            private_home.name,
            env["HOSTNAME"],
            env["TYPESAFE_API_KEY"],
            "/home/",
            "/Users/",
        ):
            assert private not in json_report
            assert private not in markdown


def test_regression_detection_checks_exact_counts_and_asi_cohorts():
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    report = copy.deepcopy(baseline)
    metrics = report["evaluation"]["splits"]["eval"]
    metrics["benign"]["hard_fpr"]["count"] += 1
    metrics["attack"]["clean_by_asi"]["ASI02"]["intervention"]["count"] -= 1
    failures = regressions(report, baseline)
    assert [failure.split(" changed")[0] for failure in failures] == ["Hard FPR", "ASI02 recall"]
    report["environment"]["dataset_sha256"]["benign_dev_v1.jsonl"] = "0" * 64
    with pytest.raises(ValueError, match="same artifact version, backend, and dataset hashes"):
        regressions(report, baseline)
