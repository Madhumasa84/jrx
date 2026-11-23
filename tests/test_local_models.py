from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from jev_reflex.cli import app

MODEL_ID = "ollaya-dev/coba-68m-ternary"
REVISION = "a" * 40
FILES = (
    "onnx/model.onnx",
    "tokenizer.json",
    "calibration.json",
    "decision.json",
    "LICENSE",
    "NOTICE",
)
runner = CliRunner()


@pytest.fixture
def model_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path / ".jev-reflex" / "models"


@pytest.fixture
def hf(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    downloads: list[str] = []
    payloads = {name: name.encode() for name in FILES}
    siblings = [SimpleNamespace(rfilename=name, lfs=None) for name in (*FILES, "model.safetensors")]
    siblings[0].lfs = SimpleNamespace(sha256=hashlib.sha256(FILES[0].encode()).hexdigest())
    info = SimpleNamespace(sha=REVISION, siblings=siblings)

    def model_info(repo_id, *, files_metadata, token):
        assert repo_id == MODEL_ID and files_metadata and token is False
        return info

    def hf_hub_download(*, repo_id, filename, revision, local_dir, token):
        assert repo_id == MODEL_ID and revision == info.sha and token is False
        assert filename in FILES
        path = Path(local_dir) / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payloads[filename])
        downloads.append(filename)
        return str(path)

    module = SimpleNamespace(
        HfApi=lambda: SimpleNamespace(model_info=model_info),
        hf_hub_download=hf_hub_download,
        downloads=downloads,
        info=info,
        payloads=payloads,
    )
    monkeypatch.setitem(sys.modules, "huggingface_hub", module)
    return module


def test_pull_status_verify_and_repair(model_home: Path, hf: SimpleNamespace) -> None:
    result = runner.invoke(app, ["model", "pull", "coba-68m-ternary"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert sorted(hf.downloads) == sorted(FILES)
    result = runner.invoke(app, ["model", "status", "--json"])
    assert result.exit_code == 0, (result.output, result.exception)
    report = json.loads(result.stdout)
    assert isinstance(report["onnxruntime_available"], bool)
    model = report["models"][0]
    assert model["model_id"] == MODEL_ID
    assert model["verified"] is True
    assert model["size_bytes"] == sum(len(name) for name in FILES)
    manifest = model_home / MODEL_ID / "manifest.json"
    assert model["manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert runner.invoke(app, ["model", "verify"]).exit_code == 0

    (graph,) = manifest.parent.glob("*/onnx/model.onnx")
    graph.write_bytes(b"tampered")
    result = runner.invoke(app, ["model", "verify"])
    assert result.exit_code == 1
    assert "SHA-256 mismatch" in result.output
    result = runner.invoke(app, ["model", "status", "--json"])
    assert json.loads(result.stdout)["models"][0]["verified"] is False
    assert runner.invoke(app, ["model", "pull"]).exit_code == 0
    assert runner.invoke(app, ["model", "verify"]).exit_code == 0


def test_failed_download_is_never_published(model_home: Path, hf: SimpleNamespace) -> None:
    hf.info.siblings[0].lfs.sha256 = "0" * 64
    result = runner.invoke(app, ["model", "pull"])
    assert result.exit_code == 1
    assert "SHA-256 mismatch" in result.output
    assert not (model_home / MODEL_ID / "manifest.json").exists()
    result = runner.invoke(app, ["model", "status", "--json"])
    assert json.loads(result.stdout)["models"] == []


def test_failed_update_preserves_previous_model(model_home: Path, hf: SimpleNamespace) -> None:
    assert runner.invoke(app, ["model", "pull"]).exit_code == 0
    manifest = model_home / MODEL_ID / "manifest.json"
    previous = manifest.read_bytes()

    hf.info.sha = "b" * 40
    hf.info.siblings[0].lfs.sha256 = "0" * 64
    result = runner.invoke(app, ["model", "pull"])
    assert result.exit_code == 1
    assert manifest.read_bytes() == previous
    assert runner.invoke(app, ["model", "verify"]).exit_code == 0


def test_pull_rechecks_the_pinned_graph_digest_before_reusing_an_installation(model_home, hf):
    from jev_reflex.model_files import pull_model

    installed = pull_model(MODEL_ID, model_home)
    manifest_path = model_home / MODEL_ID / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    replacement = b"changed graph"
    installed.graph.write_bytes(replacement)
    manifest["sha256"][FILES[0]] = hashlib.sha256(replacement).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    repaired = pull_model(MODEL_ID, model_home)
    assert repaired.read_asset(repaired.graph) == hf.payloads[FILES[0]]


def test_manifest_path_escape_is_rejected(model_home: Path, hf: SimpleNamespace) -> None:
    result = runner.invoke(app, ["model", "pull"])
    assert result.exit_code == 0, (result.output, result.exception)
    manifest = model_home / MODEL_ID / "manifest.json"
    data = json.loads(manifest.read_bytes())
    data["generation"] = "../../../outside"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    verify = runner.invoke(app, ["model", "verify"])
    assert verify.exit_code == 1
    assert "invalid manifest" in verify.output


def test_consumed_model_bytes_are_verified_against_the_loaded_manifest(model_home, hf):
    from jev_reflex.model_files import ModelError, pull_model

    installed = pull_model(MODEL_ID, model_home)
    assert installed.read_asset(installed.graph) == FILES[0].encode()
    installed.graph.write_bytes(b"unverified replacement")
    with pytest.raises(ModelError, match="changed after verification"):
        installed.read_asset(installed.graph)


@pytest.mark.parametrize("component", ["namespace", "model", "snapshot", "onnx"])
def test_model_runtime_rejects_replaced_parent_directories(model_home, hf, tmp_path, component):
    from jev_reflex.model_files import ModelError, pull_model

    installed = pull_model(MODEL_ID, model_home)
    directory = {
        "namespace": installed.graph.parents[3],
        "model": installed.graph.parents[2],
        "snapshot": installed.graph.parents[1],
        "onnx": installed.graph.parent,
    }[component]
    outside = tmp_path / "outside"
    directory.rename(outside)
    directory.symlink_to(outside, target_is_directory=True)

    # Identical bytes at another location do not make that location part of the cache.
    with pytest.raises(ModelError):
        installed.read_asset(installed.graph)


def test_model_verification_refuses_symlinked_cache_root(model_home, hf, tmp_path):
    from jev_reflex.model_files import ModelError, pull_model, verify_model

    pull_model(MODEL_ID, model_home)
    outside = tmp_path / "outside"
    model_home.rename(outside)
    model_home.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ModelError):
        verify_model(MODEL_ID, model_home)


@pytest.mark.parametrize("entry", ["root", "manifest"])
def test_model_verification_refuses_group_writable_cache_entries(model_home, hf, entry):
    from jev_reflex.model_files import ModelError, pull_model, verify_model

    pull_model(MODEL_ID, model_home)
    entry_path = model_home if entry == "root" else model_home / MODEL_ID / "manifest.json"
    entry_path.chmod(entry_path.stat().st_mode | 0o020)
    with pytest.raises(ModelError):
        verify_model(MODEL_ID, model_home)


def test_enforce_fails_closed_when_installed_graph_is_tampered(
    model_home, hf, tmp_path, monkeypatch
):
    from jev_reflex import local_evaluator as local
    from jev_reflex.cli import _check_exit_code
    from jev_reflex.config import ReflexConfig
    from jev_reflex.evaluator import evaluate_context
    from jev_reflex.model_files import pull_model, verify_model
    from jev_reflex.models import EvaluationContext, ProposedAction
    from onnx_runtime_fixture import install_runtime

    runtime = install_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(local, "verify_model", verify_model)
    hf.payloads.update(
        {
            "onnx/model.onnx": runtime.verified.graph.read_bytes(),
            "tokenizer.json": runtime.verified.tokenizer.read_bytes(),
            "decision.json": runtime.verified.decision.read_bytes(),
            "calibration.json": runtime.verified.calibration.read_bytes(),
        }
    )
    hf.info.siblings[0].lfs.sha256 = hashlib.sha256(hf.payloads[FILES[0]]).hexdigest()
    installed = pull_model(MODEL_ID, model_home)
    config = ReflexConfig.model_validate(
        {
            "mode": "enforce",
            "evaluator": {"provider": "local", "model_dir": str(model_home)},
            "hold_on": ["prompt_injection"],
            "review_on": [],
        }
    )
    ctx = EvaluationContext(
        proposed_action=ProposedAction(command="git status"),
        external_content="Repository context supplied by an integration.",
    )
    assert not evaluate_context(ctx, config=config).degraded
    assert runtime.sessions == 1

    installed.graph.write_bytes(b"tampered")
    result = evaluate_context(ctx, config=config)
    assert result.degraded
    assert _check_exit_code(result, config) == 2
    assert any("jrx model pull" in warning for warning in result.warnings)
    assert runtime.sessions == 1
