from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from jev_reflex import model_files
from jev_reflex.cli import app
from jev_reflex.model_files import PinnedModel
from onnx_runtime_fixture import install_runtime

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
def hf(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    downloads: list[str] = []
    payloads = {name: name.encode() for name in FILES}
    runtime_path = tmp_path / "hub-fixture"
    runtime_path.mkdir()
    verified = install_runtime(monkeypatch, runtime_path, stub_verification=False).verified
    payloads.update(
        {
            FILES[0]: verified.graph.read_bytes(),
            FILES[1]: verified.tokenizer.read_bytes(),
            FILES[2]: verified.calibration.read_bytes(),
            FILES[3]: verified.decision.read_bytes(),
        }
    )
    siblings = [SimpleNamespace(rfilename=name, lfs=None) for name in (*FILES, "model.safetensors")]
    siblings[0].lfs = SimpleNamespace(sha256=hashlib.sha256(payloads[FILES[0]]).hexdigest())
    info = SimpleNamespace(sha=REVISION, siblings=siblings)

    def model_info(repo_id, *, revision=None, files_metadata, token):
        assert repo_id == MODEL_ID and files_metadata and token is False
        assert revision in {None, info.sha}
        return info

    class HubPin(Mapping):
        """Pin the fake hub's current commit and bytes, as a jrx release would.

        These tests exercise cache mechanics; test_review_broker_models.py covers
        a hub that disagrees with the pinned release.
        """

        def __getitem__(self, model_id):
            if model_id != MODEL_ID:
                raise KeyError(model_id)
            return PinnedModel(
                revision=info.sha,
                sha256={name: hashlib.sha256(payloads[name]).hexdigest() for name in FILES},
            )

        def __iter__(self):
            return iter((MODEL_ID,))

        def __len__(self):
            return 1

    monkeypatch.setattr(model_files, "PINNED_MODELS", HubPin())

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
    assert model["size_bytes"] == sum(map(len, hf.payloads.values()))
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
    assert installed.read_asset(installed.graph) == hf.payloads[FILES[0]]
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
    assert runtime.sessions == 2  # Staged compatibility check and evaluation.

    installed.graph.write_bytes(b"tampered")
    result = evaluate_context(ctx, config=config)
    assert result.degraded
    assert _check_exit_code(result, config) == 2
    assert any("jrx model pull" in warning for warning in result.warnings)
    assert runtime.sessions == 2


@pytest.mark.parametrize("name", FILES[1:4])
def test_pull_repairs_cached_sidecar_that_disagrees_with_hub(model_home, hf, name):
    from jev_reflex.model_files import pull_model

    original = pull_model(MODEL_ID, model_home)
    snapshot = original.tokenizer.parent
    path = snapshot / name
    path.write_bytes(hf.payloads[name] + b"\n")
    manifest_path = snapshot.parent / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["sha256"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    sibling = next(item for item in hf.info.siblings if item.rfilename == name)
    sibling.lfs = SimpleNamespace(sha256=hashlib.sha256(hf.payloads[name]).hexdigest())

    repaired = pull_model(MODEL_ID, model_home)
    assert repaired.tokenizer.parent != snapshot
    assert repaired.read_asset(repaired.tokenizer.parent / name) == hf.payloads[name]
    assert repaired.digest == original.digest


def test_sidecar_update_changes_bundle_digest(model_home, hf):
    from jev_reflex.model_files import pull_model, verify_model

    original = pull_model(MODEL_ID, model_home)
    hf.info.sha = "b" * 40
    hf.payloads["calibration.json"] = b'{"temperature":[1,1,2]}'
    updated = pull_model(MODEL_ID, model_home)
    assert original.graph.read_bytes() == updated.graph.read_bytes()
    assert original.digest != updated.digest == verify_model(MODEL_ID, model_home).digest
    status = runner.invoke(app, ["model", "status", "--json"])
    assert json.loads(status.stdout)["models"][0]["model_digest"] == updated.digest


def test_pull_preserves_working_snapshot_when_new_bundle_cannot_load(model_home, hf):
    from jev_reflex.model_files import pull_model, verify_model

    installed = pull_model(MODEL_ID, model_home)
    manifest = model_home / MODEL_ID / "manifest.json"
    previous = manifest.read_bytes()
    decision = hf.payloads["decision.json"]
    hf.info.sha = "b" * 40
    hf.payloads["decision.json"] = b'{"engine":"unsupported"}'
    result = runner.invoke(app, ["model", "pull"])
    assert result.exit_code == 1
    assert "runtime compatibility check" in result.output
    assert manifest.read_bytes() == previous
    # The preserved snapshot verifies against the release it was pinned to.
    hf.info.sha = REVISION
    hf.payloads["decision.json"] = decision
    assert verify_model(MODEL_ID, model_home).digest == installed.digest
    assert list(manifest.parent.glob("snapshot-*")) == [installed.tokenizer.parent]


def test_snapshot_gc_preserves_other_process_reader_and_legacy_cache(model_home, hf):
    import subprocess

    from jev_reflex.model_files import pull_model, verify_model

    original = pull_model(MODEL_ID, model_home)
    snapshot = original.tokenizer.parent
    del original
    legacy = snapshot.parent / f"snapshot-{'f' * 32}"
    legacy.mkdir()
    script = (
        "import sys\n"
        "from jev_reflex import model_files\n"
        "from jev_reflex.model_files import verify_model\n"
        "model_files.PINNED_MODELS = {}  # The fake bundle is not the pinned release.\n"
        "snapshot = verify_model(*sys.argv[1:])\n"
        "print('ready', flush=True)\n"
        "sys.stdin.readline()\n"
        "assert snapshot.read_asset(snapshot.graph) == b'onnx'\n"
    )
    with subprocess.Popen(
        [sys.executable, "-B", "-c", script, MODEL_ID, str(model_home)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    ) as reader:
        assert reader.stdout is not None and reader.stdout.readline() == b"ready\n"
        hf.info.sha = "b" * 40
        second = pull_model(MODEL_ID, model_home).tokenizer.parent
        assert snapshot.is_dir() and second.is_dir()
        reader.communicate(b"finished\n", timeout=5)
        assert reader.returncode == 0

    hf.info.sha = "c" * 40
    active = pull_model(MODEL_ID, model_home)
    assert not snapshot.exists() and not second.exists()
    assert legacy.is_dir()
    assert active.tokenizer.parent.is_dir()
    assert verify_model(MODEL_ID, model_home).revision == "c" * 40


def test_live_broker_recovers_after_model_pull(model_home, hf, monkeypatch):
    from jev_reflex import local_evaluator
    from jev_reflex.broker import BrokerClient
    from jev_reflex.config import ReflexConfig
    from jev_reflex.local_evaluator import LocalSemanticEvaluator
    from jev_reflex.metrics import get_registry
    from test_broker import context, running_broker

    now = [100.0]
    monkeypatch.setattr(local_evaluator, "time", SimpleNamespace(monotonic=lambda: now[0]))
    config = ReflexConfig(
        evaluator={"provider": "local", "model_dir": str(model_home)},
        jev={"transport": "broker"},
    )
    local = LocalSemanticEvaluator(config)
    with running_broker(evaluator=local, config=config) as (broker_config, _):
        client = BrokerClient(broker_config)
        assert not client.health()["local_evaluator"]["warm"]
        assert client.evaluate(context("git status")).degraded
        pulled = runner.invoke(app, ["model", "pull"])
        assert pulled.exit_code == 0, pulled.output
        assert client.evaluate(context("git status")).degraded  # Wait for the retry deadline.
        now[0] += 1
        result = client.evaluate(context("git status"))
        health = client.health()["local_evaluator"]
        assert not result.degraded and result.model_digest == health["model_digest"]
        assert health["warm"] and "warning" not in health
        assert f'model_digest="{result.model_digest}"' in get_registry().render()


def test_legacy_manifest_is_readable_and_reused(model_home, hf):
    from jev_reflex.model_files import pull_model, verify_model

    model = pull_model(MODEL_ID, model_home)
    snapshot = model.tokenizer.parent
    digest = model.digest
    del model
    manifest_path = snapshot.parent / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest.update(version=1, generation=f"snapshot-{'a' * 32}")
    legacy = snapshot.rename(snapshot.parent / manifest["generation"])
    manifest_path.write_text(json.dumps(manifest))
    assert verify_model(MODEL_ID, model_home).digest == digest
    pulled = pull_model(MODEL_ID, model_home)
    assert pulled.tokenizer.parent == legacy
    assert hf.downloads == list(FILES)
