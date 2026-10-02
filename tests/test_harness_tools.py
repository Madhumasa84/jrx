"""Security boundaries and stale-write checks for harness workspace tools."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("langchain_core")

from jev_reflex.config import ReflexConfig, SandboxConfig  # noqa: E402
from jev_reflex.workspace import harness_tools as module  # noqa: E402


def make_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **kwargs):
    captured = []

    def evaluate(_self, context):
        captured.append(context)
        return SimpleNamespace(degraded=False, decision="REVIEW")

    monkeypatch.setattr(module.DefaultEvaluator, "evaluate", evaluate)
    config = kwargs.pop("config", ReflexConfig())
    tools = module.build_tools(tmp_path, config, "update documentation", "test", **kwargs)
    return {tool.name: tool for tool in tools}, captured


def test_write_read_stale_and_actual_gate(tmp_path, monkeypatch):
    tools, captured = make_tools(tmp_path, monkeypatch)
    write = tools["workspace_write"]
    result = write.invoke({"path": "notes.txt", "content": "first", "expected_sha256": "new"})
    read = tools["workspace_read"].invoke({"path": "notes.txt"})
    assert result["sha256"] == read["sha256"] == hashlib.sha256(b"first").hexdigest()
    assert captured[0].proposed_action.input == {
        "path": str(tmp_path / "notes.txt"),
        "content": "first",
    }
    (tmp_path / "notes.txt").write_text("external change")
    with pytest.raises(ValueError, match="file changed"):
        write.invoke(
            {"path": "notes.txt", "content": "overwrite", "expected_sha256": read["sha256"]}
        )
    assert (tmp_path / "notes.txt").read_text() == "external change"
    assert not list(tmp_path.glob(".jrx-write-*"))


@pytest.mark.parametrize(
    "path",
    [
        "../outside",
        "/etc/passwd",
        ".git/config",
        ".env",
        ".env.local",
        ".codex/config.toml",
        "keys/private_key.txt",
        "server.pem",
    ],
)
def test_sensitive_paths_rejected(tmp_path, monkeypatch, path):
    tools, _ = make_tools(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        tools["workspace_read"].invoke({"path": path})
    with pytest.raises(ValueError):
        tools["workspace_write"].invoke({"path": path, "content": "x", "expected_sha256": "new"})


def test_symlink_parents_leaf_hardlinks_and_listing(tmp_path, monkeypatch):
    tools, _ = make_tools(tmp_path, monkeypatch)
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    (outside / "file").write_text("outside")
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    (tmp_path / "leaf").symlink_to(outside / "file")
    os.link(outside / "file", tmp_path / "hard")
    (tmp_path / ".env").write_text("SECRET=abc")
    (tmp_path / "okay").write_text("okay")
    for path in ("linked/file", "leaf", "hard"):
        with pytest.raises((ValueError, OSError)):
            tools["workspace_read"].invoke({"path": path})
        with pytest.raises((ValueError, OSError)):
            tools["workspace_write"].invoke(
                {"path": path, "content": "bad", "expected_sha256": "new"}
            )
    assert (outside / "file").read_text() == "outside"
    assert tools["workspace_list"].invoke({})["entries"] == [{"name": "okay", "kind": "file"}]


@pytest.mark.parametrize("degraded,decision", [(True, "ALLOW"), (False, "HOLD")])
def test_gate_never_allows_degraded_or_hold(tmp_path, monkeypatch, degraded, decision):
    tools, _ = make_tools(tmp_path, monkeypatch)
    monkeypatch.setattr(
        module.DefaultEvaluator,
        "evaluate",
        lambda *_: SimpleNamespace(
            degraded=degraded, decision=decision, reason_summary=lambda: "blocked"
        ),
    )
    with pytest.raises(PermissionError, match="JRX blocked"):
        tools["workspace_write"].invoke({"path": "file", "content": "x", "expected_sha256": "new"})
    assert not (tmp_path / "file").exists()


def test_disabled_sandbox_and_deadline(tmp_path, monkeypatch):
    calls = []
    tools, _ = make_tools(tmp_path, monkeypatch, before_tool=calls.append)
    with pytest.raises(PermissionError, match="sandbox.enabled"):
        tools["run_command"].invoke({"argv": ["echo", "hello"]})
    assert calls == ["run_command"]
    tools, _ = make_tools(tmp_path, monkeypatch, deadline=time.monotonic() - 1)
    with pytest.raises(TimeoutError):
        tools["workspace_list"].invoke({})


def test_file_limits_and_exclusive_new(tmp_path, monkeypatch):
    tools, _ = make_tools(tmp_path, monkeypatch)
    (tmp_path / "large").write_bytes(b"x" * (module._MAX_FILE + 1))
    with pytest.raises(ValueError, match="1 MiB"):
        tools["workspace_read"].invoke({"path": "large"})
    (tmp_path / "file").write_text("original")
    with pytest.raises(ValueError, match="file changed"):
        tools["workspace_write"].invoke(
            {"path": "file", "content": "bad", "expected_sha256": "new"}
        )
    assert (tmp_path / "file").read_text() == "original"


def test_command_output_bounded_and_cleanup(tmp_path, monkeypatch):
    import sys

    config = ReflexConfig(sandbox=SandboxConfig(enabled=True, image="test-image"))
    tools, captured = make_tools(tmp_path, monkeypatch, config=config)
    cleanup = []
    monkeypatch.setattr(
        module,
        "build_sandbox_command",
        lambda *_: ([sys.executable, "-c", "print('x' * 100000)"], "test-container"),
    )
    monkeypatch.setattr(module, "remove_sandbox_container", lambda *_: cleanup.append("container"))
    result = tools["run_command"].invoke({"argv": ["printf", "hello world"]})
    assert result["returncode"] == 0
    assert result["truncated"] is True
    assert len(result["output"]) <= module._MAX_OUTPUT
    assert captured[0].proposed_action.argv == ["printf", "hello world"]
    assert captured[0].proposed_action.command == "printf 'hello world'"
    assert cleanup == ["container"]


def test_command_timeout_cleanup(tmp_path, monkeypatch):
    import sys

    config = ReflexConfig(sandbox=SandboxConfig(enabled=True, image="test-image"))
    tools, _ = make_tools(tmp_path, monkeypatch, config=config, deadline=time.monotonic() + 0.15)
    cleanup = []
    monkeypatch.setattr(
        module,
        "build_sandbox_command",
        lambda *_: ([sys.executable, "-c", "import time; time.sleep(20)"], "test-container"),
    )
    monkeypatch.setattr(module, "remove_sandbox_container", lambda *_: cleanup.append("container"))
    with pytest.raises(TimeoutError):
        tools["run_command"].invoke({"argv": ["sleep", "20"]})
    assert cleanup == ["container"]
