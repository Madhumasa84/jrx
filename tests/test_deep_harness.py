"""Exercise the actual open-source graph offline, including durable approvals."""

import hashlib
import subprocess

import pytest

pytest.importorskip("deepagents")
pytest.importorskip("langgraph.checkpoint.sqlite")

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage

from jev_reflex.config import ReflexConfig
from jev_reflex.workspace.deep_harness import (
    HarnessBudgetError,
    HarnessSession,
    load_session,
)
from jev_reflex.workspace.state import WorkspaceError


class ScriptedModel(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def call(name, args, identifier="call-1"):
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": identifier}])


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "hello.txt").write_text("before\n")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "base",
        ],
        check=True,
    )
    return root


def session(root, responses, **kwargs):
    return HarnessSession(
        root,
        ReflexConfig(mode="enforce"),
        ScriptedModel(responses=responses),
        model_name="offline:test",
        **kwargs,
    )


def test_plan_persists_without_contacting_provider(workspace):
    graph = session(
        workspace,
        [
            call(
                "write_todos",
                {"todos": [{"content": "Review implementation", "status": "completed"}]},
            ),
            AIMessage(content="Reviewed."),
        ],
    )
    record = graph.run("Inspect the repository")
    assert record["state"] == "completed"
    saved = load_session(workspace, graph.session_id)
    assert saved["todos"][0]["status"] == "completed"
    assert saved["model_calls"] == 2
    assert saved["tool_calls"] == 1
    assert graph.path.stat().st_mode & 0o777 == 0o600
    for path in graph.directory.glob("*.sqlite3"):
        assert path.stat().st_mode & 0o777 == 0o600


def test_edit_pauses_then_rejects_after_restart(workspace):
    checksum = hashlib.sha256(b"before\n").hexdigest()
    graph = session(
        workspace,
        [
            call(
                "workspace_write",
                {"path": "hello.txt", "content": "after\n", "expected_sha256": checksum},
            )
        ],
    )
    record = graph.run("Update the file")
    assert record["state"] == "awaiting_approval"
    assert (workspace / "hello.txt").read_text() == "before\n"
    restarted = session(
        workspace, [AIMessage(content="Edit was rejected.")], session_id=graph.session_id
    )
    assert restarted.run(decision="reject")["state"] == "completed"
    assert (workspace / "hello.txt").read_text() == "before\n"
    with pytest.raises(WorkspaceError, match="no pending approval"):
        restarted.run(decision="approve")


def test_changed_workspace_invalidates_approval(workspace):
    graph = session(workspace, [call("remember_note", {"key": "finding", "note": "Use pytest."})])
    assert graph.run("Remember the test command")["state"] == "awaiting_approval"
    (workspace / "hello.txt").write_text("user edit\n")
    with pytest.raises(WorkspaceError, match="workspace changed"):
        graph.run(decision="approve")


def test_reviewed_memory_survives_new_session(workspace):
    graph = session(
        workspace,
        [
            call("remember_note", {"key": "tests", "note": "Run pytest for checks."}),
            AIMessage(content="Saved."),
        ],
    )
    graph.run("Remember the test command")
    assert graph.run(decision="approve")["state"] == "completed"
    fresh = session(workspace, [call("recall_notes", {}), AIMessage(content="Memory retrieved.")])
    events = []
    fresh.run("Recall prior findings", on_event=events.append)
    assert "Run pytest for checks" in str(events)


def test_subagent_reads_share_budget_and_return_to_coordinator(workspace):
    child = ScriptedModel(
        responses=[
            call("workspace_read", {"path": "hello.txt"}, "read"),
            AIMessage(content="File contains before."),
        ]
    )
    graph = session(
        workspace,
        [
            call("task", {"subagent_type": "researcher", "description": "Read hello.txt"}),
            AIMessage(content="Investigation complete."),
        ],
        subagent_models={"researcher": child},
    )
    record = graph.run("Investigate the file")
    assert record["state"] == "completed"
    assert record["model_calls"] == 4
    assert record["tool_calls"] == 2
    assert "Investigation complete" in record["summary"]


def test_subagent_has_no_repository_write_tool(workspace):
    child = ScriptedModel(
        responses=[
            call(
                "workspace_write", {"path": "hello.txt", "content": "bad", "expected_sha256": "new"}
            ),
            AIMessage(content="No write capability."),
        ]
    )
    graph = session(
        workspace,
        [
            call("task", {"subagent_type": "reviewer", "description": "Review only"}),
            AIMessage(content="Done."),
        ],
        subagent_models={"reviewer": child},
    )
    events = []
    graph.run("Review", on_event=events.append)
    assert (workspace / "hello.txt").read_text() == "before\n"
    assert "not a valid tool" in str(events)


def test_call_budget_survives_restart(workspace):
    graph = session(workspace, [call("recall_notes", {})], max_model_calls=1)
    with pytest.raises(HarnessBudgetError):
        graph.run("Keep looking")
    saved = load_session(workspace, graph.session_id)
    assert saved["state"] == "failed" and saved["model_calls"] == 1
    restarted = session(
        workspace, [AIMessage(content="should not run")], session_id=graph.session_id
    )
    with pytest.raises(WorkspaceError, match="--recover"):
        restarted.run()
    with pytest.raises(HarnessBudgetError):
        restarted.run(recover=True)


def test_policy_changes_cannot_reuse_checkpoint(workspace):
    graph = session(workspace, [AIMessage(content="done")])
    graph.run("Inspect")
    changed = ReflexConfig(mode="enforce", policy={"allow_hold_override": True})
    with pytest.raises(WorkspaceError, match="policy changed"):
        HarnessSession(
            workspace,
            changed,
            ScriptedModel(responses=[AIMessage(content="unused")]),
            model_name="offline:test",
            session_id=graph.session_id,
        )


def test_scratch_execute_cannot_run_host_commands(workspace):
    graph = session(
        workspace,
        [call("execute", {"command": "touch escaped"}), AIMessage(content="No host shell.")],
    )
    events = []
    graph.run("Inspect", on_event=events.append)
    assert not (workspace / "escaped").exists()
    assert "does not support" in str(events) or "not supported" in str(events)


def test_model_identity_and_workspace_are_bound(workspace):
    graph = session(workspace, [AIMessage(content="done")])
    graph.run("Inspect")
    other = workspace.parent / "other"
    other.mkdir()
    with pytest.raises(FileNotFoundError):
        load_session(other, graph.session_id)
    with pytest.raises(WorkspaceError, match="model or policy"):
        HarnessSession(
            workspace,
            ReflexConfig(mode="enforce"),
            ScriptedModel(responses=[AIMessage(content="unused")]),
            model_name="other:model",
            session_id=graph.session_id,
        )


def test_recovery_requires_explicit_acknowledgment(workspace):
    graph = session(workspace, [AIMessage(content="partial")])

    def interrupt(_):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        graph.run("Inspect", on_event=interrupt)
    assert load_session(workspace, graph.session_id)["state"] == "interrupted"
    with pytest.raises(WorkspaceError, match="--recover"):
        graph.run()


def test_two_workers_can_research_with_shared_budget(workspace):
    parent = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "task",
                "args": {"subagent_type": "researcher", "description": "Investigate"},
                "id": "a",
            },
            {
                "name": "task",
                "args": {"subagent_type": "reviewer", "description": "Review"},
                "id": "b",
            },
        ],
    )
    graph = session(
        workspace,
        [parent, AIMessage(content="Both findings incorporated.")],
        subagent_models={
            "researcher": ScriptedModel(responses=[AIMessage(content="Finding one")]),
            "reviewer": ScriptedModel(responses=[AIMessage(content="Finding two")]),
        },
    )
    result = graph.run("Investigate and review")
    assert result["model_calls"] == 4
    assert result["tool_calls"] == 2
    assert result["state"] == "completed"
