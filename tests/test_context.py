import json
from io import StringIO
from pathlib import Path

import pytest

from jev_reflex.adapters.generic import context_from_hook_payload, read_hook_payload
from jev_reflex.config import ReflexConfig
from jev_reflex.context import RepositoryContextProvider, bounded_text
from jev_reflex.evaluator import compact_state
from jev_reflex.models import EvaluationContext, ProposedAction


def test_bounded_text_keeps_truncation_marker() -> None:
    result = bounded_text("a" * 200, 100)
    assert len(result) == 100
    assert "truncated by jev-reflex" in result


def test_context_provider_builds_compact_context(tmp_path: Path) -> None:
    provider = RepositoryContextProvider(
        cwd=tmp_path,
        include_git_diff=False,
        include_changed_files=False,
        max_context_chars=100,
    )
    context = provider.build(
        user_task="Fix the bug",
        proposed_action=ProposedAction(command="pytest tests/"),
        recent_context="context",
        external_content="retrieved content",
    )
    assert context.repository == tmp_path.name
    assert context.working_directory == str(tmp_path.resolve())
    assert context.proposed_action.command == "pytest tests/"
    assert context.git_diff == ""


def test_compact_state_respects_total_size_limit() -> None:
    context = EvaluationContext(
        user_task="u" * 5_000,
        proposed_action=ProposedAction(
            command="c" * 5_000,
            input={"nested": "x" * 5_000},
        ),
        changed_files=["file-" + ("x" * 1_000) for _ in range(20)],
        git_diff="d" * 5_000,
        test_results="t" * 5_000,
        recent_context="r" * 5_000,
        external_content="e" * 5_000,
    )
    state = compact_state(context, 1_000)
    encoded = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
    assert len(encoded) <= 1_000


def test_hook_payload_requires_a_nonempty_tool_call() -> None:
    with pytest.raises(ValueError, match="tool name"):
        context_from_hook_payload({}, config=ReflexConfig())
    with pytest.raises(ValueError, match="tool arguments"):
        context_from_hook_payload({"tool_name": "Bash", "tool_input": {}}, config=ReflexConfig())
    with pytest.raises(ValueError, match="invalid command"):
        context_from_hook_payload(
            {"tool_name": "Bash", "tool_input": {"command": 123}}, config=ReflexConfig()
        )


def test_hook_payload_is_bounded_before_json_parsing() -> None:
    with pytest.raises(ValueError, match="size limit"):
        read_hook_payload(StringIO("x" * (1_048_576 + 1)))
