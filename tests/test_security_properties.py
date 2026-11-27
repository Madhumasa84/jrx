"""Bounded property tests for security invariants of the shell parser, policy and hooks.

All inputs are inert: argv words from a fixed alphabet, synthetic paths inside a
temporary workspace, and commands that are parsed or evaluated but never executed.
Bash is used only as a reference for word splitting, by running ``printf '%s\\0'`` on a
generated command line with an empty environment in an empty temporary directory.

Runs are derandomized and bounded so CI sees the same examples every time; minimized
regression examples are pinned with ``@example``. Raise ``JRX_PROPERTY_EXAMPLES`` to
search harder locally.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import string
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from jev_reflex import redaction
from jev_reflex.audit import AuditLog
from jev_reflex.checks import shell
from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig
from jev_reflex.evaluator import DemoSemanticEvaluator, evaluate_context
from jev_reflex.models import EvaluationContext, ProposedAction
from jev_reflex.policy_rollout import simulate

EXAMPLES = int(os.environ.get("JRX_PROPERTY_EXAMPLES", "60"))
BOUNDED = settings(
    max_examples=EXAMPLES,
    derandomize=True,
    database=None,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
RANK = {"ALLOW": 0, "REVIEW": 1, "HOLD": 2}


@pytest.fixture(autouse=True, scope="module")
def regex_only_redaction() -> Iterator[None]:
    """Use the built-in redaction, as CI runners and the benchmark do.

    A Gitleaks binary on the developer's PATH adds about a second per evaluation and
    does not change deterministic decisions.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(redaction, "_GITLEAKS_AVAILABLE", False)
        patch.setattr(redaction, "_GITLEAKS_WARNING_SHOWN", True)
        yield


BASH = shutil.which("bash")

# --- generated command lines -----------------------------------------------------------

SAFE = string.ascii_letters + string.digits + "-_./=:,@%+"
SPECIAL = " ;|&<>()*?[]{}~#!$`'\"\\\t"
PROGRAMS = ("rm", "cp", "mv", "touch", "cat", "echo", "chmod", "curl", "git", "pip")


def _single(word: str) -> str:
    return "'" + word.replace("'", "'\\''") + "'"


def _double(word: str) -> str:
    return '"' + "".join("\\" + c if c in '\\"$`' else c for c in word) + '"'


def _escaped(word: str) -> str:
    return "".join(c if c in SAFE else "\\" + c for c in word)


@st.composite
def rendered_word(draw: st.DrawFn, word: str) -> str:
    """Spell ``word`` as one shell word, mixing quoting styles across its pieces."""
    cuts = sorted(draw(st.sets(st.integers(1, max(1, len(word) - 1)), max_size=2)))
    pieces = [word[a:b] for a, b in zip([0, *cuts], [*cuts, len(word)], strict=True) if a < b]
    out = []
    for piece in pieces:
        styles = [_single, _double, _escaped]
        if all(c in SAFE for c in piece):
            styles.append(lambda w: w)
        out.append(draw(st.sampled_from(styles))(piece))
    return "".join(out)


words = st.text(alphabet=SAFE + SPECIAL, min_size=1, max_size=10)


@st.composite
def command_lines(draw: st.DrawFn) -> tuple[list[str], str]:
    argv = [draw(st.sampled_from(PROGRAMS)), *draw(st.lists(words, min_size=0, max_size=4))]
    return argv, " ".join(draw(rendered_word(w)) for w in argv)


def _bash_argv(line: str) -> list[str]:
    assert BASH is not None
    with tempfile.TemporaryDirectory() as empty:
        out = subprocess.run(
            [BASH, "--noprofile", "--norc", "-c", "printf '%s\\0' " + line],
            env={},
            cwd=empty,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout
    return out.decode().split("\0")[:-1]


def _parsed_argv(line: str) -> list[list[str]]:
    plan = shell.inspect(ProposedAction(command=line))
    assert not plan.opaque, line
    return [list(command.argv) for command in plan.commands]


@pytest.mark.skipif(BASH is None, reason="bash is the word-splitting reference")
@BOUNDED
@given(command_lines())
@example((["rm", "-rf", "./x"], "r''m -rf ./x"))
@example((["rm", "-rf", "./x"], '"r"m -r\\f ./x'))
@example((["echo", "a b", "c$d", "e f"], "echo 'a b' \"c\\$d\" e\\ f"))
def test_parser_splits_words_like_bash(case: tuple[list[str], str]) -> None:
    argv, line = case
    assert _bash_argv(line) == argv, line  # the generator spells what it means
    assert _parsed_argv(line) == [argv], line


# --- equivalent spellings get the same decision ----------------------------------------


@pytest.fixture(scope="module")
def workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="jrx-prop-"))
    (root / ".git" / "hooks").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "README.md").write_text("fixture\n")
    yield root.resolve()
    shutil.rmtree(root)


def _decision(command: str, workspace: Path, config: ReflexConfig | None = None) -> str:
    context = EvaluationContext(
        user_task="maintain the fixture repository",
        repository=str(workspace),
        repository_root=str(workspace),
        working_directory=str(workspace),
        proposed_action=ProposedAction(command=command),
    )
    result = evaluate_context(context, config=config or ReflexConfig(mode="enforce"), use_jev=False)
    return result.decision


@BOUNDED
@given(command_lines())
@example((["rm", "-rf", "./cache"], "r''m -rf ./c'a'che"))
def test_equivalent_quoting_gets_the_same_decision(workspace: Path, case) -> None:
    argv, line = case
    assert _decision(line, workspace) == _decision(shlex.join(argv), workspace), line


# Control files Tier-0 protects. CI workflow files are not among them (a documented
# detection gap), so they are not used here.
PROTECTED = (".git/hooks/pre-commit", "reflex.yaml", ".claude/settings.json", "AGENTS.md")
WRITERS = ("touch {p}", "printf x > {p}", "cp README.md {p}", "tee {p}", "chmod +x {p}")


@st.composite
def spelled_path(draw: st.DrawFn, workspace: Path, path: str) -> str:
    """An equivalent spelling of a workspace-relative path."""
    parts = path.split("/")
    out: list[str] = []
    for part in parts:
        if draw(st.booleans()):
            out.append(".")
        if draw(st.booleans()):
            out.append(draw(st.sampled_from(("src", "docs", "x"))) + "/..")
        out.append(part)
    spelled = "/".join(out)
    if draw(st.booleans()):
        spelled = spelled.replace("/", "//", 1)
    if draw(st.booleans()):
        spelled = f"{workspace}/{spelled}"
    elif draw(st.booleans()):
        spelled = f"./{spelled}"
    return draw(rendered_word(spelled))


@BOUNDED
@given(st.data(), st.sampled_from(PROTECTED), st.sampled_from(WRITERS))
def test_protected_path_writes_stay_protected_after_normalization(
    workspace: Path, data: st.DataObject, path: str, writer: str
) -> None:
    canonical = _decision(writer.format(p=shlex.quote(path)), workspace)
    assert canonical != "ALLOW", writer  # the fixture really is protected
    variant = writer.format(p=data.draw(spelled_path(workspace, path)))
    assert RANK[_decision(variant, workspace)] >= RANK[canonical], variant


# --- recorded and replayed decisions agree ---------------------------------------------

policies = st.fixed_dictionaries(
    {
        "mode": st.sampled_from(("advisory", "review", "enforce")),
        "thresholds": st.sampled_from(
            ({"review": 0.5, "strong": 0.9}, {"review": 0.3, "strong": 0.6}, {})
        ),
    }
)


@BOUNDED
@given(policies, st.lists(command_lines(), min_size=1, max_size=4))
def test_replay_reproduces_every_recorded_decision(workspace: Path, policy, cases) -> None:
    with tempfile.TemporaryDirectory() as directory:
        audit = Path(directory) / "audit.jsonl"
        config = ReflexConfig.model_validate(
            {**policy, "audit": {"enabled": True, "path": str(audit)}}
        )
        for _, line in cases:
            context = EvaluationContext(
                user_task="maintain the fixture repository",
                repository=str(workspace),
                repository_root=str(workspace),
                working_directory=str(workspace),
                proposed_action=ProposedAction(command=line),
            )
            evaluate_context(context, config=config, semantic_evaluator=DemoSemanticEvaluator())
        assert AuditLog(config).verify()[0]
        report = simulate(audit, config, config)
    assert report["total"] == report["replayed"] == len(cases), report
    assert report["skipped_decision_mismatch"] == 0, report
    assert not any(report["changes"].values()), report


# --- ambiguous hook input in enforce mode ----------------------------------------------

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=8),
    lambda inner: (
        st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=8), inner, max_size=3)
    ),
    max_leaves=8,
)
payloads = st.one_of(
    json_values,
    st.fixed_dictionaries(
        {},
        optional={
            "tool_name": json_values | st.sampled_from(("Bash", "Write", "mcp__x__y")),
            "tool_input": json_values,
            "cwd": json_values,
            "hook_event_name": st.sampled_from(("PreToolUse", "", "Other")),
        },
    ),
)


def _well_formed(payload: object) -> bool:
    # Every event other than PostToolUse is evaluated as PreToolUse (the strict reading).
    if not isinstance(payload, dict):
        return False
    tool, arguments = payload.get("tool_name"), payload.get("tool_input")
    if not isinstance(tool, str) or not tool.strip():
        return False
    if isinstance(arguments, str):
        return bool(arguments.strip())  # raw text is inspected as the tool's input
    # An argument object needs one value with content; false and 0 are content
    # (MCP tools take flags and counts), None, blank text and empty containers are not.
    return isinstance(arguments, dict) and any(
        value is not None
        and not (isinstance(value, str) and not value.strip())
        and not (isinstance(value, dict | list) and not value)
        for value in arguments.values()
    )


@BOUNDED
@given(payloads)
@example({"tool_name": "Bash", "tool_input": {}})
@example({"tool_name": "Bash", "tool_input": {"command": 7}})
@example([{"tool_name": "Bash"}])
@example({"tool_name": "mcp__x__y", "tool_input": False})  # found by this property
def test_ambiguous_hook_input_is_denied_in_enforce_mode(workspace: Path, payload) -> None:
    policy = workspace / "reflex.yaml"
    policy.write_text("mode: enforce\n")
    result = CliRunner().invoke(
        app, ["claude-code-hook", "--config", str(policy), "--demo"], input=json.dumps(payload)
    )
    assert result.exit_code == 0, result.output
    output = json.loads(result.stdout)
    decision = output.get("hookSpecificOutput", {}).get("permissionDecision")
    assert decision != "allow", output  # never skip the host's permission prompt
    if not _well_formed(payload):
        assert decision == "deny", (payload, output)
