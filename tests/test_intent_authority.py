"""Adversarial tests of optional host-side trajectory and delegation controls."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from jev_reflex.config import ReflexConfig
from jev_reflex.models import EvaluationContext, ProposedAction


@pytest.mark.parametrize("adapter", ["claude_code", "codex", "deepseek", "openrouter"])
def test_public_adapters_cannot_downgrade_agent_controls(adapter):
    import importlib

    from jev_reflex.models import EvaluationResult, RiskInfo

    module = importlib.import_module(f"jev_reflex.adapters.{adapter}")
    result = EvaluationResult(
        decision="HOLD",
        risk=RiskInfo(score=1.0, choice="high"),
        triggered_rules=["agent_control:AUTHORITY_DENIED"],
    )
    output = getattr(module, f"{adapter}_hook_response")(result, ReflexConfig(mode="advisory"))
    if adapter == "openrouter":
        assert output.get("block")
    else:
        assert output["hookSpecificOutput"].get("permissionDecision") == "deny"


@pytest.fixture
def controls(tmp_path):
    from jev_reflex.agent_state import create_host_key
    from jev_reflex.authority import AuthorityStore
    from jev_reflex.intent import IntentStore

    key = tmp_path / "host.key"
    create_host_key(key)
    config = ReflexConfig.model_validate(
        {
            "mode": "enforce",
            "intent": {"enabled": True, "path": str(tmp_path / "intent.db"), "key_path": str(key)},
            "authority": {
                "enabled": True,
                "path": str(tmp_path / "authority.db"),
                "key_path": str(key),
                "environment": "test",
            },
        }
    )
    return config, IntentStore(config.intent), AuthorityStore(config.authority), tmp_path


def context(root, command="cat tests/test_one.py", task="Fix a failing unit test"):
    return EvaluationContext(
        user_task=task,
        repository_root=str(root),
        working_directory=str(root),
        proposed_action=ProposedAction(command=command),
    )


def envelope(store, root, **extra):
    return store.create(
        session_id="task-session",
        task="Fix a failing unit test",
        repository=str(root),
        policy_revision="policy-v1",
        scopes=["tests"],
        capabilities=["read", "test"],
        **extra,
    )


def test_intent_slow_drift_and_restart(controls):
    from jev_reflex.intent import IntentStore

    config, store, _, root = controls
    envelope(store, root, max_drift_score=1.0)
    for _ in range(3):
        assert store.evaluate("task-session", context(root), "policy-v1", "ALLOW", scope_creep=0.3)[
            "allowed"
        ]
    result = IntentStore(config.intent).evaluate(
        "task-session", context(root), "policy-v1", "ALLOW", scope_creep=0.3
    )
    assert not result["allowed"]
    assert "cumulative_drift" in result["evidence"]
    assert len(store.explain("task-session")) == 4


@pytest.mark.parametrize(
    "command",
    [
        "cat .env",
        "cat deploy/settings.yaml",
        "cat tests/../helm/values.yaml",
        "curl https://example.invalid",
        "python -c 'print(1)'",
    ],
)
def test_intent_scope_expansion_denied(controls, command):
    _, store, _, root = controls
    envelope(store, root)
    assert not store.evaluate("task-session", context(root, command), "policy-v1", "ALLOW")[
        "allowed"
    ]


@pytest.mark.parametrize(
    "task,revision",
    [("Deploy to production", "policy-v1"), ("Fix a failing unit test", "policy-v2")],
)
def test_intent_binding_changes_deny(controls, task, revision):
    _, store, _, root = controls
    envelope(store, root)
    assert not store.evaluate("task-session", context(root, task=task), revision, "ALLOW")[
        "allowed"
    ]


def test_intent_concurrent_lineage_and_stop(controls):
    _, store, _, root = controls
    envelope(store, root)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: store.evaluate("task-session", context(root), "policy-v1", "ALLOW"),
                range(24),
            )
        )
    assert all(row["allowed"] for row in results)
    records = store.explain("task-session")
    assert len({row["action_id"] for row in records}) == 24
    assert all(
        row["parent_action_id"] == records[i - 1]["action_id"] for i, row in enumerate(records) if i
    )
    store.stop("task-session")
    assert not store.evaluate("task-session", context(root), "policy-v1", "ALLOW")["allowed"]


def test_intent_tamper_and_bounded_storage(controls):
    from jev_reflex.agent_state import ControlError

    config, store, _, root = controls
    config.intent.max_actions_per_session = 2
    envelope(store, root)
    for _ in range(2):
        store.evaluate("task-session", context(root), "policy-v1", "ALLOW")
    with pytest.raises(ControlError):
        store.evaluate("task-session", context(root), "policy-v1", "ALLOW")
    with sqlite3.connect(config.intent.path) as db:
        db.execute("UPDATE objects SET payload='{}' WHERE namespace='intent'")
    with pytest.raises(ControlError):
        store.status("task-session")


def issue(store, root, **extra):
    options = dict(
        issuer="operator",
        issuer_session="operator-session",
        subject="parent",
        session_id="parent-session",
        repository=str(root),
        environment="test",
        policy_revision="policy-v1",
        scopes=["."],
        capabilities=["read", "modify", "test"],
        ttl_seconds=900,
    )
    options.update(extra)
    return store.issue(**options)


def validate(store, lease, root, nonce="action-1", **extra):
    options = dict(
        subject=lease["subject"],
        session_id=lease["session_id"],
        repository=str(root),
        environment="test",
        policy_revision="policy-v1",
        capabilities=["read"],
        resources=["tests/test_one.py"],
        nonce=nonce,
    )
    options.update(extra)
    return store.validate(lease["lease_id"], **options)


def child(store, parent, root, **extra):
    return issue(
        store,
        root,
        issuer=parent["subject"],
        issuer_session=parent["session_id"],
        subject="child",
        session_id="child-session",
        scopes=extra.pop("scopes", ["tests"]),
        capabilities=extra.pop("capabilities", ["read"]),
        ttl_seconds=extra.pop("ttl_seconds", 300),
        parent_id=parent["lease_id"],
        **extra,
    )


def test_valid_nested_delegation_and_revocation(controls):
    from jev_reflex.agent_state import ControlError

    _, _, store, root = controls
    parent = issue(store, root)
    narrow = child(store, parent, root)
    grandchild = store.issue(
        issuer="child",
        issuer_session="child-session",
        subject="grandchild",
        session_id="grandchild-session",
        repository=str(root),
        environment="test",
        policy_revision="policy-v1",
        scopes=["tests/unit"],
        capabilities=["read"],
        ttl_seconds=30,
        parent_id=narrow["lease_id"],
    )
    assert (
        validate(store, grandchild, root, resources=["tests/unit/test_x.py"])["lease_id"]
        == grandchild["lease_id"]
    )
    assert len(store.tree(parent["lease_id"])) == 3
    store.revoke(parent["lease_id"])
    with pytest.raises(ControlError):
        validate(store, grandchild, root, nonce="action-2", resources=["tests/unit/test_x.py"])


@pytest.mark.parametrize(
    "changes",
    [
        {"scopes": ["helm"]},
        {"scopes": ["tests_evil"]},
        {"capabilities": ["deploy"]},
        {"ttl_seconds": 1000},
        {"environment": "production"},
        {"policy_revision": "other"},
        {"issuer_session": "sibling-session"},
    ],
)
def test_child_cannot_widen_authority(controls, changes):
    from jev_reflex.agent_state import ControlError

    _, _, store, root = controls
    parent = issue(store, root, scopes=["tests"])
    options = dict(
        issuer="parent",
        issuer_session="parent-session",
        subject="child",
        session_id="child-session",
        repository=str(root),
        environment="test",
        policy_revision="policy-v1",
        scopes=["tests/unit"],
        capabilities=["read"],
        ttl_seconds=300,
        parent_id=parent["lease_id"],
    )
    options.update(changes)
    with pytest.raises(ControlError):
        store.issue(**options)


@pytest.mark.parametrize(
    "changes",
    [
        {"subject": "sibling"},
        {"session_id": "sibling-session"},
        {"repository": "/another-repo"},
        {"environment": "production"},
        {"policy_revision": "policy-v2"},
        {"resources": ["../secret"]},
    ],
)
def test_lease_wrong_binding_denies(controls, changes):
    from jev_reflex.agent_state import ControlError

    _, _, store, root = controls
    lease = issue(store, root)
    with pytest.raises(ControlError):
        validate(store, lease, root, **changes)


def test_concurrent_replay_exactly_one_success(controls):
    from jev_reflex.agent_state import ControlError

    _, _, store, root = controls
    lease = issue(store, root)

    def attempt(_):
        try:
            validate(store, lease, root)
            return True
        except ControlError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(24))) == 1


def test_expiry_tamper_forged_parent_and_depth(controls, monkeypatch):
    from jev_reflex.agent_state import ControlError

    config, _, store, root = controls
    with pytest.raises(ControlError):
        issue(store, root, parent_id="forged")
    lease = issue(store, root)
    import jev_reflex.authority as authority

    monkeypatch.setattr(authority.time, "time", lambda: lease["expires_at"] + 1)
    with pytest.raises(ControlError):
        validate(store, lease, root)
    monkeypatch.undo()
    config.authority.max_depth = 1
    narrow = child(store, lease, root)
    with pytest.raises(ControlError):
        child(store, narrow, root)
    with sqlite3.connect(config.authority.path) as db:
        data = json.loads(
            db.execute("SELECT payload FROM objects WHERE id=?", (lease["lease_id"],)).fetchone()[0]
        )
        data["parent_id"] = lease["lease_id"]
        db.execute("UPDATE objects SET payload=? WHERE id=?", (json.dumps(data), lease["lease_id"]))
    with pytest.raises(ControlError):
        validate(store, lease, root, nonce="different")


def test_scoped_symlink_escape(controls):
    from jev_reflex.agent_state import ControlError

    _, intents, leases, root = controls
    (root / "tests").mkdir()
    (root / "tests" / "escape").symlink_to(root.parent)
    envelope(intents, root)
    assert not intents.evaluate(
        "task-session", context(root, "cat tests/escape/outside"), "policy-v1", "ALLOW"
    )["allowed"]
    lease = issue(leases, root, scopes=["tests"])
    with pytest.raises(ControlError):
        validate(leases, lease, root, resources=["tests/escape/outside"])


def test_full_evaluator_missing_controls_hold(controls, monkeypatch):
    from jev_reflex.evaluator import evaluate_context

    config, _, _, root = controls
    monkeypatch.setenv("JRX_SESSION_ID", "missing")
    result = evaluate_context(context(root), config=config, use_jev=False)
    assert result.decision == "HOLD"
    assert any(rule.startswith("agent_control:") for rule in result.triggered_rules)


def test_intent_cannot_be_overridden_by_cli_yes(controls, monkeypatch):
    from typer.testing import CliRunner

    from jev_reflex.cli import app

    config, intents, _, root = controls
    config.authority.enabled = False
    config.policy.allow_hold_override = True
    envelope(intents, root)
    path = root / "policy.json"
    path.write_text(config.model_dump_json())
    monkeypatch.setenv("JRX_SESSION_ID", "task-session")
    marker = root / "executed"
    result = CliRunner().invoke(
        app,
        [
            "exec",
            "--config",
            str(path),
            "--cwd",
            str(root),
            "--task",
            "Fix a failing unit test",
            "--no-jev",
            "--yes",
            "--",
            "touch",
            str(marker),
        ],
    )
    assert result.exit_code == 2, result.output
    assert not marker.exists()


def test_authority_use_deletion_is_detected(controls):
    from jev_reflex.agent_state import ControlError

    config, _, store, root = controls
    lease = issue(store, root)
    validate(store, lease, root)
    with sqlite3.connect(config.authority.path) as db:
        db.execute("DELETE FROM objects WHERE namespace='use'")
    with pytest.raises(ControlError):
        validate(store, lease, root)


@pytest.mark.parametrize(
    "command", ["wc --files0-from=private/list", "/usr/bin/../../tmp/repo/cat tests/file"]
)
def test_opaque_read_options_and_executable_traversal_deny(controls, command):
    _, store, _, root = controls
    envelope(store, root)
    # Use repository-wide resources to isolate capability misclassification.
    command_context = context(root, command)
    from jev_reflex.action_scope import describe_action

    assert "unknown" in describe_action(command_context)[0]


def test_intent_cli_mode_override_cannot_disable_envelope(controls, monkeypatch):
    from typer.testing import CliRunner

    from jev_reflex.cli import app

    config, intents, _, root = controls
    config.authority.enabled = False
    envelope(intents, root)
    path = root / "policy.json"
    path.write_text(config.model_dump_json())
    monkeypatch.setenv("JRX_SESSION_ID", "task-session")
    marker = root / "mode-override-executed"
    result = CliRunner().invoke(
        app,
        [
            "exec",
            "--config",
            str(path),
            "--mode",
            "advisory",
            "--cwd",
            str(root),
            "--task",
            "Fix a failing unit test",
            "--no-jev",
            "--",
            "touch",
            str(marker),
        ],
    )
    assert result.exit_code == 2, result.output
    assert not marker.exists()


def test_authority_multiple_mcp_calls_use_distinct_request_nonces(controls, monkeypatch):
    from io import BytesIO
    from types import SimpleNamespace

    from jev_reflex.agent_controls import policy_revision
    from jev_reflex.mcp_gateway import MCPGateway

    config, _, leases, root = controls
    config.intent.enabled = False
    config.mcp.use_jev = False
    from jev_reflex.config import MCPToolRule

    config.mcp.tools = [MCPToolRule(server="files", name="read", effect="read")]
    lease = issue(leases, root, policy_revision=policy_revision(config))
    monkeypatch.chdir(root)
    monkeypatch.setenv("JRX_SESSION_ID", "parent-session")
    monkeypatch.setenv("JRX_AGENT_ID", "parent")
    monkeypatch.setenv("JRX_AUTHORITY_LEASE_ID", lease["lease_id"])
    monkeypatch.setenv("JRX_ACTION_NONCE", "fixed-host-launch")
    upstream = BytesIO()
    process = SimpleNamespace(stdin=upstream, poll=lambda: None)
    gateway = MCPGateway(config, "files", ["unused"], sink=BytesIO())
    first = b'{"id":1,"method":"tools/call","params":{"name":"read","arguments":{"path":"tests/test_one.py"}}}\n'
    second = first.replace(b'"id":1', b'"id":2')
    try:
        gateway._handle(process, first)
        gateway._handle(process, second)
        assert upstream.getvalue() == first + second
    finally:
        for _, timer in gateway._pending.values():
            timer.cancel()


def test_valid_authority_and_intent_through_cli(controls, monkeypatch):
    from typer.testing import CliRunner

    from jev_reflex.agent_controls import policy_revision
    from jev_reflex.cli import app

    config, intents, leases, root = controls
    (root / "tests").mkdir()
    (root / "tests" / "test_one.py").write_text("synthetic file\n")
    revision = policy_revision(config)
    intents.create(
        session_id="parent-session",
        task="Fix a failing unit test",
        repository=str(root),
        scopes=["tests"],
        capabilities=["read"],
        policy_revision=revision,
    )
    lease = issue(leases, root, policy_revision=revision)
    monkeypatch.setenv("JRX_SESSION_ID", "parent-session")
    monkeypatch.setenv("JRX_AGENT_ID", "parent")
    monkeypatch.setenv("JRX_AUTHORITY_LEASE_ID", lease["lease_id"])
    monkeypatch.setenv("JRX_ACTION_NONCE", "cli-action-one")
    path = root / "reflex.json"
    path.write_text(config.model_dump_json())
    result = CliRunner().invoke(
        app,
        [
            "exec",
            "--config",
            str(path),
            "--cwd",
            str(root),
            "--task",
            "Fix a failing unit test",
            "--no-jev",
            "--",
            "cat",
            "tests/test_one.py",
        ],
    )
    assert result.exit_code == 0, result.output
    replay = CliRunner().invoke(
        app,
        [
            "exec",
            "--config",
            str(path),
            "--cwd",
            str(root),
            "--task",
            "Fix a failing unit test",
            "--no-jev",
            "--",
            "cat",
            "tests/test_one.py",
        ],
    )
    assert replay.exit_code == 2, replay.output


def test_slow_drift_through_evaluation_pipeline(controls, monkeypatch):
    from jev_reflex.agent_controls import policy_revision
    from jev_reflex.evaluator import evaluate_context
    from jev_reflex.models import RiskInfo, SemanticSignals

    config, intents, _, root = controls
    config.authority.enabled = False
    intents.create(
        session_id="task-session",
        task="Fix a failing unit test",
        repository=str(root),
        scopes=["tests"],
        capabilities=["read"],
        max_drift_score=1.0,
        policy_revision=policy_revision(config),
    )
    monkeypatch.setenv("JRX_SESSION_ID", "task-session")

    class Semantic:
        def evaluate(self, ctx):
            return SemanticSignals(probabilities={"scope_creep": 0.3}, risk=RiskInfo(choice="low"))

    decisions = [
        evaluate_context(context(root), config=config, semantic_evaluator=Semantic()).decision
        for _ in range(4)
    ]
    assert decisions == ["ALLOW", "ALLOW", "ALLOW", "HOLD"]


def test_benign_long_session_and_missing_key_fail_closed(controls):
    from jev_reflex.agent_state import ControlError

    config, store, _, root = controls
    envelope(store, root)
    for _ in range(60):
        assert store.evaluate("task-session", context(root), "policy-v1", "ALLOW")["allowed"]
    assert store.status("task-session")["action_count"] == 60
    from pathlib import Path

    Path(config.intent.key_path).unlink()
    with pytest.raises((OSError, ControlError)):
        store.status("task-session")


def test_intent_record_deletion_detected(controls):
    from jev_reflex.agent_state import ControlError

    config, store, _, root = controls
    envelope(store, root)
    store.evaluate("task-session", context(root), "policy-v1", "ALLOW")
    with sqlite3.connect(config.intent.path) as db:
        db.execute("DELETE FROM objects WHERE namespace='action'")
    with pytest.raises(ControlError):
        store.status("task-session")


def test_lease_cannot_delegate_approval_and_forbidden_is_inherited(controls):
    from jev_reflex.agent_state import ControlError

    _, _, store, root = controls
    with pytest.raises(ControlError):
        issue(store, root, capabilities=["review"])
    lease = issue(store, root, forbidden=["secrets", "deploy"])
    narrow = child(store, lease, root)
    assert narrow["forbidden"] == ["deploy", "secrets"]


def test_agent_control_cli_visibility(controls):
    from typer.testing import CliRunner

    from jev_reflex.cli import app

    config, _, _, root = controls
    path = root / "policy.json"
    path.write_text(config.model_dump_json())
    runner = CliRunner()
    created = runner.invoke(
        app,
        [
            "intent",
            "create",
            "visible",
            "--config",
            str(path),
            "--repository",
            str(root),
            "--task",
            "read tests",
            "--scope",
            "tests",
            "--capability",
            "read",
        ],
    )
    assert created.exit_code == 0, created.output
    for command in ("status", "explain", "stop"):
        result = runner.invoke(app, ["intent", command, "visible", "--config", str(path)])
        assert result.exit_code == 0, result.output
    issued = runner.invoke(
        app,
        [
            "authority",
            "issue",
            "child",
            "child-session",
            "--config",
            str(path),
            "--repository",
            str(root),
            "--scope",
            "tests",
            "--capability",
            "read",
        ],
    )
    assert issued.exit_code == 0, issued.output
    lease_id = json.loads(issued.output)["lease_id"]
    for command in ("inspect", "tree", "revoke"):
        result = runner.invoke(app, ["authority", command, lease_id, "--config", str(path)])
        assert result.exit_code == 0, result.output


def test_synthetic_secret_filename_is_redacted_from_lineage(controls):
    config, intents, _, root = controls
    envelope(intents, root)
    secret = "synthetic-audit-v2-filename-value"
    intents.evaluate(
        "task-session", context(root, "cat tests/api_key=" + secret), "policy-v1", "ALLOW"
    )
    from pathlib import Path

    assert secret.encode() not in Path(config.intent.path).read_bytes()
