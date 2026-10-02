"""Seeded adversarial invariants using only temporary local state."""

import itertools
import json
import multiprocessing
import random
from concurrent.futures import ThreadPoolExecutor

import pytest

from jev_reflex.audit import AuditLog
from jev_reflex.config import AccessConfig, ReflexConfig, SessionLimitsConfig
from jev_reflex.context import RepositoryContextProvider
from jev_reflex.enterprise import AccessDenied, ApprovalStore, Identity
from jev_reflex.evaluator import evaluate_context
from jev_reflex.models import ProposedAction
from jev_reflex.policy import PolicyDecision
from jev_reflex.serialization import safe_yaml_load
from jev_reflex.session_limits import SessionLimitError, SessionStore


def reserve_process(args):
    path, maximum = args
    try:
        SessionStore(SessionLimitsConfig(path=path, max_tool_calls=maximum)).reserve(
            "parallel", semantic=1
        )
        return True
    except SessionLimitError:
        return False


def test_multiprocess_session_budget_never_double_spends(tmp_path):
    path = str(tmp_path / "session.db")
    maximum = 12
    with multiprocessing.get_context("fork").Pool(4) as pool:
        results = pool.map(reserve_process, [(path, maximum)] * 40)
    assert sum(results) == maximum
    status = SessionStore(SessionLimitsConfig(path=path)).status("parallel")
    assert status["tool_calls"] == status["semantic_evaluations"] == maximum


def test_production_reviewers_and_consumption_atomic(tmp_path):
    config = AccessConfig(
        issuer="https://idp.invalid",
        audience="jrx",
        jwks_uri="https://idp.invalid/jwks",
        environment="production",
        approval_db=str(tmp_path / "approval.db"),
        rules=[
            {
                "role": "reviewer",
                "actions": ["review"],
                "repositories": ["*"],
                "environments": ["production"],
            }
        ],
    )
    store = ApprovalStore(config)
    requester = Identity("developer", frozenset())
    approval = store.request(requester, str(tmp_path), "production", "binding", "echo harmless")
    reviewer = Identity("reviewer-one", frozenset({"reviewer"}))

    def grant(_):
        try:
            store.grant(approval, reviewer)
            return True
        except AccessDenied:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(grant, range(16))) == 1
    with pytest.raises(AccessDenied):
        store.consume(approval, requester, "binding")
    store.grant(approval, Identity("reviewer-two", frozenset({"reviewer"})))

    def consume(_):
        try:
            store.consume(approval, requester, "binding")
            return True
        except AccessDenied:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(consume, range(24))) == 1


def test_seeded_audit_protected_field_mutations_reject(tmp_path):
    path = tmp_path / "audit"
    log = AuditLog(ReflexConfig(audit={"enabled": True, "path": str(path)}))
    for _ in range(10):
        log.write_entry("echo safe", [], {}, PolicyDecision("ALLOW", (), ()))
    original = path.read_text()
    rng = random.Random(0xA0D17)
    for field in (
        "seq",
        "timestamp_utc",
        "action_summary",
        "policy_decision",
        "prev_hash",
        "entry_hash",
    ):
        records = [json.loads(line) for line in original.splitlines()]
        row = rng.choice(records)
        row[field] = row[field] + 1 if isinstance(row[field], int) else str(row[field]) + "altered"
        path.write_text("".join(json.dumps(record) + "\n" for record in records))
        assert not log.verify()[0]
    path.write_text(original)
    assert log.verify()[0]
    # A valid suffix deletion is intentionally NOT claimed detectable without a checkpoint.
    path.write_text("\n".join(original.splitlines()[:-1]) + "\n")
    assert log.verify()[0]


def test_git_flag_order_and_quoting_properties(tmp_path):
    provider = RepositoryContextProvider(cwd=tmp_path)
    for flags in itertools.permutations(["--force", "--delete", "old"]):
        for separator in (" ", "\t"):
            command = separator.join(["git", "-c", "color.ui=false", "branch", *flags])
            ctx = provider.build(user_task="", proposed_action=ProposedAction(command=command))
            assert evaluate_context(ctx, config=ReflexConfig(), use_jev=False).decision == "HOLD"


@pytest.mark.parametrize(
    "raw", ["x: &a [1]\ny: *a", "x: " + "[" * 70 + "0" + "]" * 70, "x: " + "a" * 1_048_576]
)
def test_config_structural_limits_reject(raw):
    with pytest.raises(ValueError):
        safe_yaml_load(raw)
