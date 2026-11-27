"""Regression tests for redaction, audit verification and observability review findings."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import random
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import jev_reflex
from jev_reflex import logging_config
from jev_reflex.audit import GENESIS_HASH, AuditEntry, AuditLog
from jev_reflex.audit_report import build_audit_report
from jev_reflex.cli import app
from jev_reflex.config import ReflexConfig
from jev_reflex.dashboard import DashboardConfig, snapshot
from jev_reflex.enterprise import Identity
from jev_reflex.metrics import MetricsRegistry
from jev_reflex.policy import PolicyDecision
from jev_reflex.redaction import REDACTED_SECRET, redact_argv, redact_obj, redact_text
from jev_reflex.signing import Ed25519Signer

SECRET = "Zq8vR2mK7xLp4Tn9Wc3B"
BUDGET_SECONDS = 1.0
MIN_ADVERSARIAL_BYTES = 200_000


# ---------------------------------------------------------------------------
# Finding 1: redaction must be linear-time on agent-controlled input.
# ---------------------------------------------------------------------------

# Each case is measured in a child process so a regression fails within the
# timeout instead of hanging the suite.
_TIMING_CHILD = r"""
import json, sys, time
from jev_reflex import redaction as r

text = sys.stdin.read()
secrets = json.loads(sys.argv[1])
timings, outputs = {}, {}

def measure(name, call):
    start = time.perf_counter()
    result = call()
    timings[name] = time.perf_counter() - start
    return result

outputs["redact_text"] = measure("redact_text", lambda: r.redact_text(text))
outputs["redact_argv"] = "\n".join(measure("redact_argv", lambda: r.redact_argv(["tool", text])))
outputs["redact_obj"] = json.dumps(measure("redact_obj", lambda: r.redact_obj({"items": [text]})))
# checks/secrets.py runs these shared patterns over the same untrusted text.
for name in (
    "_BEARER_RE", "_KNOWN_TOKEN_RE", "_SECRET_ASSIGNMENT_RE", "_SECRET_FLAG_RE",
    "_USERPASS_FLAG_RE", "_USERPASS_ATTACHED_RE", "_URL_SECRET_RE",
):
    pattern = getattr(r, name)
    measure("checks:" + name, lambda: sum(1 for _ in pattern.finditer(text)))
leaks = sorted({name for name, out in outputs.items() for s in secrets if s in out})
print(json.dumps({"timings": timings, "leaks": leaks}))
"""


def _run_timed(text: str, secrets: list[str]) -> dict[str, object]:
    package_root = str(Path(jev_reflex.__file__).resolve().parent.parent)
    env = {**os.environ, "PYTHONPATH": package_root}
    try:
        completed = subprocess.run(
            [sys.executable, "-c", _TIMING_CHILD, json.dumps(secrets)],
            input=text,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
            check=True,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("redaction did not finish within 60 seconds")
    return json.loads(completed.stdout)


def _repeat(prefix: str, unit: str, suffix: str = "") -> str:
    count = MIN_ADVERSARIAL_BYTES // len(unit) + 1
    return prefix + unit * count + suffix


_TRAILER = f"\npassword={SECRET}\n"

ADVERSARIAL_SHAPES = {
    "flag-token-chain": _repeat("--", "token-", "!"),
    "flag-token-chain-dashes": _repeat("--", "a-", "token!"),
    "pem-begin-without-end": _repeat("", "-----BEGIN RSA PRIVATE KEY-----"),
    "jwt-prefix-run": _repeat("", "eyJ-", "é"),
    "openai-prefix-run": _repeat("", "sk-", "é"),
    "slack-prefix-run": _repeat("", "xoxb-", "é"),
    "identifier-token-suffix": _repeat("a", "_token", "!"),
    "authorization-whitespace": _repeat("authorization:", " "),
    "assignment-whitespace": _repeat("password", " ", "x"),
    "repeated-keywords": _repeat("", "password "),
    "keyword-padding": _repeat("", "password" + " " * 50),
    "user-flags": _repeat("", "-u "),
    "unterminated-quotes": _repeat("", 'password="'),
    "escaped-quote-run": _repeat('password="', "\\"),
    "url-userinfo-without-at": _repeat("", "x://u:"),
    "url-userinfo-many-at": _repeat("https://u:", "p@"),
    "mysql-options": _repeat("", "mysql -p"),
    "sshpass-options": _repeat("", "sshpass -p "),
    "header-dash-chain": _repeat("", "X-", "Key: v"),
    "dash-chain-assignment": _repeat("", "a-", "password=v"),
    "escaped-json-keys": _repeat("", '\\"password\\":\\"'),
    "json-keys": _repeat("", '{"password":'),
    "attached-p": _repeat("", "-p"),
    "token-assignments": _repeat("", "token="),
    "basic-auth-headers": _repeat("", "Authorization: Basic "),
    "password-flag-chain": _repeat("", "--password-"),
    "dotted-keys": _repeat("", "a.b-", "=x"),
    "camel-keys": _repeat("", "aB", ":x"),
    "colons": _repeat("", "a:"),
    "equals": _repeat("", "a="),
}


@pytest.mark.parametrize("shape", sorted(ADVERSARIAL_SHAPES))
def test_redaction_is_linear_on_adversarial_input(shape):
    text = ADVERSARIAL_SHAPES[shape] + _TRAILER
    assert len(text) >= MIN_ADVERSARIAL_BYTES
    result = _run_timed(text, [SECRET])
    slow = {name: round(t, 3) for name, t in result["timings"].items() if t >= BUDGET_SECONDS}
    assert not slow, f"{shape}: {slow}"
    assert result["leaks"] == [], f"{shape}: secret survived in {result['leaks']}"


_MIX_FRAGMENTS = [
    "--token-",
    "token-",
    "-----BEGIN RSA PRIVATE KEY-----",
    "eyJ-",
    "_token",
    "authorization: ",
    "password ",
    "-u ",
    'password="',
    "x://u:",
    "p@",
    "mysql -p",
    "sshpass -p ",
    "X-",
    '\\"password\\":\\"',
    '{"password":',
    "Bearer ",
    "a.b-",
    "aB:",
    "\\",
    "'",
    '"',
    ",",
    "=",
    ":",
    " ",
    "\n",
]


@pytest.mark.parametrize("seed", range(5))
def test_redaction_is_linear_and_complete_on_random_adversarial_mixes(seed):
    rng = random.Random(seed)
    pieces: list[str] = []
    size = 0
    while size < MIN_ADVERSARIAL_BYTES:
        # Mostly short runs, with occasional long runs of one shape.
        repeat = rng.randint(1, 50) if rng.random() < 0.8 else rng.randint(2_000, 12_000)
        piece = rng.choice(_MIX_FRAGMENTS) * repeat
        pieces.append(piece)
        size += len(piece)
    secret_forms = [
        "\npassword={}\n",
        '\n{{"api_key": "{}"}}\n',
        "\nsshpass -p {} ssh host\n",
        "\nmysql -u root -p{} db\n",
        "\ngit clone https://bob:{}@example.com/r.git\n",
        "\ncurl -u bob:{} https://example.com\n",
        "\ndeploy --token {}\n",
    ]
    secrets = [f"{SECRET}{index}" for index in range(len(secret_forms))]
    for form, secret in zip(secret_forms, secrets, strict=True):
        pieces.insert(rng.randint(0, len(pieces)), form.format(secret))
    text = "".join(pieces)
    result = _run_timed(text, secrets)
    slow = {name: round(t, 3) for name, t in result["timings"].items() if t >= BUDGET_SECONDS}
    assert not slow, f"seed {seed}: {slow}"
    assert result["leaks"] == [], f"seed {seed}: secret survived in {result['leaks']}"


# ---------------------------------------------------------------------------
# Finding 3: credentials in common shell forms.
# ---------------------------------------------------------------------------

LEAKING_SHELL_FORMS = [
    f"git clone https://alice:{SECRET}@github.example.com/org/repo.git",
    f"DATABASE_URL=postgres://app:{SECRET}@db.internal:5432/prod",
    f"psql postgres://app:{SECRET}@db.internal/prod",
    f"redis-cli -u redis://:{SECRET}@cache:6379 ping",
    f"sshpass -p {SECRET} ssh host",
    f"sshpass -p{SECRET} ssh host",
    f"-----BEGIN OPENSSH PRIVATE KEY-----\n{SECRET}AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
    f"PGPASSWORD={SECRET} psql -h db",
    f"MYSQL_PWD={SECRET} mysql",
    f"export DBPASSWORD={SECRET}",
    f"mysql -u root -p{SECRET} db",
    f"mysqldump -uroot -p'{SECRET}' db",
    f"/usr/bin/mariadb -p{SECRET}",
    f'{{"password": "{SECRET}"}}',
    f'{{"api_key":"{SECRET}"}}',
    f'{{"2fa_secret": "{SECRET}"}}',
    f'{{"Authorization": "Basic {SECRET}"}}',
    f'curl -d \'{{\\"password\\":\\"{SECRET}\\"}}\' https://api.example.com/login',
    f"password=abc,{SECRET}",
    f'password="abc\\"{SECRET}"',
    f'password="unterminated {SECRET}',
    f"docker login -u bob -p {SECRET} registry.example.com",
    f"redis-cli -a {SECRET} ping",
    f"java -Dspring.datasource.password={SECRET} -jar app.jar",
    f"curl -H 'X-Api-Key: {SECRET}' https://api.example.com",
    f"$config = ['password' => '{SECRET}'];",
]


@pytest.mark.parametrize("command", LEAKING_SHELL_FORMS)
def test_common_shell_credential_forms_are_redacted(command):
    result = redact_text(command)
    assert SECRET not in result
    assert REDACTED_SECRET in result


def test_shell_redaction_keeps_command_structure():
    assert redact_text(f"mysql -u root -p{SECRET} db") == f"mysql -u root -p{REDACTED_SECRET} db"
    assert (
        redact_text(f"git clone https://alice:{SECRET}@github.example.com/org/repo.git")
        == f"git clone https://alice:{REDACTED_SECRET}@github.example.com/org/repo.git"
    )
    assert redact_text(f"sshpass -p {SECRET} ssh -p 22 host") == (
        f"sshpass -p {REDACTED_SECRET} ssh -p 22 host"
    )
    assert redact_text(f'{{"password": "{SECRET}", "user": "bob"}}') == (
        f'{{"password": "{REDACTED_SECRET}", "user": "bob"}}'
    )
    assert (
        redact_text(f"PGPASSWORD={SECRET} psql -h db") == f"PGPASSWORD={REDACTED_SECRET} psql -h db"
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["mysql", "-uroot", f"-p{SECRET}"],
        ["mysql", "-u", "root", f"-p{SECRET}", "db"],
        ["sshpass", "-p", SECRET, "ssh", "host"],
        ["sshpass", f"-p{SECRET}", "ssh", "host"],
        ["psql", f"postgres://app:{SECRET}@db/prod"],
        ["env", f"PGPASSWORD={SECRET}", "psql"],
        ["curl", "-u", f"user:{SECRET}", "https://example.invalid"],
        ["docker", "login", "-u", "bob", "-p", SECRET],
        ["redis-cli", "-a", SECRET, "ping"],
        ["curl", "-d", f'{{"password": "{SECRET}"}}', "https://example.invalid"],
    ],
)
def test_argv_mirrors_shell_credential_redaction(argv):
    result = redact_argv(argv)
    assert SECRET not in " ".join(result)
    assert len(result) == len(argv)


def test_argv_keeps_user_names_and_prompting_password_flags():
    assert redact_argv(["mysql", "-uroot", "-p", "mydb"]) == ["mysql", "-uroot", "-p", "mydb"]
    assert redact_argv(["sudo", "-u", "postgres", "psql"]) == ["sudo", "-u", "postgres", "psql"]
    assert redact_argv(["deploy", "--token", "$DEPLOY_TOKEN"]) == [
        "deploy",
        "--token",
        "$DEPLOY_TOKEN",
    ]
    assert redact_argv(["deploy", "--token", "$literal!"]) == ["deploy", "--token", REDACTED_SECRET]


ORDINARY_TEXT = [
    "git clone https://github.com/org/repo.git",
    "ssh user@host",
    "ssh -p 2222 user@host",
    "pip install -p 3",
    "git push -u origin main",
    "sudo -u postgres psql",
    "mysql -u root -p mydb",
    "def password_reset_view(request):\n    return render(request)",
    "if password_valid and token_count > 3:",
    "contact alice@example.com or bob.smith@example.org",
    "curl http://localhost:8080/api/v1/items?page=2",
    "kubectl get secret my-secret -o yaml",
    "secretName: tls-cert",
    "json.dumps(data, sort_keys=True)",
    "echo $TYPESAFE_API_KEY",
    "export TOKEN=$GITHUB_TOKEN",
    "PWD=/home/dev/project",
]


@pytest.mark.parametrize("text", ORDINARY_TEXT)
def test_ordinary_commands_and_code_are_not_redacted(text):
    assert redact_text(text) == text


# ---------------------------------------------------------------------------
# Finding 4: structured secrets in redact_obj.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        {"password": "$uperS3cretPw!" + SECRET},
        {"passwords": [SECRET]},
        {"credentials": [{"value": SECRET}]},
        {"api_key": {"value": SECRET}},
        {"password": 123456789},
        {"passphrase": SECRET},
        {"accessKey": SECRET},
        {"signingKey": SECRET},
        {"basicAuth": SECRET},
        {"pwd": SECRET},
        {"cookie": f"session={SECRET}"},
        {"secret": SECRET.encode()},
        {"note": f"password={SECRET}".encode()},
        {"tokens": (SECRET,)},
        {"secrets": {SECRET}},
        {f"ghp_{SECRET}abcdefghij": 1},
        {f"password={SECRET}": "value"},
    ],
)
def test_redact_obj_redacts_structured_secrets(value):
    original = copy.deepcopy(value)
    result = redact_obj(value)
    assert SECRET not in repr(result)
    assert "123456789" not in repr(result)
    assert value == original


def test_redact_obj_keeps_variable_references_and_signal_scores():
    assert redact_obj({"password": "$DB_PASSWORD", "token": "${DEPLOY_TOKEN}"}) == {
        "password": "$DB_PASSWORD",
        "token": "${DEPLOY_TOKEN}",
    }
    signals = {"signals": {"secret_exposure": 0.71, "destructive": 0.1}, "degraded": False}
    assert redact_obj(signals) == signals
    assert redact_obj({"password": None, "token_enabled": True}) == {
        "password": None,
        "token_enabled": True,
    }


def test_redact_obj_keeps_distinct_keys_that_redact_alike():
    result = redact_obj({f"ghp_{SECRET}abcdefghij": 1, f"ghp_{SECRET}klmnopqrst": 2})
    assert sorted(result.values()) == [1, 2]
    assert SECRET not in repr(result)


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------


def _signing_keys(tmp_path: Path) -> tuple[Path, Path]:
    signer = Ed25519Signer()
    public = tmp_path / "audit.pub"
    public.write_text(signer.get_public_key_pem())
    private = tmp_path / "audit.key"
    private.write_text(signer.get_private_key_pem())
    os.chmod(private, 0o600)
    return private, public


def _rechain(records: list[dict[str, object]]) -> str:
    """Recompute hashes the way an attacker without the signing key can."""
    previous = GENESIS_HASH
    lines = []
    for record in records:
        record = dict(record)
        record.pop("decision_signature", None)
        record.pop("entry_hash", None)
        record["prev_hash"] = previous
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
        previous = hashlib.sha256((previous + canonical).encode()).hexdigest()
        record["entry_hash"] = previous
        lines.append(json.dumps(record))
    return "".join(line + "\n" for line in lines)


def _forged_unsigned_log(tmp_path: Path) -> tuple[Path, Path, Path, ReflexConfig]:
    private, public = _signing_keys(tmp_path)
    log = tmp_path / "audit.jsonl"
    writer = ReflexConfig.model_validate(
        {
            "audit": {"enabled": True, "path": str(log)},
            "signing": {
                "require_signature": True,
                "private_key_path": str(private),
                "public_key_path": str(public),
            },
        }
    )
    AuditLog(writer).write_entry("rm -rf /prod", [], {}, PolicyDecision("HOLD", (), ()))
    records = [json.loads(line) for line in log.read_text().splitlines()]
    for record in records:
        record["policy_decision"] = "ALLOW"
    log.write_text(_rechain(records))
    return log, private, public, writer


# ---------------------------------------------------------------------------
# Finding 2: verify honours signing.require_signature and the configured key.
# ---------------------------------------------------------------------------


def test_verify_uses_configured_public_key_and_rejects_stripped_signatures(tmp_path):
    _, _, _, writer = _forged_unsigned_log(tmp_path)
    reader = writer.model_copy(
        update={"signing": writer.signing.model_copy(update={"private_key_path": None})}
    )
    valid, message = AuditLog(reader).verify()
    assert not valid
    assert "signature" in message


def test_verify_fails_when_signature_is_required_but_no_key_is_available(tmp_path):
    log = tmp_path / "audit.jsonl"
    AuditLog(ReflexConfig(audit={"enabled": True, "path": str(log)})).write_entry(
        "ls", [], {}, PolicyDecision("ALLOW", (), ())
    )
    config = ReflexConfig(audit={"path": str(log)}, signing={"require_signature": True})
    valid, message = AuditLog(config).verify()
    assert not valid
    assert "public key" in message


def test_verify_checks_every_signature_with_the_configured_key(tmp_path):
    private, public = _signing_keys(tmp_path)
    log = tmp_path / "audit.jsonl"
    writer = ReflexConfig.model_validate(
        {
            "audit": {"enabled": True, "path": str(log)},
            "signing": {"private_key_path": str(private), "public_key_path": str(public)},
        }
    )
    for decision in ("ALLOW", "HOLD"):
        AuditLog(writer).write_entry("ls", [], {}, PolicyDecision(decision, (), ()))
    assert AuditLog.reader(writer).verify() == (
        True,
        "chain intact, 2 entries (signatures verified)",
    )


def test_cli_audit_verify_honours_require_signature(tmp_path, monkeypatch):
    log, _, public, _ = _forged_unsigned_log(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reflex.yaml").write_text(
        json.dumps(
            {
                "audit": {"enabled": True, "path": str(log)},
                "signing": {"require_signature": True, "public_key_path": str(public)},
            }
        )
    )
    result = CliRunner().invoke(app, ["audit", "verify"])
    assert result.exit_code == 1
    assert "chain intact" not in result.stdout


def _dashboard(tmp_path: Path, policy: Path, log: Path) -> DashboardConfig:
    return DashboardConfig.model_validate(
        {
            "access": {
                "issuer": "https://idp.example",
                "audience": "jrx",
                "jwks_uri": "https://idp.example/jwks",
                "environment": "dashboard",
                "rules": [
                    {
                        "role": "ops",
                        "actions": ["view"],
                        "repositories": ["repo-a"],
                        "environments": ["dashboard"],
                    }
                ],
            },
            "sources": [
                {
                    "team": "a",
                    "repository": "repo-a",
                    "policy_path": str(policy),
                    "audit_path": str(log),
                }
            ],
        }
    )


def test_dashboard_honours_policy_signature_requirement(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    log, _, public, _ = _forged_unsigned_log(tmp_path)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        f"mode: enforce\nsigning:\n  require_signature: true\n  public_key_path: {public}\n"
    )
    team = snapshot(_dashboard(tmp_path, policy, log), Identity("operator", frozenset({"ops"})))[
        "teams"
    ][0]
    assert team["audit_integrity"]["valid"] is False
    assert "decisions" not in team


# ---------------------------------------------------------------------------
# Finding 7: verification never needs the producer's private key.
# ---------------------------------------------------------------------------


def _signed_log_with_unavailable_private_key(tmp_path: Path) -> tuple[Path, Path, Path]:
    private, public = _signing_keys(tmp_path)
    log = tmp_path / "audit.jsonl"
    writer = ReflexConfig.model_validate(
        {
            "audit": {"enabled": True, "path": str(log)},
            "signing": {"private_key_path": str(private), "public_key_path": str(public)},
        }
    )
    AuditLog(writer).write_entry("ls", [], {}, PolicyDecision("ALLOW", (), ()))
    private.unlink()  # The verifying host only has the public key.
    return log, private, public


def test_cli_audit_verify_does_not_load_the_private_signing_key(tmp_path, monkeypatch):
    log, private, public = _signed_log_with_unavailable_private_key(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reflex.yaml").write_text(
        json.dumps(
            {
                "audit": {"enabled": True, "path": str(log)},
                "signing": {
                    "require_signature": True,
                    "private_key_path": str(private),
                    "public_key_path": str(public),
                },
            }
        )
    )
    result = CliRunner().invoke(app, ["audit", "verify"])
    assert result.exit_code == 0, result.output
    assert "chain intact, 1 entries (signatures verified)" in result.stdout


def test_dashboard_does_not_load_the_private_signing_key(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    log, private, public = _signed_log_with_unavailable_private_key(tmp_path)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "mode: enforce\nsigning:\n  require_signature: true\n"
        f"  private_key_path: {private}\n  public_key_path: {public}\n"
    )
    # The dashboard trusts only an operator-pinned audit key, never the policy's choice.
    dashboard = _dashboard(tmp_path, policy, log)
    dashboard.sources[0].audit_public_key_path = str(public)
    team = snapshot(dashboard, Identity("operator", frozenset({"ops"})))["teams"][0]
    assert team["audit_integrity"]["valid"] is True, team
    assert team["decisions"]["ALLOW"] == 1


# ---------------------------------------------------------------------------
# Finding 5: verification rejects parser differentials.
# ---------------------------------------------------------------------------


def _hold_log(tmp_path: Path) -> tuple[Path, ReflexConfig]:
    log = tmp_path / "audit.jsonl"
    config = ReflexConfig(audit={"enabled": True, "path": str(log)})
    AuditLog(config).write_entry("deploy prod", [], {}, PolicyDecision("HOLD", (), ()))
    return log, config


def test_duplicate_member_tampering_fails_verification_and_blocks_appends(tmp_path):
    log, config = _hold_log(tmp_path)
    raw = log.read_text()
    tampered = raw.replace('{"seq": 1,', '{"policy_decision": "ALLOW", "seq": 1,', 1)
    assert tampered != raw
    log.write_text(tampered)
    valid, message = AuditLog(config).verify()
    assert not valid
    assert "duplicate" in message
    with pytest.raises(ValueError, match="audit"):
        build_audit_report(log, config)
    with pytest.raises(ValueError, match="audit"):
        AuditLog(config).write_entry("ls", [], {}, PolicyDecision("ALLOW", (), ()))
    assert log.read_text() == tampered


def test_non_canonical_record_bytes_fail_verification(tmp_path):
    log, config = _hold_log(tmp_path)
    record = json.loads(log.read_text())
    log.write_text(json.dumps(record, separators=(",", ":")) + "\n")
    valid, message = AuditLog(config).verify()
    assert not valid
    assert "non-canonical" in message


def test_file_and_snapshot_verification_frame_records_identically(tmp_path):
    log, config = _hold_log(tmp_path)
    AuditLog(config).write_entry("ls", [], {}, PolicyDecision("ALLOW", (), ()))
    log.write_bytes(log.read_bytes().replace(b"\n", b"\r", 1))
    snapshot_text = log.read_bytes().decode()
    file_result = AuditLog(config).verify()
    snapshot_result = AuditLog(config).verify(snapshot=snapshot_text)
    assert file_result[0] is False
    assert file_result == snapshot_result


def test_dashboard_renders_records_with_unicode_line_separators(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    log = tmp_path / "audit.jsonl"
    policy = tmp_path / "policy.yaml"
    policy.write_text("mode: enforce\n")
    config = ReflexConfig(mode="enforce")
    entry = AuditEntry(
        seq=1,
        timestamp_utc="2026-10-09T00:00:00Z",
        action_summary="echo first\u2028second",
        policy_decision="HOLD",
        policy_version_hash=AuditLog(config)._compute_policy_version_hash(config),
    )
    log.write_text(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n", encoding="utf-8")
    team = snapshot(_dashboard(tmp_path, policy, log), Identity("operator", frozenset({"ops"})))[
        "teams"
    ][0]
    assert team["audit_integrity"]["valid"] is True, team
    assert "error" not in team, team
    assert team["decisions"]["HOLD"] == 1


# ---------------------------------------------------------------------------
# Finding 9: display helpers tolerate malformed records.
# ---------------------------------------------------------------------------


def test_tail_and_overrides_skip_malformed_records(tmp_path):
    log = tmp_path / "audit.jsonl"
    config = ReflexConfig(audit={"enabled": True, "path": str(log)})
    audit = AuditLog(config)
    audit.write_human_override("reviewer", "REVIEW", "deploy", "checked")
    with log.open("a", encoding="utf-8") as stream:
        stream.write("[1, 2]\n")
        stream.write('"text"\n')
        stream.write(json.dumps({"event_type": "human_override", "timestamp_utc": 17}) + "\n")
        stream.write(json.dumps({"event_type": "human_override", "timestamp": ["x"]}) + "\n")
        stream.write('{"event_type": "human_override", "event_type": "policy_decision"}\n')
    entries = audit.tail(10)
    assert all(isinstance(entry, dict) for entry in entries)
    # Records without an integer seq are malformed for display and skipped too.
    assert [entry["identity"] for entry in entries] == ["reviewer"]
    overrides = audit.get_overrides()
    assert [entry["identity"] for entry in overrides] == ["reviewer"]
    recent = audit.get_overrides(since="2000-01-01")
    assert [entry["identity"] for entry in recent] == ["reviewer"]


# ---------------------------------------------------------------------------
# Finding 10 and observability follow-ups.
# ---------------------------------------------------------------------------


class _Response:
    status_code = 200


def test_webhook_stop_drains_queued_entries():
    delivered: list[dict[str, object]] = []

    def post(url, json=None, headers=None, timeout=None):
        time.sleep(0.05)
        delivered.append(json)
        return _Response()

    with patch("requests.post", post):
        sink = logging_config.WebhookSink("https://example.invalid/hook")
        for index in range(10):
            sink.emit({"index": index})
        sink.stop()
    assert [entry["index"] for entry in delivered] == list(range(10))


def test_webhook_stop_is_bounded_by_its_timeout():
    release = threading.Event()

    def post(url, json=None, headers=None, timeout=None):
        release.wait(timeout)
        return _Response()

    with patch("requests.post", post):
        sink = logging_config.WebhookSink("https://example.invalid/hook")
        for index in range(5):
            sink.emit({"index": index})
        started = time.monotonic()
        sink.stop(timeout=0.5)
        elapsed = time.monotonic() - started
        release.set()
    assert elapsed < 2.0


def test_sink_handler_failures_never_reach_the_caller(monkeypatch):
    class BrokenSink:
        def emit(self, entry):
            raise OSError("sink unavailable")

        def close(self):
            pass

    handler = logging_config._SinkHandler(BrokenSink())  # type: ignore[arg-type]
    handler.setFormatter(logging_config.JSONFormatter())
    logger = logging.getLogger("jrx-review-sink-test")
    monkeypatch.setattr(logger, "handlers", [handler])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(logging, "raiseExceptions", False)
    logging_config.log_structured("INFO", "event", {"a": 1}, logger_name=logger.name)
    logging_config.log_structured("INFO", "event", {"a": object()}, logger_name=logger.name)


def test_metrics_exposition_ends_with_a_newline():
    registry = MetricsRegistry()
    registry.get_counter("jrx_test_total", "Test counter").inc()
    registry.get_gauge("jrx_test_gauge", "Test gauge").set(1.0)
    rendered = registry.render()
    assert rendered.endswith("\n")
    assert not rendered.endswith("\n\n")


# --- policy_reload records cannot be spoofed by an agent action summary --------------


def _decision(name):
    from jev_reflex.policy import PolicyDecision

    return PolicyDecision(name, (), ())


def test_agent_action_named_policy_reload_is_counted_and_replayed(tmp_path):
    from jev_reflex.policy_rollout import simulate

    path = tmp_path / "audit.jsonl"
    config = ReflexConfig(mode="enforce", audit={"enabled": True, "path": str(path)})
    AuditLog(config).write_entry(
        "policy_reload",
        [],
        {},
        _decision("ALLOW"),
        risk_choice="low",
        risk_confidence=0.9,
        degraded=True,
        forced_review=False,
    )
    report = build_audit_report(path, config)
    assert report["decisions"]["ALLOW"] == 1
    assert report["degraded_evaluations"] == 1
    assert report["other_events"] == 0
    replay = simulate(path, config, config)
    assert replay["total"] == 1


def test_real_policy_reload_record_is_typed_verified_and_kept_out_of_decisions(tmp_path):
    from jev_reflex.policy_rollout import simulate

    path = tmp_path / "audit.jsonl"
    config = ReflexConfig(audit={"enabled": True, "path": str(path)})
    log = AuditLog(config)
    log.write_entry("ls", [], {}, _decision("ALLOW"))
    log.write_entry("policy_reload", [], {}, _decision("ALLOW"), event_type="policy_reload")
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert "event_type" not in records[0]  # decision records keep their historical bytes
    assert records[1]["event_type"] == "policy_reload"
    assert log.verify()[0] is True
    report = build_audit_report(path, config)
    assert report["decisions"]["ALLOW"] == 1
    assert report["other_events"] == 1
    assert simulate(path, config, config)["total"] == 1

    # The event type is under the hash: relabelling a decision as a reload breaks the chain.
    forged = dict(records[0], event_type="policy_reload")
    path.write_text(json.dumps(forged) + "\n" + json.dumps(records[1]) + "\n")
    assert log.verify()[0] is False


def _reload_fixture(tmp_path: Path, marker: dict[str, object]) -> tuple[Path, ReflexConfig]:
    """A replayable decision followed by ``marker``, chained like a writer would."""
    path = tmp_path / "audit.jsonl"
    config = ReflexConfig(mode="enforce", audit={"enabled": True, "path": str(path)})
    AuditLog(config).write_entry(
        "ls",
        [],
        {},
        _decision("ALLOW"),
        risk_choice="low",
        risk_confidence=0.9,
        degraded=False,
        forced_review=False,
    )
    decision = json.loads(path.read_text())
    record = {
        "seq": 2,
        "timestamp_utc": decision["timestamp_utc"],
        "action_summary": "policy_reload",
        "hard_rule_findings": [],
        "jev_signals": {},
        "policy_decision": "ALLOW",
        "policy_version_hash": decision["policy_version_hash"],
        **marker,
    }
    path.write_text(_rechain([decision, {k: v for k, v in record.items() if v is not None}]))
    assert AuditLog(config).verify()[0] is True
    return path, config


def _decision_counts(path: Path, config: ReflexConfig, tmp_path: Path) -> list[object]:
    from jev_reflex.policy_rollout import simulate

    report = build_audit_report(path, config)
    replay = simulate(path, config, config)
    policy = tmp_path / "policy.yaml"
    policy.write_text("mode: enforce\n")
    team = snapshot(_dashboard(tmp_path, policy, path), Identity("operator", frozenset({"ops"})))
    return [
        report["decisions"]["ALLOW"],
        report["other_events"],
        replay["total"],
        replay["skipped_legacy"],
        team["teams"][0]["decisions"]["ALLOW"],
    ]


@pytest.mark.parametrize(
    "marker",
    [
        {},  # the untyped shape PolicyReloader wrote before reloads were typed
        {"policy_decision": None},  # no decision label at all
        {"policy_decision": ""},
    ],
)
def test_legacy_untyped_policy_reload_markers_are_reloads_in_every_reader(tmp_path, marker):
    path, config = _reload_fixture(tmp_path, marker)
    # One decision and one reload: no false ALLOW, no inflated replay totals, no failure.
    assert _decision_counts(path, config, tmp_path) == [1, 1, 1, 0, 1]


@pytest.mark.parametrize(
    "marker",
    [
        {"event_type": "policy_decision"},  # explicitly typed decisions stay decisions
        {"risk_choice": "low", "risk_confidence": 0.9, "degraded": False, "forced_review": False},
        {"hard_rule_findings": [{"check": "git", "triggered": False}]},
    ],
)
def test_decisions_that_only_share_the_reload_summary_stay_decisions(tmp_path, marker):
    path, config = _reload_fixture(tmp_path, marker)
    allow, other_events, total, *_, dashboard_allow = _decision_counts(path, config, tmp_path)
    assert (allow, other_events, total, dashboard_allow) == (2, 0, 2, 2)


@pytest.mark.parametrize("event_type", ["human_override", "", "POLICY_RELOAD"])
def test_write_entry_rejects_other_event_types(tmp_path, event_type):
    config = ReflexConfig(audit={"enabled": True, "path": str(tmp_path / "audit.jsonl")})
    with pytest.raises(ValueError, match="unsupported audit event type"):
        AuditLog(config).write_entry("x", [], {}, _decision("ALLOW"), event_type=event_type)


# ---------------------------------------------------------------------------
# PR review follow-ups: tail limits, replay framing, dashboard trust key.
# ---------------------------------------------------------------------------


def _display_log(tmp_path: Path, lines: list[str]) -> tuple[Path, ReflexConfig]:
    log = tmp_path / "audit.jsonl"
    log.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return log, ReflexConfig.model_validate({"audit": {"enabled": True, "path": str(log)}})


def test_tail_validates_display_fields_before_applying_the_limit(tmp_path, monkeypatch):
    lines = [
        json.dumps({"seq": 1, "policy_decision": "ALLOW", "action_summary": "ls"}),
        json.dumps({"action_summary": "older record without seq"}),
        json.dumps({"seq": True, "action_summary": "boolean seq"}),
        json.dumps({"seq": 2, "policy_decision": "HOLD", "action_summary": "rm"}),
        "{not json",
    ]
    log, config = _display_log(tmp_path, lines)
    assert [entry["seq"] for entry in AuditLog(config).tail(2)] == [2, 1]
    assert [entry["seq"] for entry in AuditLog(config).tail(1)] == [2]

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["audit", "tail", "-n", "2", "--path", str(log)])
    assert result.exit_code == 0, result.output
    assert "Seq: 2" in result.output and "Seq: 1" in result.output
    assert "without seq" not in result.output


def test_tail_reads_only_the_end_of_a_large_log(tmp_path, monkeypatch):
    lines = [json.dumps({"seq": index, "action_summary": "x" * 40}) for index in range(1, 20_001)]
    _, config = _display_log(tmp_path, lines)
    decoded = []
    original = AuditLog._display_record
    monkeypatch.setattr(
        AuditLog, "_display_record", staticmethod(lambda line: decoded.append(1) or original(line))
    )
    assert [entry["seq"] for entry in AuditLog(config).tail(3)] == [20_000, 19_999, 19_998]
    assert len(decoded) <= 5  # the trailing newline's empty line plus three records


@pytest.mark.parametrize("block", [1, 2, 3, 7, 4096])
def test_reverse_line_reader_keeps_multibyte_text_across_block_boundaries(tmp_path, block):
    lines = [
        "é première",
        "ü✓ zweite",
        "",
        "日本語 third",
        "\udc80".encode("utf-8", "surrogatepass").decode("latin-1"),
    ]
    log = tmp_path / "audit.jsonl"
    log.write_bytes(
        b"".join(line.encode("utf-8", "surrogatepass") + b"\n" for line in lines[:4])
        + b"\xff\xfe broken\n"
    )
    config = ReflexConfig.model_validate({"audit": {"enabled": True, "path": str(log)}})
    found = list(AuditLog(config)._lines_from_end(block=block))
    # Invalid UTF-8 lines are skipped; everything else comes back newest first.
    assert found == ["", *reversed(lines[:4])]


def test_tail_of_a_missing_or_empty_log_is_empty(tmp_path):
    config = ReflexConfig.model_validate(
        {"audit": {"enabled": True, "path": str(tmp_path / "missing.jsonl")}}
    )
    assert AuditLog(config).tail(5) == []
    (tmp_path / "missing.jsonl").write_text("")
    assert AuditLog(config).tail(5) == []


def test_plain_tail_renders_malformed_findings_and_signals_without_failing(tmp_path, monkeypatch):
    lines = [
        json.dumps(
            {
                "seq": 1,
                "policy_decision": "HOLD",
                "action_summary": "well formed",
                "hard_rule_findings": [{"check": "git", "reason_code": "push", "triggered": True}],
                "jev_signals": {"unsafe": 0.5},
            }
        ),
        json.dumps(
            {
                "seq": 2,
                "policy_decision": "HOLD",
                "action_summary": "malformed items",
                "hard_rule_findings": ["bare", {"check": "partial"}, 7],
                "jev_signals": {"unsafe": "high", "huge": 10**400, "none": None},
            }
        ),
        json.dumps(
            {
                "seq": 3,
                "policy_decision": "HOLD",
                "action_summary": "malformed containers",
                "hard_rule_findings": "not a list",
                "jev_signals": ["not", "a", "mapping"],
            }
        ),
    ]
    log, _ = _display_log(tmp_path, lines)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["audit", "tail", "-n", "3", "--path", str(log)])
    # A malformed record must not stop the listing after partial output.
    assert result.exit_code == 0, result.output
    assert result.output.count("---") == 3
    for seq in (1, 2, 3):
        assert f"Seq: {seq}" in result.output
    assert "  - git: push (triggered: True)" in result.output  # well-formed output unchanged
    assert "  - unsafe: 0.50" in result.output
    assert "  - unsafe: high" in result.output
    assert "  - bare" in result.output and "  - not a list" in result.output


@pytest.mark.parametrize("separator", [b"\r\n", b"\r"])
def test_policy_replay_rejects_separators_that_verification_rejects(tmp_path, separator):
    from jev_reflex.policy_rollout import simulate

    log = tmp_path / "audit.jsonl"
    config = ReflexConfig.model_validate(
        {"mode": "enforce", "audit": {"enabled": True, "path": str(log)}}
    )
    for command in ("ls", "pwd"):
        AuditLog(config).write_entry(
            command,
            [],
            {},
            PolicyDecision("ALLOW", (), ()),
            risk_choice="low",
            risk_confidence=0.9,
            degraded=False,
            forced_review=False,
        )
    assert simulate(log, config, config)["total"] == 2
    log.write_bytes(log.read_bytes().replace(b"\n", separator))
    assert AuditLog(config).verify()[0] is False
    with pytest.raises(ValueError, match="verification failed"):
        simulate(log, config, config)


@pytest.mark.parametrize("require_signature", [False, True])
def test_dashboard_never_lets_an_unsigned_policy_choose_the_audit_key(
    tmp_path, monkeypatch, require_signature
):
    import jev_reflex.signing as signing

    monkeypatch.setenv("HOME", str(tmp_path))
    operator_private, operator_public = _signing_keys(tmp_path)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    attacker_private, attacker_public = _signing_keys(attacker)
    log = tmp_path / "audit.jsonl"
    forged = ReflexConfig.model_validate(
        {
            "audit": {"enabled": True, "path": str(log)},
            "signing": {"private_key_path": str(attacker_private)},
        }
    )
    AuditLog(forged).write_entry("rm -rf /prod", [], {}, PolicyDecision("ALLOW", (), ()))
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "mode: enforce\nsigning:\n"
        f"  require_signature: {str(require_signature).lower()}\n"
        f"  public_key_path: {attacker_public}\n"
    )

    loaded: list[Path] = []
    real_load = signing.load_public_key
    monkeypatch.setattr(
        signing, "load_public_key", lambda path: loaded.append(path) or real_load(path)
    )
    identity = Identity("operator", frozenset({"ops"}))
    team = snapshot(_dashboard(tmp_path, policy, log), identity)["teams"][0]
    # Without a pinned key nothing vouches for signatures, and the policy's key is unused.
    assert attacker_public not in loaded
    if require_signature:
        assert team["audit_integrity"]["valid"] is False  # it can only fail closed
        assert "decisions" not in team
    else:
        assert "signature" not in team["audit_integrity"]["message"]

    pinned = _dashboard(tmp_path, policy, log)
    pinned.sources[0].audit_public_key_path = str(operator_public)
    team = snapshot(pinned, identity)["teams"][0]
    assert team["audit_integrity"]["valid"] is False  # only the operator key is trusted
    assert "decisions" not in team
    assert operator_private.exists()
    assert loaded == [operator_public]  # the source policy's key is never loaded
