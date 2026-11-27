"""`jrx policy` commands: linting, signing, impact, staged rollout and trust status.

Moved unchanged from cli.py so the operator-facing policy and trust surface can be
reviewed on its own; cli.py registers ``policy_app``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal, cast

import typer

from .config import ReflexConfig
from .formatters import terminal_line
from .serialization import read_config_bytes, safe_yaml_load
from .signing import CosignSigner, Ed25519Signer, Signer, load_public_key, sign_file, verify_file

policy_app = typer.Typer(name="policy", help="Policy file signing and verification.")
rollout_app = typer.Typer(
    name="rollout", help="Stage, promote, and roll back signed policy revisions."
)
policy_app.add_typer(rollout_app, name="rollout")


def _parse_policy_file(raw: bytes) -> ReflexConfig:
    value = safe_yaml_load(raw.decode("utf-8"))
    return ReflexConfig.model_validate(value)


@policy_app.command("lint")
def policy_lint(
    config: Path = typer.Option(
        Path("reflex.yaml"), "-c", "--config", help="Candidate policy file to check offline."
    ),
    strict: bool = typer.Option(False, "--strict", help="Also fail on warnings."),
    profile: str = typer.Option("standard", "--profile", help="standard or production."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable diagnostics."),
) -> None:
    """Find policy mistakes without activating the policy or calling external services."""
    from .policy_lint import lint_policy
    from .redaction import redact_obj

    if profile not in {"standard", "production"}:
        raise typer.BadParameter("profile must be standard or production")
    report = redact_obj(
        lint_policy(config, profile=cast(Literal["standard", "production"], profile))
    )
    if json_output:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        typer.echo(f"Policy lint: {report['errors']} errors, {report['warnings']} warnings")
        for issue in report["issues"]:
            typer.echo(
                f"{issue['severity'].upper()} {issue['path'] or '<root>'}: {issue['message']} [{issue['code']}]"
            )
    if report["errors"] or (strict and report["warnings"]):
        raise typer.Exit(code=1)


@policy_app.command("simulate")
def policy_simulate(
    audit: Path = typer.Option(..., "--audit"),
    baseline: Path = typer.Option(..., "--baseline"),
    candidate: Path = typer.Option(..., "--candidate"),
    public_key: Path | None = typer.Option(
        None, "--public-key", help="Trusted audit verification key."
    ),
) -> None:
    """Replay verified audit decisions against a proposed policy without model calls."""
    from .policy_rollout import simulate

    try:
        report = simulate(
            audit,
            _parse_policy_file(read_config_bytes(baseline)),
            _parse_policy_file(read_config_bytes(candidate)),
            public_key=public_key,
        )
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    except Exception:
        # YAML, model and audit diagnostics can contain private input.
        typer.echo("Policy simulation failed; check the audit chain and input policies.", err=True)
        raise typer.Exit(code=2) from None


@policy_app.command("impact")
def policy_impact(
    audit: Path = typer.Option(..., "--audit"),
    baseline: Path = typer.Option(..., "--baseline"),
    candidate: Path = typer.Option(..., "--candidate"),
    public_key: Path | None = typer.Option(
        None, "--public-key", help="Trusted audit verification key."
    ),
    max_new_allows: int | None = typer.Option(None, "--max-new-allows", min=0),
    max_relaxations: int | None = typer.Option(
        None,
        "--max-relaxations",
        min=0,
        help=(
            "Limit new ALLOW and HOLD-to-REVIEW decisions combined. With any limit set, a "
            "candidate whose mode runs a decision class the baseline blocked also fails."
        ),
    ),
    github_output: Path | None = typer.Option(None, "--github-output"),
) -> None:
    """Preview a candidate policy using aggregate audit replay counts."""
    from .policy_impact import impact_report

    try:
        report = impact_report(audit, baseline, candidate, public_key=public_key)
    except Exception:
        # Policy values and private audit data can appear in diagnostics.
        typer.echo("Unassessed. Check policy syntax, replay support and audit integrity.")
        raise typer.Exit(2) from None

    typer.echo(report.markdown())
    if not report.replayed:
        typer.echo("\nUnassessed. No matching decisions could be replayed.")
        raise typer.Exit(2)
    if github_output is not None:
        try:
            with github_output.open("a", encoding="utf-8") as stream:
                stream.write(f"counts={report.summary()}\n")
        except OSError:
            typer.echo("Could not write the GitHub output file.", err=True)
            raise typer.Exit(2) from None
    if max_new_allows is not None and report.new_allows > max_new_allows:
        typer.echo(f"\nNew ALLOW decisions exceed the limit of {max_new_allows}.")
        raise typer.Exit(1)
    if max_relaxations is not None and report.relaxations > max_relaxations:
        typer.echo(f"\nPolicy relaxations exceed the limit of {max_relaxations}.")
        raise typer.Exit(1)
    if (max_new_allows is not None or max_relaxations is not None) and (
        report.enforcement_relaxations
    ):
        typer.echo("\nThe candidate's mode relaxes enforcement, which no limit allows.")
        raise typer.Exit(1)


def _rollout_store(bootstrap: Path):
    from .config import load_bootstrap_config
    from .policy_rollout import RolloutStore

    settings = load_bootstrap_config(bootstrap)
    if not settings.rollout_state_path:
        raise ValueError("bootstrap rollout_state_path is required")
    return settings, RolloutStore(Path(settings.rollout_state_path), settings)


@rollout_app.command("stage")
def policy_rollout_stage(
    bootstrap: Path = typer.Option(..., "--bootstrap"),
    baseline: Path = typer.Option(..., "--baseline"),
    audit: Path = typer.Option(..., "--audit"),
    public_key: Path | None = typer.Option(
        None, "--public-key", help="Trusted audit verification key."
    ),
    max_new_allows: int = typer.Option(
        0,
        "--max-new-allows",
        min=0,
        help=(
            "Limit replayed decisions the candidate newly lets execute: any change to ALLOW, "
            "plus decisions the baseline's mode blocked and the candidate's mode runs (for "
            "example HOLD to REVIEW under enforce, or any HOLD under advisory). A candidate "
            "whose mode runs a decision class the baseline blocked is always rejected."
        ),
    ),
) -> None:
    """Fetch a signed remote candidate and stage it after an offline replay."""
    from .config import parse_policy_bytes, verify_policy_signature
    from .policy_rollout import SignedPolicy, policy_hash, simulate
    from .policy_source import PolicyFetcher

    try:
        settings, store = _rollout_store(bootstrap)
        if settings.policy_source.type is None:
            raise ValueError("a signed policy source is required")
        baseline_bytes = read_config_bytes(baseline)
        baseline_signature = None
        if settings.require_signature:
            # Store exactly the bytes and signature verified here, so every
            # later read can verify the snapshot again.
            baseline_signature = read_config_bytes(baseline.with_suffix(baseline.suffix + ".sig"))
            verify_policy_signature(baseline_bytes, baseline_signature, settings)
        active = parse_policy_bytes(baseline_bytes)
        baseline_snapshot: ReflexConfig | SignedPolicy = (
            active
            if baseline_signature is None
            else SignedPolicy(baseline_bytes, baseline_signature, "bootstrap")
        )
        current = store.status()
        if current["active_hash"] and current["active_hash"] != policy_hash(active):
            raise ValueError("baseline policy differs from active rollout policy")
        fetched = PolicyFetcher(settings.policy_source).fetch_signed()
        candidate = parse_policy_bytes(fetched.raw)
        report = simulate(audit, active, candidate, public_key=public_key)
        if report["replayed"] == 0 or report["newly_executable"] > max_new_allows:
            raise ValueError("simulation gate failed")
        if report["enforcement_relaxations"]:
            # A weaker mode lets a whole decision class run, which no replay count bounds.
            raise ValueError("candidate relaxes enforcement")
        store.stage(
            baseline_snapshot, SignedPolicy(fetched.raw, fetched.signature, "policy_source")
        )
        typer.echo(json.dumps({"status": store.status(), "simulation": report}, indent=2))
    except Exception as exc:
        typer.echo(f"Policy stage failed: {type(exc).__name__}.", err=True)
        raise typer.Exit(code=2) from None


@rollout_app.command("promote")
def policy_rollout_promote(
    percent: int = typer.Option(..., "--percent", min=1, max=100),
    bootstrap: Path = typer.Option(..., "--bootstrap"),
) -> None:
    """Activate a stable percentage of repositories or fully promote a candidate."""
    try:
        _, store = _rollout_store(bootstrap)
        store.promote(percent)
        typer.echo(json.dumps(store.status(), indent=2))
    except (OSError, ValueError):
        typer.echo("Policy promotion failed.", err=True)
        raise typer.Exit(code=2) from None


@rollout_app.command("rollback")
def policy_rollout_rollback(bootstrap: Path = typer.Option(..., "--bootstrap")) -> None:
    """Restore the active policy and clear a staged candidate."""
    try:
        _, store = _rollout_store(bootstrap)
        store.rollback()
        typer.echo(json.dumps(store.status(), indent=2))
    except (OSError, ValueError):
        typer.echo("Policy rollback failed.", err=True)
        raise typer.Exit(code=2) from None


@rollout_app.command("status")
def policy_rollout_status(bootstrap: Path = typer.Option(..., "--bootstrap")) -> None:
    """Show active, candidate, and previous policy revisions."""
    try:
        _, store = _rollout_store(bootstrap)
        typer.echo(json.dumps(store.status(), indent=2))
    except (OSError, ValueError):
        typer.echo("Policy rollout status unavailable.", err=True)
        raise typer.Exit(code=2) from None


@policy_app.command("keygen")
def policy_keygen(
    output_dir: Path = typer.Option(..., "--output-dir", help="Directory for the signing keypair."),
) -> None:
    """Generate an Ed25519 policy signing keypair."""
    directory = output_dir.expanduser()
    private_path = directory / "policy_signing.key"
    public_path = directory / "policy_signing.pub"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if private_path.exists() or public_path.exists():
            raise FileExistsError("Policy signing keypair already exists")
        signer = Ed25519Signer()
        descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as private_file:
            private_file.write(signer.get_private_key_pem())
        with public_path.open("x", encoding="utf-8") as public_file:
            public_file.write(signer.get_public_key_pem())
        typer.echo(f"Private key written to: {private_path}")
        typer.echo(f"Public key written to: {public_path}")
    except Exception as exc:
        typer.echo(f"Error generating policy keypair: {exc}", err=True)
        raise typer.Exit(code=1) from None


@policy_app.command("verify")
def policy_verify(
    config_path: Path = typer.Argument(..., help="Path to the signed policy file."),
    public_key: Path = typer.Option(..., "--public-key", help="Path to the public key."),
    signature: Path | None = typer.Option(None, "--signature", help="Path to the signature file."),
    signer_type: str = typer.Option("ed25519", "--signer-type", help="ed25519 or cosign."),
) -> None:
    """Verify a policy signature against a pinned public key."""
    try:
        signer: Signer
        if signer_type == "ed25519":
            signer = Ed25519Signer()
        elif signer_type == "cosign":
            signer = CosignSigner()
        else:
            raise typer.BadParameter("signer_type must be ed25519 or cosign")
        config_file = config_path.expanduser()
        signature_file = (
            signature.expanduser()
            if signature
            else config_file.with_suffix(config_file.suffix + ".sig")
        )
        key = load_public_key(public_key.expanduser())
        if not verify_file(config_file, signature_file, key, signer):
            typer.echo("Policy signature verification failed.", err=True)
            raise typer.Exit(code=1)
        typer.echo("Policy signature verified.")
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"Error verifying policy: {exc}", err=True)
        raise typer.Exit(code=1) from None


@policy_app.command("sign")
def policy_sign(
    config_path: Path = typer.Argument(..., help="Path to reflex.yaml to sign."),
    key: Path = typer.Option(None, "--key", help="Path to private key file."),
    signer_type: str = typer.Option(
        "ed25519", "--signer-type", help="Signer type: ed25519 or cosign."
    ),
    output: Path | None = typer.Option(None, "--output", help="Output path for signature file."),
) -> None:
    """Sign a policy configuration file."""

    try:
        signer: Signer
        if signer_type not in {"ed25519", "cosign"}:
            raise typer.BadParameter("signer_type must be ed25519 or cosign")
        if key is None:
            # Generate a new keypair if no key is provided
            if signer_type == "ed25519":
                signer = Ed25519Signer()
                typer.echo("Generated new Ed25519 keypair")
                typer.echo(f"Public key (PEM):\n{signer.get_public_key_pem()}")
                typer.echo(f"Private key (PEM):\n{signer.get_private_key_pem()}")
                typer.echo("")
                typer.echo("Save the private key securely and use the public key for verification.")
                typer.echo("Example bootstrap.yaml:")
                typer.echo("  require_signature: true")
                typer.echo("  public_key_path: /path/to/public_key.pem")
                typer.echo("  signer_type: ed25519")
            else:
                raise typer.BadParameter("key is required for cosign signer")
        else:
            # Load existing key
            key_path = Path(key).expanduser()
            if signer_type == "ed25519":
                signer = Ed25519Signer(private_key_path=key_path)
            elif signer_type == "cosign":
                signer = CosignSigner(private_key_path=key_path)

        config_file = Path(config_path).expanduser()
        if not config_file.exists():
            raise typer.BadParameter(f"Config file not found: {config_file}")

        signature_path = sign_file(config_file, signer, output)
        typer.echo(f"Signature written to: {signature_path}")
    except Exception as e:
        typer.echo(f"Error signing policy: {e}", err=True)
        raise typer.Exit(code=1) from None


def _echo_trust(report: dict[str, Any]) -> None:
    def where(item: dict[str, Any] | None) -> str:
        if item is None:
            return "not used"
        owner = "operator-controlled" if item["operator_controlled"] else "writable by you"
        missing = "" if item["exists"] else ", missing"
        return f"{terminal_line(item['path'])} ({owner}{missing})"

    evaluator = report["evaluator"]
    privileged = " (privileged: nothing is protected)" if evaluator["privileged"] else ""
    typer.echo(f"Evaluating user: uid {evaluator['uid']}{privileged}")
    bootstrap = report["bootstrap"]
    if bootstrap["path"] is None:
        typer.echo("Bootstrap: none (signatures not required)")
    else:
        owner = "operator-controlled" if bootstrap["operator_controlled"] else "writable by you"
        typer.echo(f"Bootstrap: {terminal_line(bootstrap['path'])} ({owner})")
    required = "required" if report["require_signature"] else "not required"
    typer.echo(f"Policy signature: {required}; public key: {where(report['public_key'])}")
    typer.echo(f"Policy file: {where(report['policy'])}")
    typer.echo(f"Rollout state: {where(report['rollout_state'])}")
    protected = report["policy_protected_from_evaluating_user"]
    typer.echo(
        "Effective policy protected from the evaluating user: " + ("yes" if protected else "no")
    )
    for issue in report["issues"]:
        typer.echo(f"Evaluation will refuse: {terminal_line(issue)}")


@policy_app.command("status")
def policy_status(
    config: Path | None = typer.Option(
        None, "--config", help="Policy file to assess (default: ./reflex.yaml)."
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit the trust report as JSON."),
) -> None:
    """Show the configured central policy source and which policy inputs are trusted."""
    from .config import load_bootstrap_config, trust_report

    try:
        bootstrap = load_bootstrap_config()
        report = trust_report(config)
    except (OSError, ValueError) as exc:
        typer.echo(f"Policy status unavailable: {terminal_line(exc)}", err=True)
        raise typer.Exit(code=2) from None
    if json_output:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
        return
    _echo_trust(report)

    if bootstrap.policy_source.type is None:
        typer.echo("Policy source: local (reflex.yaml)")
        typer.echo("No central policy configured")
        return

    typer.echo(f"Policy source type: {bootstrap.policy_source.type}")
    typer.echo(f"Policy source URI: {bootstrap.policy_source.uri}")
    if bootstrap.policy_source.ref:
        typer.echo(f"Policy source ref: {bootstrap.policy_source.ref}")
    # Runtime never polls or merges the central source; only staging reads it.
    typer.echo(
        "Runtime policy: reflex.yaml, replaced by the active or canary revision when "
        "rollout state exists. The central source is read only by `jrx policy rollout stage`."
    )
    if bootstrap.rollout_state_path:
        typer.echo(f"Rollout state: {bootstrap.rollout_state_path}")
        typer.echo("Run `jrx policy rollout status --bootstrap <file>` for active revisions.")
    else:
        typer.echo("Rollout state: not configured; the central policy is not applied.")


@policy_app.command("test")
def policy_test(
    fixtures: Path | None = typer.Option(
        None, "--fixtures", help="Directory containing golden policy fixtures."
    ),
    config: Path | None = typer.Option(
        None, "-c", "--config", help="Path to reflex.yaml configuration to test."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format."),
) -> None:
    """Run golden fixture regression suite against a policy configuration."""
    from .golden_runner import run_fixtures

    config_path = config
    if config_path is None:
        if Path("reflex.yaml").exists():
            config_path = Path("reflex.yaml")
        elif Path("reflex.example.yaml").exists():
            config_path = Path("reflex.example.yaml")

    try:
        report = run_fixtures(fixtures_dir=fixtures, config_path=config_path)
    except Exception as e:
        typer.echo(f"Error running policy fixtures: {e}", err=True)
        raise typer.Exit(code=1) from None

    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        typer.echo(report.summary_table())

    if not report.all_passed:
        raise typer.Exit(code=1)
