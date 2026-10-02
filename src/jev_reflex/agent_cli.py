"""Operator CLI for optional host-controlled intent and authority stores."""

from __future__ import annotations

import getpass
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import typer

from .agent_controls import host_subject, policy_revision
from .agent_state import create_host_key
from .authority import AuthorityStore
from .config import ReflexConfig, load_config
from .enterprise import authorize, verified_identity
from .intent import IntentStore

intent_app = typer.Typer(help="Create and inspect host-approved task envelopes.")
authority_app = typer.Typer(help="Issue, inspect and revoke scoped agent authority leases.")


@contextmanager
def operation() -> Iterator[None]:
    try:
        yield
    except (OSError, ValueError, RuntimeError):
        typer.echo("Agent control operation denied or state unavailable.", err=True)
        raise typer.Exit(2) from None


def operator(config: ReflexConfig, repository: str, action: str = "admin") -> str:
    if config.access is not None:
        identity = verified_identity(config.access)
        authorize(
            identity,
            config.access,
            action,
            str(Path(repository).resolve()),
            config.access.environment,
        )
        return identity.subject
    # Without OIDC these commands are host administration, protected by the OS.
    return os.environ.get("JRX_AGENT_ID") or getpass.getuser()


@intent_app.command("keygen")
def intent_keygen(
    config: Path = typer.Option(..., "--config"),
    repository: Path = typer.Option(..., "--repository"),
) -> None:
    with operation():
        loaded = load_config(config)
        operator(loaded, str(repository))
        create_host_key(Path(loaded.intent.key_path))
        typer.echo("Host control key created.")


@intent_app.command("create")
def intent_create(
    session_id: str,
    config: Path = typer.Option(..., "--config"),
    task: str = typer.Option(..., "--task"),
    repository: Path = typer.Option(..., "--repository"),
    scope: list[str] = typer.Option(..., "--scope"),
    capability: list[str] = typer.Option(..., "--capability"),
    forbidden: list[str] = typer.Option([], "--forbidden"),
    max_drift_score: float = typer.Option(1.0, "--max-drift-score"),
) -> None:
    with operation():
        loaded = load_config(config)
        operator(loaded, str(repository))
        result = IntentStore(loaded.intent).create(
            session_id=session_id,
            task=task,
            repository=str(repository),
            scopes=scope,
            capabilities=capability,
            forbidden=forbidden,
            max_drift_score=max_drift_score,
            policy_revision=policy_revision(loaded),
        )
        typer.echo(json.dumps(result))


@intent_app.command("status")
def intent_status(session_id: str, config: Path = typer.Option(..., "--config")) -> None:
    with operation():
        loaded = load_config(config)
        result = IntentStore(loaded.intent).status(session_id)
        operator(loaded, result["repository"], "view")
        typer.echo(json.dumps(result))


@intent_app.command("explain")
def intent_explain(session_id: str, config: Path = typer.Option(..., "--config")) -> None:
    with operation():
        loaded = load_config(config)
        store = IntentStore(loaded.intent)
        operator(loaded, store.status(session_id)["repository"], "view")
        typer.echo(json.dumps(store.explain(session_id)))


@intent_app.command("stop")
def intent_stop(session_id: str, config: Path = typer.Option(..., "--config")) -> None:
    with operation():
        loaded = load_config(config)
        store = IntentStore(loaded.intent)
        operator(loaded, store.status(session_id)["repository"])
        store.stop(session_id)
        typer.echo("Intent session stopped.")


@authority_app.command("keygen")
def authority_keygen(
    config: Path = typer.Option(..., "--config"),
    repository: Path = typer.Option(..., "--repository"),
) -> None:
    with operation():
        loaded = load_config(config)
        operator(loaded, str(repository))
        create_host_key(Path(loaded.authority.key_path))
        typer.echo("Host control key created.")


@authority_app.command("issue")
def authority_issue(
    subject: str,
    session_id: str,
    config: Path = typer.Option(..., "--config"),
    repository: Path = typer.Option(..., "--repository"),
    scope: list[str] = typer.Option(..., "--scope"),
    capability: list[str] = typer.Option(..., "--capability"),
    forbidden: list[str] = typer.Option([], "--forbidden"),
    ttl_seconds: int = typer.Option(900, "--ttl-seconds"),
    parent_id: str | None = typer.Option(None, "--parent-id"),
) -> None:
    with operation():
        loaded = load_config(config)
        issuer = operator(loaded, str(repository)) if parent_id is None else host_subject(loaded)
        if parent_id is not None and loaded.access is not None:
            operator(loaded, str(repository), "execute")
        result = AuthorityStore(loaded.authority).issue(
            issuer=issuer,
            issuer_session=os.environ.get("JRX_SESSION_ID", "host-operator"),
            subject=subject,
            session_id=session_id,
            repository=str(repository),
            environment=loaded.authority.environment,
            scopes=scope,
            capabilities=capability,
            forbidden=forbidden,
            ttl_seconds=ttl_seconds,
            policy_revision=policy_revision(loaded),
            parent_id=parent_id,
        )
        typer.echo(json.dumps(result))


@authority_app.command("inspect")
def authority_inspect(lease_id: str, config: Path = typer.Option(..., "--config")) -> None:
    with operation():
        loaded = load_config(config)
        result = AuthorityStore(loaded.authority).inspect(lease_id)
        operator(loaded, result["repository"], "view")
        typer.echo(json.dumps(result))


@authority_app.command("revoke")
def authority_revoke(lease_id: str, config: Path = typer.Option(..., "--config")) -> None:
    with operation():
        loaded = load_config(config)
        store = AuthorityStore(loaded.authority)
        operator(loaded, store.inspect(lease_id)["repository"])
        store.revoke(lease_id)
        typer.echo("Authority lease revoked.")


@authority_app.command("tree")
def authority_tree(lease_id: str, config: Path = typer.Option(..., "--config")) -> None:
    with operation():
        loaded = load_config(config)
        store = AuthorityStore(loaded.authority)
        operator(loaded, store.inspect(lease_id)["repository"], "view")
        typer.echo(json.dumps(store.tree(lease_id)))
