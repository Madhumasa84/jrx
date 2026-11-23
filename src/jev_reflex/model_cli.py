"""Handlers for the optional local model cache commands."""

from __future__ import annotations

import json
from importlib.util import find_spec
from pathlib import Path

import typer

from .config import load_config
from .model_files import ModelError, installed_models, pull_model, verify_model


def pull(model_id: str | None, config: Path | None) -> None:
    try:
        policy = load_config(config)
        evaluator = policy.evaluator
        model = pull_model(
            model_id or evaluator.local_model,
            evaluator.model_dir,
            config=policy if evaluator.provider != "jev" and not evaluator.local_base_url else None,
        )
    except (ModelError, ValueError, OSError) as exc:
        typer.echo(f"Model pull failed. {exc}", err=True)
        raise typer.Exit(1) from None
    typer.echo(
        f"Installed {model.model_id} ({model.size_bytes:,} bytes, bundle SHA-256 {model.digest})."
    )


def status(config: Path | None, json_output: bool) -> None:
    try:
        evaluator = load_config(config).evaluator
        models = installed_models(evaluator.model_dir)
    except (ModelError, ValueError, OSError) as exc:
        typer.echo(f"Model status failed. {exc}", err=True)
        raise typer.Exit(1) from None

    available = find_spec("onnxruntime") is not None
    if json_output:
        typer.echo(json.dumps({"onnxruntime_available": available, "models": models}))
        return
    typer.echo(f"ONNX Runtime is {'available' if available else 'unavailable'}.")
    if not models:
        typer.echo("No local models installed.")
    for model in models:
        message = "verified" if model["verified"] else f"unverified ({model['error']})"
        size = model["size_bytes"]
        display_size = f"{size:,} bytes" if size is not None else "size unavailable"
        typer.echo(f"{model['model_id']}  {display_size}  {message}")


def verify(model_id: str | None, config: Path | None) -> None:
    try:
        evaluator = load_config(config).evaluator
        model = verify_model(model_id or evaluator.local_model, evaluator.model_dir)
    except (ModelError, ValueError, OSError) as exc:
        typer.echo(f"Model verification failed. {exc}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"Verified {model.model_id} (manifest SHA-256 {model.manifest_sha256}).")
