"""Install and verify the self-contained Coba ONNX model bundle."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from errno import ELOOP, ENOTDIR
from importlib import import_module
from pathlib import Path
from typing import Any
from uuid import uuid4

from .config import DEFAULT_MODEL_DIR, DEFAULT_MODEL_ID

INSTALL_LOCAL = 'pip install "jev-reflex[local]"'
PULL_MODEL = "jrx model pull"

_MODEL_COMPONENT = r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,94}[A-Za-z0-9_])?"
_MODEL_ID = re.compile(rf"{_MODEL_COMPONENT}/{_MODEL_COMPONENT}")
_REVISION = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GENERATION = re.compile(r"snapshot-[0-9a-f]{32}")
_MANIFEST = "manifest.json"
_MANIFEST_LIMIT = 16_384
_GRAPH = "onnx/model.onnx"
_FILES = (_GRAPH, "tokenizer.json", "calibration.json", "decision.json", "LICENSE", "NOTICE")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


class ModelError(RuntimeError):
    """The local model cannot be installed or used safely."""


@dataclass(frozen=True)
class VerifiedModel:
    model_id: str
    graph: Path
    tokenizer: Path
    calibration: Path
    decision: Path
    digest: str
    manifest_sha256: str
    size_bytes: int
    revision: str
    _cache: Path
    _asset_hashes: dict[Path, str]

    def read_asset(self, file: Path) -> bytes:
        """Verify the exact bytes the tokenizer or inference runtime will consume."""
        expected = self._asset_hashes[file]
        with _open_cache_file(self._cache, file) as stream:
            contents = stream.read()
        if hashlib.sha256(contents).hexdigest() != expected:
            raise ModelError("Local model artifact changed after verification.")
        return contents


def canonical_model_id(model_id: str) -> str:
    if model_id == "coba-68m-ternary":
        return DEFAULT_MODEL_ID
    if (
        not _MODEL_ID.fullmatch(model_id)
        or ".." in model_id
        or "--" in model_id
        or model_id.endswith(".git")
    ):
        raise ModelError(
            "Expected a Hugging Face model ID in owner/model form or coba-68m-ternary."
        )
    return model_id


def _cache_directory(model_dir: str | Path) -> Path:
    try:
        path = Path(model_dir).expanduser().absolute()
        if ".." in path.parts:
            raise ValueError("parent path component")
        # Resolve platform aliases above the trust boundary, such as macOS /var.
        # The configured cache root itself must be a real directory.
        return path.parent.resolve() / path.name
    except (OSError, RuntimeError, ValueError):
        raise ModelError("Cannot resolve evaluator.model_dir.") from None


def _trusted_permissions(info: os.stat_result) -> None:
    if info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
        raise ModelError(
            "Local model cache requires trusted owners and non-writable group/world permissions."
        )


@contextmanager
def _open_cache_directory(cache: Path, directory: Path, *, create: bool = False) -> Iterator[int]:
    if not directory.is_relative_to(cache) or ".." in directory.parts:
        raise ModelError("Local model directory is outside the configured cache.")
    descriptor = os.open(directory.anchor, _DIRECTORY_FLAGS)
    try:
        first_trusted = len(cache.parts) - 1
        if first_trusted == 0:
            _trusted_permissions(os.fstat(descriptor))
        for position, component in enumerate(directory.parts[1:], start=1):
            if create:
                with suppress(FileExistsError):
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                if exc.errno in {ELOOP, ENOTDIR}:
                    raise ModelError(
                        "Local model cache requires real directories without symbolic links."
                    ) from None
                raise
            os.close(descriptor)
            descriptor = child
            if position >= first_trusted:
                _trusted_permissions(os.fstat(descriptor))
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _open_cache_file(cache: Path, file: Path) -> Iterator[io.BufferedReader]:
    with _open_cache_directory(cache, file.parent) as parent:
        try:
            descriptor = os.open(file.name, _READ_FLAGS, dir_fd=parent)
        except OSError as exc:
            if exc.errno == ELOOP:
                raise ModelError(
                    f"Local model artifact {file.name} must not be a symbolic link."
                ) from None
            raise
        with open(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ModelError(f"Expected a regular file for local model artifact {file.name}.")
            _trusted_permissions(info)
            yield stream


def _read_manifest(model_id: str, cache: Path) -> tuple[dict[str, Any], str]:
    with _open_cache_file(cache, cache / model_id / _MANIFEST) as stream:
        raw = stream.read(_MANIFEST_LIMIT + 1)
    try:
        data = json.loads(raw) if len(raw) <= _MANIFEST_LIMIT else None
    except (ValueError, RecursionError):
        data = None
    if (
        not isinstance(data, dict)
        or data.get("version") != 1
        or data.get("model_id") != model_id
        or not isinstance(data.get("revision"), str)
        or not _REVISION.fullmatch(data["revision"])
        or not isinstance(data.get("generation"), str)
        or not _GENERATION.fullmatch(data["generation"])
        or not isinstance(data.get("sha256"), dict)
        or data["sha256"].keys() != set(_FILES)
        or any(
            not isinstance(digest, str) or not _SHA256.fullmatch(digest)
            for digest in data["sha256"].values()
        )
    ):
        raise ModelError(f"Local model {model_id} has an invalid manifest.")
    return data, hashlib.sha256(raw).hexdigest()


def _snapshot_paths(snapshot: Path) -> dict[str, Path]:
    return {name: snapshot / name for name in _FILES}


def _artifact_digest(cache: Path, path: Path) -> tuple[str, int]:
    with _open_cache_file(cache, path) as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest(), os.fstat(stream.fileno()).st_size


def _verify_hashes(cache: Path, files: dict[str, Path], expected: dict[str, str]) -> int:
    total_size = 0
    for name, path in files.items():
        digest, size = _artifact_digest(cache, path)
        if digest != expected[name]:
            raise ModelError(f"SHA-256 mismatch for local model artifact {name}.")
        total_size += size
    return total_size


def verify_model(model_id: str, model_dir: str | Path = DEFAULT_MODEL_DIR) -> VerifiedModel:
    """Verify the published manifest and every required file before returning their paths."""
    model_id = canonical_model_id(model_id)
    try:
        cache = _cache_directory(model_dir)
        manifest, manifest_sha256 = _read_manifest(model_id, cache)
        files = _snapshot_paths(cache / model_id / manifest["generation"])
        size = _verify_hashes(cache, files, manifest["sha256"])
    except FileNotFoundError:
        raise ModelError(f"Local model {model_id} is missing. Run `{PULL_MODEL}`.") from None
    except ModelError as exc:
        raise ModelError(f"{exc} Run `{PULL_MODEL}`.") from None
    except (OSError, RuntimeError):
        raise ModelError(f"Cannot read local model {model_id}. Run `{PULL_MODEL}`.") from None
    return VerifiedModel(
        model_id=model_id,
        graph=files[_GRAPH],
        tokenizer=files["tokenizer.json"],
        calibration=files["calibration.json"],
        decision=files["decision.json"],
        digest=manifest["sha256"][_GRAPH],
        manifest_sha256=manifest_sha256,
        size_bytes=size,
        revision=manifest["revision"],
        _cache=cache,
        _asset_hashes={file: manifest["sha256"][name] for name, file in files.items()},
    )


def _catalog(hub: Any, model_id: str) -> tuple[str, dict[str, Any]]:
    try:
        info = hub.HfApi().model_info(model_id, files_metadata=True, token=False)
    except Exception as exc:
        raise ModelError(
            f"Could not resolve {model_id} on Hugging Face ({type(exc).__name__})."
        ) from None
    if not isinstance(info.sha, str) or not _REVISION.fullmatch(info.sha):
        raise ModelError(f"Hugging Face did not return a commit SHA for {model_id}.")
    siblings = {file.rfilename: file for file in info.siblings or []}
    missing = set(_FILES) - siblings.keys()
    if missing:
        raise ModelError(f"{model_id} lacks required artifacts ({', '.join(sorted(missing))}).")
    return info.sha, siblings


def _download(
    hub: Any, model_id: str, revision: str, cache: Path, snapshot: Path, catalog: dict[str, Any]
) -> dict[str, str]:
    hashes = {}
    for name, path in _snapshot_paths(snapshot).items():
        try:
            downloaded = hub.hf_hub_download(
                repo_id=model_id, filename=name, revision=revision, local_dir=snapshot, token=False
            )
        except Exception as exc:
            raise ModelError(f"Could not download {name} ({type(exc).__name__}).") from None
        if Path(downloaded) != path:
            raise ModelError(f"Hugging Face returned an unexpected path for {name}.")
        digest, _ = _artifact_digest(cache, path)
        remote_hash = getattr(catalog[name].lfs, "sha256", None)
        if remote_hash is not None and digest != remote_hash:
            raise ModelError(f"SHA-256 mismatch for downloaded artifact {name}.")
        hashes[name] = digest
    metadata = snapshot / ".cache"
    if metadata.exists():
        shutil.rmtree(metadata)
    return hashes


def pull_model(model_id: str, model_dir: str | Path = DEFAULT_MODEL_DIR) -> VerifiedModel:
    """Fetch a pinned revision and publish its manifest only after verification."""
    model_id = canonical_model_id(model_id)
    cache = _cache_directory(model_dir)
    try:
        hub = import_module("huggingface_hub")
    except ImportError:
        raise ModelError(
            f"Model download requires the local extra. Run `{INSTALL_LOCAL}`."
        ) from None

    revision, catalog = _catalog(hub, model_id)
    try:
        installed = verify_model(model_id, cache)
    except ModelError:
        installed = None
    pinned_graph_digest = getattr(catalog[_GRAPH].lfs, "sha256", None)
    if (
        installed is not None
        and installed.revision == revision
        and (pinned_graph_digest is None or installed.digest == pinned_graph_digest)
    ):
        return installed

    generation = f"snapshot-{uuid4().hex}"
    root = cache / model_id
    snapshot = root / generation
    pending_manifest = f".{generation}.json"
    try:
        with _open_cache_directory(cache, root, create=True) as root_fd:
            os.mkdir(generation, mode=0o700, dir_fd=root_fd)
            published = False
            try:
                hashes = _download(hub, model_id, revision, cache, snapshot, catalog)
                _verify_hashes(cache, _snapshot_paths(snapshot), hashes)
                manifest = {
                    "version": 1,
                    "model_id": model_id,
                    "revision": revision,
                    "generation": generation,
                    "sha256": hashes,
                }
                manifest_fd = os.open(
                    pending_manifest,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=root_fd,
                )
                with os.fdopen(manifest_fd, "w", encoding="utf-8") as stream:
                    json.dump(manifest, stream, indent=2, sort_keys=True)
                    stream.write("\n")
                # Readers with the old manifest can still open that immutable snapshot.
                os.replace(pending_manifest, _MANIFEST, src_dir_fd=root_fd, dst_dir_fd=root_fd)
                published = True
            finally:
                if not published:
                    with suppress(FileNotFoundError):
                        os.unlink(pending_manifest, dir_fd=root_fd)
                    shutil.rmtree(generation, dir_fd=root_fd, ignore_errors=True)
    except OSError:
        raise ModelError(f"Cannot write the local model cache for {model_id}.") from None
    return verify_model(model_id, cache)


def _cache_subdirectories(cache: Path, directory: Path) -> list[str]:
    with _open_cache_directory(cache, directory) as descriptor, os.scandir(descriptor) as entries:
        return sorted(entry.name for entry in entries if entry.is_dir(follow_symlinks=False))


def _cached_model_ids(cache: Path) -> Iterator[str]:
    try:
        namespaces = _cache_subdirectories(cache, cache)
    except FileNotFoundError:
        return
    for namespace in namespaces:
        try:
            names = _cache_subdirectories(cache, cache / namespace)
        except (OSError, ModelError):
            continue
        for name in names:
            try:
                yield canonical_model_id(f"{namespace}/{name}")
            except ModelError:
                continue


def installed_models(model_dir: str | Path = DEFAULT_MODEL_DIR) -> list[dict[str, Any]]:
    """Report integrity of the active snapshot for each managed model."""
    directory = _cache_directory(model_dir)
    models = []
    for model_id in _cached_model_ids(directory):
        entry: dict[str, Any] = {
            "model_id": model_id,
            "size_bytes": None,
            "manifest_sha256": None,
            "revision": None,
            "verified": False,
        }
        try:
            manifest, digest = _read_manifest(model_id, directory)
            entry.update(manifest_sha256=digest, revision=manifest["revision"])
            files = _snapshot_paths(directory / model_id / manifest["generation"])
            entry["size_bytes"] = _verify_hashes(directory, files, manifest["sha256"])
            entry["verified"] = True
        except FileNotFoundError:
            if entry["manifest_sha256"] is None:
                continue
            entry["error"] = "Cannot read one or more local model artifacts."
        except ModelError as exc:
            entry["error"] = str(exc)
        except OSError:
            entry["error"] = "Cannot read one or more local model artifacts."
        models.append(entry)
    return models
