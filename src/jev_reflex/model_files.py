"""Install and verify the self-contained Coba ONNX model bundle."""

from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from errno import ELOOP, ENOTDIR
from importlib import import_module
from pathlib import Path
from typing import Any
from uuid import uuid4
from weakref import finalize

from .config import DEFAULT_MODEL_DIR, DEFAULT_MODEL_ID, EvaluatorConfig, ReflexConfig

INSTALL_LOCAL = 'pip install "jev-reflex[local]"'
PULL_MODEL = "jrx model pull"

_MODEL_COMPONENT = r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,94}[A-Za-z0-9_])?"
_MODEL_ID = re.compile(rf"{_MODEL_COMPONENT}/{_MODEL_COMPONENT}")
_REVISION = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_LEGACY_GENERATION = re.compile(r"snapshot-[0-9a-f]{32}")
_GENERATION = re.compile(r"snapshot-v2-[0-9a-f]{32}")
_MANIFEST = "manifest.json"
_MANIFEST_LIMIT = 16_384
_GRAPH = "onnx/model.onnx"
_INFERENCE_FILES = (_GRAPH, "tokenizer.json", "calibration.json", "decision.json")
_FILES = (*_INFERENCE_FILES, "LICENSE", "NOTICE")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_BLOB_ID = re.compile(r"[0-9a-f]{40}")


class ModelError(RuntimeError):
    """The local model cannot be installed or used safely."""


@dataclass(frozen=True)
class PinnedModel:
    """A reviewed upstream release: its commit and the SHA-256 of every bundle file."""

    revision: str
    sha256: Mapping[str, str]


# The default bundle installs only this reviewed Hugging Face commit, whatever the
# hub (or HF_ENDPOINT) reports as current. The ONNX graph digest is its Git LFS
# SHA-256; the other digests hash the files downloaded at that commit. Adopting a
# new upstream release means reviewing it and updating this pin in a jrx release.
PINNED_MODELS: Mapping[str, PinnedModel] = {
    DEFAULT_MODEL_ID: PinnedModel(
        revision="3553b95dc9b48f40cc3ffe11cd99c9a79e6c6c28",
        sha256={
            _GRAPH: "b7a5f89126004ce77fad386f58b4218f96ca795132d43189c241a020c5d8b757",
            "tokenizer.json": "6c8aaa9a542084f2457eab775d4eeb51f92a70c0fd9de28d5edb0ddec3c08d30",
            "calibration.json": "f4a8b5dd4e1c38d083626646a644c965407eb97c28c0c4869f94fb2539e1383f",
            "decision.json": "b01dafbc1f887d3498e0106911067400a17287d99f968c6446901c8416713169",
            "LICENSE": "a6cba85bc92e0cff7a450b1d873c0eaa2e9fc96bf472df0247a26bec77bf3ff9",
            "NOTICE": "ecb02baa6b8cbc327f2ba66ec319dddcea5ddb067f9c04b679be77e2b00327aa",
        },
    ),
}


def _pinned_release(model_id: str) -> PinnedModel | None:
    pin = PINNED_MODELS.get(model_id)
    if pin is not None and (
        not isinstance(pin.revision, str)
        or not _REVISION.fullmatch(pin.revision)
        or set(pin.sha256) != set(_FILES)
        or any(
            not isinstance(digest, str) or not _SHA256.fullmatch(digest)
            for digest in pin.sha256.values()
        )
    ):
        raise ModelError(f"The pinned release of {model_id} does not cover every bundle file.")
    return pin


class _SnapshotLease:
    """Keep a shared lock until the reader releases its verified snapshot."""

    def __init__(self, cache: Path, snapshot: Path) -> None:
        with _open_cache_directory(cache, snapshot) as fd:
            fcntl.flock(fd, fcntl.LOCK_SH)
            self.close = finalize(self, os.close, os.dup(fd))


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
    _lease: _SnapshotLease = field(repr=False, compare=False)

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
        or type(data.get("version")) is not int
        or data["version"] not in {1, 2}
        or data.get("model_id") != model_id
        or not isinstance(data.get("revision"), str)
        or not _REVISION.fullmatch(data["revision"])
        or not isinstance(data.get("generation"), str)
        or not (_LEGACY_GENERATION if data["version"] == 1 else _GENERATION).fullmatch(
            data["generation"]
        )
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


def _active_snapshot(model_id: str, cache: Path) -> tuple[dict[str, Any], str, _SnapshotLease]:
    # Pair the manifest read with acquisition of the snapshot lock so a writer
    # cannot delete the generation between those operations.
    with _open_cache_directory(cache, cache / model_id) as root_fd:
        fcntl.flock(root_fd, fcntl.LOCK_SH)
        manifest, digest = _read_manifest(model_id, cache)
        return manifest, digest, _SnapshotLease(cache, cache / model_id / manifest["generation"])


def _verified_snapshot(
    cache: Path, manifest: dict[str, Any], manifest_sha256: str, lease: _SnapshotLease
) -> VerifiedModel:
    model_id = manifest["model_id"]
    files = _snapshot_paths(cache / model_id / manifest["generation"])
    hashes = manifest["sha256"]
    pin = _pinned_release(model_id)
    # The manifest is self-written, so a cache pulled from an unreviewed upstream
    # revision (for example by an earlier jrx) must not stay trusted.
    if pin is not None and dict(hashes) != dict(pin.sha256):
        raise ModelError(f"Local model {model_id} does not match its pinned release.")
    size = _verify_hashes(cache, files, hashes)
    inference_hashes = {name: hashes[name] for name in _INFERENCE_FILES}
    digest = hashlib.sha256(json.dumps(inference_hashes, sort_keys=True).encode()).hexdigest()
    return VerifiedModel(
        model_id=model_id,
        graph=files[_GRAPH],
        tokenizer=files["tokenizer.json"],
        calibration=files["calibration.json"],
        decision=files["decision.json"],
        digest=digest,
        manifest_sha256=manifest_sha256,
        size_bytes=size,
        revision=manifest["revision"],
        _cache=cache,
        _asset_hashes={file: hashes[name] for name, file in files.items()},
        _lease=lease,
    )


def verify_model(model_id: str, model_dir: str | Path = DEFAULT_MODEL_DIR) -> VerifiedModel:
    """Verify the published manifest and pin the snapshot for subsequent exact-byte reads."""
    model_id = canonical_model_id(model_id)
    try:
        cache = _cache_directory(model_dir)
        manifest, digest, lease = _active_snapshot(model_id, cache)
        try:
            return _verified_snapshot(cache, manifest, digest, lease)
        except BaseException:
            lease.close()
            raise
    except FileNotFoundError:
        raise ModelError(f"Local model {model_id} is missing. Run `{PULL_MODEL}`.") from None
    except ModelError as exc:
        raise ModelError(f"{exc} Run `{PULL_MODEL}`.") from None
    except (OSError, RuntimeError):
        raise ModelError(f"Cannot read local model {model_id}. Run `{PULL_MODEL}`.") from None


# Each bundle file maps to ("sha256", digest) or ("blob", Git blob SHA-1).
_Expected = dict[str, tuple[str, str]]


def _catalog(hub: Any, model_id: str) -> tuple[str, _Expected]:
    """Resolve the commit to install and an expected digest for every bundle file.

    The default model trusts only its pinned release. Another model is the user's
    own choice of repository: every file must match the digest the hub publishes
    for the resolved commit (Git LFS SHA-256, or the Git blob SHA-1 of a regular
    file), and a file without one is refused.
    """
    pin = _pinned_release(model_id)
    try:
        info = hub.HfApi().model_info(
            model_id,
            revision=pin.revision if pin is not None else None,
            files_metadata=True,
            token=False,
        )
    except Exception as exc:
        raise ModelError(
            f"Could not resolve {model_id} on Hugging Face ({type(exc).__name__})."
        ) from None
    if not isinstance(info.sha, str) or not _REVISION.fullmatch(info.sha):
        raise ModelError(f"Hugging Face did not return a commit SHA for {model_id}.")
    if pin is not None and info.sha != pin.revision:
        raise ModelError(f"Hugging Face did not resolve the pinned revision of {model_id}.")
    siblings = {file.rfilename: file for file in info.siblings or []}
    missing = set(_FILES) - siblings.keys()
    if missing:
        raise ModelError(f"{model_id} lacks required artifacts ({', '.join(sorted(missing))}).")
    expected: _Expected = {}
    for name in _FILES:
        lfs = getattr(siblings[name].lfs, "sha256", None)
        blob = getattr(siblings[name], "blob_id", None)
        if lfs is not None and (not isinstance(lfs, str) or not _SHA256.fullmatch(lfs)):
            raise ModelError(f"Hugging Face returned an invalid digest for {name}.")
        if pin is not None:
            if lfs is not None and lfs != pin.sha256[name]:
                raise ModelError(
                    f"SHA-256 mismatch for {name}: Hugging Face metadata disagrees with the "
                    "pinned release."
                )
            expected[name] = ("sha256", pin.sha256[name])
        elif lfs is not None:
            expected[name] = ("sha256", lfs)
        elif isinstance(blob, str) and _BLOB_ID.fullmatch(blob):
            expected[name] = ("blob", blob)
        else:
            raise ModelError(f"Hugging Face published no verifiable digest for {name}.")
    return info.sha, expected


def _blob_digest(size: int) -> Any:
    """Git's object ID for a regular file, as the hub reports in sibling ``blob_id``.

    It is the only per-file digest the hub publishes for non-LFS files of a
    user-chosen model; the default model is checked against pinned SHA-256s.
    """
    return hashlib.sha1(b"blob %d\0" % size, usedforsecurity=False)


def _matches(expected: tuple[str, str], sha256: str, blob: str) -> bool:
    kind, digest = expected
    return (sha256 if kind == "sha256" else blob) == digest


def _owner_only(descriptor: int, mode: int) -> None:
    if os.fstat(descriptor).st_uid != os.geteuid():
        raise ModelError("Local model cache requires downloads owned by the current user.")
    os.fchmod(descriptor, mode)


def _restrict_download(cache: Path, snapshot: Path, name: str) -> None:
    """Make a fresh download owner-only before it is hashed and trusted.

    huggingface_hub creates local_dir entries with umask-derived modes, such as
    0664 and 0775 under the common 0002 umask. Our snapshot directory is 0700, so
    no other user can reach those entries before they are restricted here.
    """
    *directories, filename = name.split("/")
    with _open_cache_directory(cache, snapshot) as root:
        parent = os.dup(root)
    try:
        for component in directories:
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
            except OSError as exc:
                if exc.errno in {ELOOP, ENOTDIR}:
                    raise ModelError(
                        "Local model cache requires real directories without symbolic links."
                    ) from None
                raise
            os.close(parent)
            parent = child
            _owner_only(parent, 0o700)
        try:
            descriptor = os.open(filename, _READ_FLAGS, dir_fd=parent)
        except OSError as exc:
            if exc.errno == ELOOP:
                raise ModelError(
                    f"Local model artifact {filename} must not be a symbolic link."
                ) from None
            raise
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ModelError(f"Expected a regular file for local model artifact {filename}.")
            _owner_only(descriptor, 0o600)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _download_digests(cache: Path, path: Path) -> tuple[str, str]:
    """Hash a downloaded artifact once for both SHA-256 and its Git blob ID."""
    with _open_cache_file(cache, path) as stream:
        sha256 = hashlib.sha256()
        blob = _blob_digest(os.fstat(stream.fileno()).st_size)
        while chunk := stream.read(1 << 20):
            sha256.update(chunk)
            blob.update(chunk)
    return sha256.hexdigest(), blob.hexdigest()


def _download(
    hub: Any, model_id: str, revision: str, cache: Path, snapshot: Path, expected: _Expected
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
        _restrict_download(cache, snapshot, name)
        sha256, blob = _download_digests(cache, path)
        if not _matches(expected[name], sha256, blob):
            label = "SHA-256" if expected[name][0] == "sha256" else "Git blob SHA-1"
            raise ModelError(f"{label} mismatch for downloaded artifact {name}.")
        hashes[name] = sha256
    metadata = snapshot / ".cache"
    if metadata.exists():
        shutil.rmtree(metadata)
    return hashes


def _installed_matches(model: VerifiedModel, revision: str, expected: _Expected) -> bool:
    if model.revision != revision:
        return False
    snapshot = model.tokenizer.parent
    try:
        for name, (kind, digest) in expected.items():
            file = snapshot / name
            if kind == "sha256":
                if model._asset_hashes[file] != digest:
                    return False
                continue
            contents = model.read_asset(file)
            blob = _blob_digest(len(contents))
            blob.update(contents)
            if blob.hexdigest() != digest:
                return False
    except (ModelError, OSError):
        return False
    return True


def _collect_inactive_snapshots(root_fd: int, active: str) -> None:
    """Reclaim unpinned snapshots created by clients that participate in the locking protocol."""
    with os.scandir(root_fd) as entries:
        generations = [
            entry.name
            for entry in entries
            if entry.name != active and _GENERATION.fullmatch(entry.name)
        ]
    for generation in generations:
        try:
            fd = os.open(generation, _DIRECTORY_FLAGS, dir_fd=root_fd)
            try:
                _trusted_permissions(os.fstat(fd))
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                shutil.rmtree(generation, dir_fd=root_fd)
            finally:
                os.close(fd)
        except (OSError, ModelError):
            # A reader, a staged download, or a cache entry we cannot safely remove.
            continue


def pull_model(
    model_id: str,
    model_dir: str | Path = DEFAULT_MODEL_DIR,
    *,
    config: ReflexConfig | None = None,
) -> VerifiedModel:
    """Fetch and load-check a pinned revision before switching the active manifest."""
    from .local_evaluator import LocalEvaluationError, LocalONNXModel

    model_id = canonical_model_id(model_id)
    cache = _cache_directory(model_dir)
    try:
        hub = import_module("huggingface_hub")
    except ImportError:
        raise ModelError(
            f"Model download requires the local extra. Run `{INSTALL_LOCAL}`."
        ) from None

    revision, expected = _catalog(hub, model_id)
    try:
        installed = verify_model(model_id, cache)
    except ModelError:
        installed = None
    if installed is not None and _installed_matches(installed, revision, expected):
        return installed
    del installed

    generation = f"snapshot-v2-{uuid4().hex}"
    root = cache / model_id
    snapshot = root / generation
    pending_manifest = f".{generation}.json"
    policy = config or ReflexConfig(evaluator=EvaluatorConfig(provider="local"))
    try:
        with _open_cache_directory(cache, root, create=True) as root_fd:
            fcntl.flock(root_fd, fcntl.LOCK_EX)
            os.mkdir(generation, mode=0o700, dir_fd=root_fd)
            published = False
            lease = None
            try:
                lease = _SnapshotLease(cache, snapshot)
                # Pin the new snapshot while the root lock is released for slow I/O.
                fcntl.flock(root_fd, fcntl.LOCK_UN)
                hashes = _download(hub, model_id, revision, cache, snapshot, expected)
                manifest = {
                    "version": 2,
                    "model_id": model_id,
                    "revision": revision,
                    "generation": generation,
                    "sha256": hashes,
                }
                manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
                model = _verified_snapshot(
                    cache, manifest, hashlib.sha256(manifest_bytes).hexdigest(), lease
                )
                try:
                    LocalONNXModel(policy, assets=model)
                except LocalEvaluationError as exc:
                    raise ModelError(
                        f"Downloaded model failed the runtime compatibility check. {exc}"
                    ) from None
                manifest_fd = os.open(
                    pending_manifest,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=root_fd,
                )
                with os.fdopen(manifest_fd, "wb") as stream:
                    stream.write(manifest_bytes)
                fcntl.flock(root_fd, fcntl.LOCK_EX)
                os.replace(pending_manifest, _MANIFEST, src_dir_fd=root_fd, dst_dir_fd=root_fd)
                published = True
                # Collection is best-effort once the active manifest has switched.
                with suppress(OSError):
                    _collect_inactive_snapshots(root_fd, generation)
                return model
            finally:
                if not published:
                    with suppress(FileNotFoundError):
                        os.unlink(pending_manifest, dir_fd=root_fd)
                    shutil.rmtree(generation, dir_fd=root_fd, ignore_errors=True)
                    if lease is not None:
                        lease.close()
    except OSError:
        raise ModelError(f"Cannot write the local model cache for {model_id}.") from None


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
            manifest, digest, lease = _active_snapshot(model_id, directory)
            try:
                entry.update(manifest_sha256=digest, revision=manifest["revision"])
                model = _verified_snapshot(directory, manifest, digest, lease)
                entry.update(size_bytes=model.size_bytes, model_digest=model.digest, verified=True)
            finally:
                lease.close()
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
