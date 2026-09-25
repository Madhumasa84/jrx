"""Inspect worktrees through private Git metadata without executable configuration."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def inspect_git(
    cwd: Path, *args: str, timeout: float = 5, _depth: int = 0
) -> subprocess.CompletedProcess[bytes]:
    if _depth > 16:
        raise ValueError("Git submodule nesting exceeds inspection limit")
    if not args or args[0] not in {"rev-parse", "status", "diff"}:
        raise ValueError("unsupported Git inspection operation")
    cwd = cwd.resolve()
    root = next(
        (
            path
            for path in (cwd, *cwd.parents)
            if (path / ".git").is_file() or (path / ".git" / "HEAD").is_file()
        ),
        None,
    )
    if root is None:
        return subprocess.CompletedProcess(["git", *args], 128, b"", b"")
    gitdir = root / ".git"
    if gitdir.is_file():
        pointer = os.fsdecode(gitdir.read_bytes()).removesuffix("\n")
        if not pointer.startswith("gitdir: "):
            raise ValueError("invalid Git worktree pointer")
        gitdir = (root / pointer[8:]).resolve()
    common = gitdir
    if (gitdir / "commondir").is_file():
        common = (
            gitdir / os.fsdecode((gitdir / "commondir").read_bytes()).removesuffix("\n")
        ).resolve()
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_NO_LAZY_FETCH="1",
    )
    options: dict[str, Any] = dict(
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
        shell=False,
    )
    # Read only format metadata, without following includes. Never run a worktree
    # operation against repository or user configuration: enumerating and then
    # disabling helpers has a race if another process adds a new filter driver.
    formats = subprocess.run(
        [
            "git",
            "config",
            "--file",
            str(common / "config"),
            "--no-includes",
            "--get-regexp",
            r"^extensions\.(objectformat|refstorage)$",
        ],
        **options,
    )
    if formats.returncode not in (0, 1):
        raise ValueError("Git format could not be inspected")
    object_format = "sha1"
    ref_storage = "files"
    for line in formats.stdout.splitlines():
        name, _, value = line.partition(b" ")
        if name == b"extensions.objectformat":
            if value not in {b"sha1", b"sha256"}:
                raise ValueError("unsupported Git object format")
            object_format = value.decode("ascii")
        elif name == b"extensions.refstorage":
            if value not in {b"files", b"reftable"}:
                raise ValueError("unsupported Git reference format")
            ref_storage = value.decode("ascii")
    with tempfile.TemporaryDirectory(prefix="jrx-git-") as directory:
        shadow = Path(directory)
        (shadow / "HEAD").write_bytes((gitdir / "HEAD").read_bytes())
        config_text = (
            "[core]\nrepositoryformatversion = 1\nbare = false\n"
            f"[extensions]\nobjectformat = {object_format}\n"
        )
        if ref_storage != "files":
            config_text += f"refstorage = {ref_storage}\n"
        (shadow / "config").write_text(config_text, encoding="ascii")
        for name in ("objects", "refs", "packed-refs", "shallow", "reftable"):
            target = common / name
            if target.exists():
                (shadow / name).symlink_to(target.resolve())
        if (gitdir / "index").exists():
            shutil.copyfile(gitdir / "index", shadow / "index")
        for shared_index in gitdir.glob("sharedindex.*"):
            if shared_index.is_file():
                shutil.copyfile(shared_index, shadow / shared_index.name)
        if (common / "info" / "exclude").is_file():
            (shadow / "info").mkdir()
            (shadow / "info" / "exclude").symlink_to((common / "info" / "exclude").resolve())
        command = [
            "git",
            "--no-pager",
            "--git-dir",
            str(shadow),
            "--work-tree",
            str(root),
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=" + os.devnull,
        ]
        if args[0] in {"status", "diff"} and "--cached" not in args:
            flagged = subprocess.run([*command, "ls-files", "-v", "-z"], **options)
            if flagged.returncode != 0:
                raise ValueError("Git index flags could not be inspected")
            assume_unchanged = []
            skip_worktree = []
            for entry in flagged.stdout.split(b"\0"):
                if len(entry) < 3:
                    continue
                tag, path = entry[:1], entry[2:]
                if tag.islower():
                    assume_unchanged.append(path)
                if tag.upper() == b"S":
                    candidate = root / os.fsdecode(path)
                    # Missing sparse-checkout files are intentionally absent.
                    if candidate.exists() or candidate.is_symlink():
                        skip_worktree.append(path)
            for flag, paths in (
                ("--no-assume-unchanged", assume_unchanged),
                ("--no-skip-worktree", skip_worktree),
            ):
                if paths:
                    normalized = subprocess.run(
                        [*command, "update-index", flag, "-z", "--stdin"],
                        input=b"\0".join(paths) + b"\0",
                        **{key: value for key, value in options.items() if key != "stdin"},
                    )
                    if normalized.returncode != 0:
                        raise ValueError("Git inspection index could not be normalized")
        if args[0] == "diff":
            args = (
                args[0],
                "--no-ext-diff",
                "--no-textconv",
                "--ignore-submodules=dirty",
                *args[1:],
            )
        if args[0] == "status":
            args = (*args, "--ignore-submodules=dirty")
        result = subprocess.run([*command, *args], **options)
        if args[0] == "status" and result.returncode == 0:
            # Do not let Git recursively inspect submodules with their own config.
            # Inspect each initialized gitlink through the same private view and
            # include its changed paths so approvals bind to the actual contents.
            indexed = subprocess.run([*command, "ls-files", "--stage", "-z"], **options)
            if indexed.returncode != 0:
                raise ValueError("Git submodule index could not be inspected")
            modules = {
                entry.split(b"\t", 1)[1]
                for entry in indexed.stdout.split(b"\0")
                if entry.startswith(b"160000 ") and b"\t" in entry
            }
            for relative in sorted(modules):
                module = root / os.fsdecode(relative)
                if not (module / ".git").exists():
                    continue
                if not module.resolve().is_relative_to(root):
                    raise ValueError("Git submodule is outside its worktree")
                nested = inspect_git(
                    module,
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                    timeout=timeout,
                    _depth=_depth + 1,
                )
                if nested.returncode != 0:
                    raise ValueError("Git submodule could not be inspected")
                for path in status_paths(nested.stdout):
                    result.stdout += b" M " + relative + b"/" + os.fsencode(path) + b"\0"
        return result


def status_paths(status: bytes) -> list[str]:
    """Decode porcelain v1 -z records, including the unprefixed rename source."""
    paths: list[str] = []
    entries = iter(status.split(b"\0"))
    for entry in entries:
        if not entry:
            continue
        if len(entry) < 4 or entry[2:3] != b" ":
            raise ValueError("Malformed Git status record")
        paths.append(os.fsdecode(entry[3:]))
        if b"R" in entry[:2] or b"C" in entry[:2]:
            source = next(entries, b"")
            if not source:
                raise ValueError("Incomplete Git rename record")
            paths.append(os.fsdecode(source))
    return paths
