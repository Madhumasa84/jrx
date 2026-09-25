"""Exercise Git trust boundaries using actual repositories and executable helpers."""

import shlex
import subprocess
from pathlib import Path

import pytest

from jev_reflex.config import ReflexConfig
from jev_reflex.context import RepositoryContextProvider
from jev_reflex.enterprise import action_binding
from jev_reflex.models import ProposedAction


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init")
    git(tmp_path, "config", "user.email", "test@example.test")
    git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "tracked").write_text("before\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-m", "baseline")
    (tmp_path / "tracked").write_text("after\n")
    return tmp_path


def context(repo: Path):
    return RepositoryContextProvider(cwd=repo).build(
        user_task="", proposed_action=ProposedAction(command="true")
    )


def test_context_includes_real_worktree_diff(repo: Path):
    assert "+after" in context(repo).git_diff


@pytest.mark.parametrize("operation", ["context", "approval"])
@pytest.mark.parametrize("helper", ["fsmonitor", "clean", "process", "textconv", "external"])
def test_inspection_never_executes_repository_helpers(repo: Path, operation: str, helper: str):
    script = repo / "helper.sh"
    marker = repo / "executed"
    script.write_text('#!/bin/sh\ntouch "$(dirname "$0")/executed"\ncat\n')
    script.chmod(0o700)
    command = shlex.quote(str(script))
    if helper == "fsmonitor":
        git(repo, "config", "core.fsmonitor", command)
    elif helper in {"clean", "process"}:
        (repo / ".gitattributes").write_text("tracked filter=attack\n")
        git(repo, "config", f"filter.attack.{helper}", command)
    elif helper == "textconv":
        (repo / ".gitattributes").write_text("tracked diff=attack\n")
        git(repo, "config", "diff.attack.textconv", command)
    else:
        git(repo, "config", "diff.external", command)
    if operation == "context":
        assert "+after" in context(repo).git_diff
    else:
        action_binding(ReflexConfig(), repo, ["true"], "development")
    assert not marker.exists()


def test_changed_files_preserve_rename_source_and_newlines(repo: Path):
    git(repo, "mv", "tracked", "renamed\n")
    files = context(repo).changed_files
    assert "tracked" in files
    assert "renamed\n" in files
    assert "cked" not in files


def test_fixture_benchmark_is_independent_of_worktree_diff(repo, monkeypatch):
    import json

    from typer.testing import CliRunner

    from jev_reflex.cli import app

    (repo / "tracked").write_text('password = "not-a-real-password"\n')
    monkeypatch.chdir(repo)
    result = CliRunner().invoke(app, ["benchmark", "stability", "--runs", "1", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["gold_metrics"]["decision_accuracy"] == 1.0


def test_benchmark_data_is_found_in_target_install(tmp_path, monkeypatch):
    from jev_reflex import cli

    package = tmp_path / "target" / "jev_reflex"
    package.mkdir(parents=True)
    data = tmp_path / "target" / "share" / "jev-reflex" / "benchmarks" / "stability"
    data.mkdir(parents=True)
    (data / "case.json").write_text("{}")
    monkeypatch.setattr(cli, "__file__", str(package / "cli.py"))
    assert cli._benchmark_root() == data


def test_filter_added_after_inspection_cannot_execute(repo, monkeypatch):
    from jev_reflex.git_inspection import inspect_git

    marker = repo / "race-executed"
    script = repo / "race.sh"
    script.write_text('#!/bin/sh\ntouch "$(dirname "$0")/race-executed"\ncat\n')
    script.chmod(0o700)
    (repo / ".gitattributes").write_text("tracked filter=late\n")
    run = subprocess.run

    def change_config(*args, **kwargs):
        result = run(*args, **kwargs)
        if "--get-regexp" in args[0]:
            run(
                ["git", "-C", str(repo), "config", "filter.late.clean", shlex.quote(str(script))],
                check=True,
            )
        return result

    monkeypatch.setattr(subprocess, "run", change_config)
    inspect_git(repo, "diff")
    assert not marker.exists()


def test_inspection_supports_linked_worktree_and_preserves_index(repo, tmp_path):
    linked = tmp_path / "linked worktree"
    git(repo, "worktree", "add", "--detach", str(linked), "HEAD")
    (linked / "tracked").write_text("linked change\n")
    result = context(linked)
    assert result.repository_root == str(linked)
    assert "+linked change" in result.git_diff
    before = (repo / ".git" / "index").read_bytes()
    first = action_binding(ReflexConfig(), repo, ["true"], "development")
    assert action_binding(ReflexConfig(), repo, ["true"], "development") == first
    assert (repo / ".git" / "index").read_bytes() == before


def test_inspection_ignores_environment_selected_repository(repo, monkeypatch):
    monkeypatch.setenv("GIT_WORK_TREE", "/")
    monkeypatch.setenv("GIT_DIR", "/missing-git-dir")
    assert context(repo).repository_root == str(repo)
    assert "+after" in context(repo).git_diff


def test_sha256_repository_inspection(tmp_path):
    git(tmp_path, "init", "--object-format=sha256")
    git(tmp_path, "config", "user.email", "test@example.test")
    git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "tracked").write_text("before\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-m", "base")
    (tmp_path / "tracked").write_text("after\n")
    assert "+after" in context(tmp_path).git_diff
    assert action_binding(ReflexConfig(), tmp_path, ["true"], "development")


def test_bare_repository_cannot_satisfy_worktree_bound_approval(tmp_path):
    from jev_reflex.enterprise import AccessDenied

    bare = tmp_path / "bare.git"
    git(tmp_path, "init", "--bare", str(bare))
    assert RepositoryContextProvider(cwd=bare).repository_root() is None
    with pytest.raises(AccessDenied, match="Git repository is required"):
        action_binding(ReflexConfig(), bare, ["true"], "development")


def test_split_index_inspection_preserves_diff_and_index(repo):
    git(repo, "update-index", "--split-index")
    index = (repo / ".git" / "index").read_bytes()
    assert "+after" in context(repo).git_diff
    assert "tracked" in context(repo).changed_files
    assert (repo / ".git" / "index").read_bytes() == index


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_index_flags_cannot_hide_changed_action_contents(repo, flag):
    git(repo, "update-index", flag, "tracked")
    first = action_binding(ReflexConfig(), repo, ["true"], "development")
    index = (repo / ".git" / "index").read_bytes()
    (repo / "tracked").write_text("different execution\n")
    assert action_binding(ReflexConfig(), repo, ["true"], "development") != first
    assert "+different execution" in context(repo).git_diff
    assert (repo / ".git" / "index").read_bytes() == index


def test_sandbox_mount_is_not_redirected_by_repository_config(repo):
    from jev_reflex.config import SandboxConfig
    from jev_reflex.sandbox import build_sandbox_command

    git(repo, "config", "core.worktree", str(repo.parent))
    command, _ = build_sandbox_command(["true"], repo, SandboxConfig(enabled=True, image="test"))
    assert f"type=bind,src={repo},dst={repo}" in command


def test_approval_binding_includes_submodule_worktree_changes(repo, tmp_path):
    module_source = tmp_path / "source"
    module_source.mkdir()
    git(module_source, "init")
    git(module_source, "config", "user.email", "test@example.test")
    git(module_source, "config", "user.name", "Test")
    (module_source / "script").write_text("before\n")
    git(module_source, "add", ".")
    git(module_source, "commit", "-m", "base")
    git(repo, "-c", "protocol.file.allow=always", "submodule", "add", str(module_source), "module")
    marker = repo / "submodule-helper-executed"
    script = repo / "submodule-helper.sh"
    script.write_text('#!/bin/sh\ntouch "$(dirname "$0")/submodule-helper-executed"\ncat\n')
    script.chmod(0o700)
    git(repo / "module", "config", "core.fsmonitor", shlex.quote(str(script)))
    git(repo / "module", "config", "filter.attack.clean", shlex.quote(str(script)))
    (repo / "module" / ".gitattributes").write_text("script filter=attack\n")
    first = action_binding(ReflexConfig(), repo, ["true"], "development")
    (repo / "module" / "script").write_text("after\n")
    assert action_binding(ReflexConfig(), repo, ["true"], "development") != first
    assert "module/script" in context(repo).changed_files
    assert not marker.exists()


def test_bare_repository_linked_worktree_satisfies_approval(tmp_path):
    src = tmp_path / "src"
    git(tmp_path, "init", str(src))
    git(src, "config", "user.email", "test@example.test")
    git(src, "config", "user.name", "Test")
    (src / "init.txt").write_text("initial\n")
    git(src, "add", ".")
    git(src, "commit", "-m", "init")
    bare = tmp_path / "bare.git"
    git(tmp_path, "clone", "--bare", str(src), str(bare))
    wt = tmp_path / "wt"
    git(bare, "worktree", "add", str(wt), "HEAD")
    (wt / "file.txt").write_text("hello\n")
    assert action_binding(ReflexConfig(), wt, ["true"], "development") is not None


def test_reftable_format_accepted_and_unknown_refstorage_rejected(tmp_path, monkeypatch):
    from jev_reflex.git_inspection import inspect_git

    repo = tmp_path / "repo"
    git(tmp_path, "init", str(repo))
    (repo / ".git" / "reftable").mkdir()
    (repo / ".git" / "config").write_text(
        "[core]\nrepositoryformatversion = 1\n[extensions]\nrefstorage = custom_db\n"
    )
    with pytest.raises(ValueError, match="unsupported Git reference format"):
        inspect_git(repo, "status")

    # When refstorage is reftable, format inspection recognizes it without raising unsupported format error
    (repo / ".git" / "config").write_text(
        "[core]\nrepositoryformatversion = 1\n[extensions]\nrefstorage = reftable\n"
    )
    intercepted_config = []
    real_run = subprocess.run

    def record_shadow_run(cmd, *args, **kwargs):
        if "--git-dir" in cmd:
            idx = cmd.index("--git-dir")
            shadow_dir = Path(cmd[idx + 1])
            if (shadow_dir / "config").exists():
                intercepted_config.append((shadow_dir / "config").read_text())
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr("jev_reflex.git_inspection.subprocess.run", record_shadow_run)
    try:
        inspect_git(repo, "status")
    except ValueError:
        pass  # host git 2.34 doesn't support reftable runtime, but format inspection must have passed
    assert any("refstorage = reftable" in cfg for cfg in intercepted_config)
