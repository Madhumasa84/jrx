"""Repository context collection with bounded, shell-free Git calls."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Protocol

from .git_inspection import inspect_git, status_paths
from .models import EvaluationContext, ProposedAction


def bounded_text(value: str | None, limit: int) -> str:
    """Bound a text field deterministically while retaining both ends of a diff."""

    value = value or ""
    if len(value) <= limit:
        return value
    marker = "\n...[truncated by jev-reflex]...\n"
    if limit <= len(marker):
        return value[:limit]
    available = limit - len(marker)
    head = available // 2
    tail = available - head
    return value[:head] + marker + value[-tail:]


class ContextProvider(Protocol):
    """Reusable context-provider contract for future agent surfaces."""

    def build(
        self,
        *,
        user_task: str,
        proposed_action: ProposedAction,
        stdin_diff: str = "",
        recent_context: str = "",
        external_content: str = "",
        test_results: str = "",
        changed_files: list[str] | None = None,
    ) -> EvaluationContext: ...


class RepositoryContextProvider:
    """Collect only the repository facts needed for a pre-action judgment."""

    def __init__(
        self,
        cwd: Path | None = None,
        *,
        include_git_diff: bool = True,
        include_changed_files: bool = True,
        include_tests: bool = True,
        max_diff_chars: int = 30_000,
        max_context_chars: int = 50_000,
    ) -> None:
        self.working_directory = (cwd or Path.cwd()).resolve(strict=False)
        self.include_git_diff = include_git_diff
        self.include_changed_files = include_changed_files
        self.include_tests = include_tests
        self.max_diff_chars = max_diff_chars
        self.max_context_chars = max_context_chars

    def _git(self, *args: str) -> str:
        try:
            completed = inspect_git(self.working_directory, *args, timeout=3)
        except (OSError, subprocess.SubprocessError, ValueError):
            return ""
        if completed.returncode != 0:
            return ""
        return completed.stdout.decode("utf-8", errors="surrogateescape")

    def repository_root(self) -> Path | None:
        root = self._git("rev-parse", "--show-toplevel").removesuffix("\n")
        if not root:
            return None
        try:
            return Path(root).resolve(strict=False)
        except OSError:
            return None

    def _changed_files(self, root: Path) -> list[str]:
        del root  # The Git command runs relative to the provider's canonical directory.
        output = self._git("status", "--porcelain=v1", "-z", "--untracked-files=all")
        return list(dict.fromkeys(status_paths(output.encode("utf-8", errors="surrogateescape"))))[
            :500
        ]

    def build(
        self,
        *,
        user_task: str,
        proposed_action: ProposedAction,
        stdin_diff: str = "",
        recent_context: str = "",
        external_content: str = "",
        test_results: str = "",
        changed_files: list[str] | None = None,
    ) -> EvaluationContext:
        root = self.repository_root()
        repository = root.name if root else self.working_directory.name
        files = changed_files or []
        if self.include_changed_files and not files:
            files = self._changed_files(root or self.working_directory)

        diff = stdin_diff
        if not diff and self.include_git_diff:
            diff = self._git("diff", "--unified=3")

        return EvaluationContext(
            user_task=bounded_text(user_task, self.max_context_chars),
            repository=bounded_text(repository, 500),
            repository_root=bounded_text(str(root or self.working_directory), 1_000),
            working_directory=bounded_text(str(self.working_directory), 1_000),
            proposed_action=proposed_action,
            changed_files=[bounded_text(item, 1_000) for item in files[:500]],
            git_diff=bounded_text(diff, self.max_diff_chars),
            test_results=bounded_text(
                test_results if self.include_tests else "", self.max_context_chars
            ),
            recent_context=bounded_text(recent_context, self.max_context_chars),
            external_content=bounded_text(external_content, self.max_context_chars),
        )
