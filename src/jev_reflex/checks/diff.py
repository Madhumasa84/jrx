"""File paths and added lines from proposed unified diffs and structured patches."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from ..models import EvaluationContext


@dataclass
class FileChange:
    paths: set[str] = field(default_factory=set)
    added: list[str] = field(default_factory=list)


_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


def file_changes(text: str) -> list[FileChange]:
    changes: list[FileChange] = []
    entry: FileChange | None = None
    old = new = 0
    for line in text.splitlines():
        if line.startswith("diff --git "):
            entry = FileChange()
            changes.append(entry)
            old = new = 0
            try:
                entry.paths.update(
                    value[2:] for value in shlex.split(line)[2:] if value.startswith(("a/", "b/"))
                )
            except ValueError:
                pass
        elif match := _HUNK.match(line):
            old, new = (int(value) if value is not None else 1 for value in match.groups())
        elif (old or new) and line[:1] in {" ", "-", "+"}:
            old = max(0, old - (line[0] != "+"))
            new = max(0, new - (line[0] != "-"))
            if entry is not None and line[0] == "+":
                entry.added.append(line[1:])
        elif line.startswith(("--- ", "+++ ", "rename from ", "rename to ")):
            if entry is None:
                entry = FileChange()
                changes.append(entry)
            is_header = line.startswith(("--- ", "+++ "))
            value = (line[4:] if is_header else line.split(" ", 2)[2]).split("\t", 1)[0]
            if value.startswith('"'):
                try:
                    value = shlex.split(value)[0]
                except (ValueError, IndexError):
                    continue
            if value != "/dev/null":
                entry.paths.add(
                    value[2:] if is_header and value.startswith(("a/", "b/")) else value
                )
    return changes


def proposed_changes(context: EvaluationContext) -> list[FileChange]:
    if context.proposed_diff or context.proposed_action.type == "observation":
        return file_changes(context.git_diff)
    return []
