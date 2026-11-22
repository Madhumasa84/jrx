"""Recognize storage and infrastructure operations at their command boundary."""

from __future__ import annotations

import re

from ..models import DeterministicFinding, EvaluationContext
from .shell import inspect, program

_SQL = {"psql", "mysql", "sqlite3", "sqlcmd", "duckdb"}
_MIGRATORS = {"alembic", "django-admin", "rails", "prisma", "migrate", "migration"}
_DROP = re.compile(r"\b(?:drop\s+(?:database|table)|delete\s+from\s+\w+)\b", re.I)
_FORMATTERS = {"wipefs", "fdisk", "parted", "mkfs"}


def _reason(name: str, args: tuple[str, ...]) -> tuple[str, bool] | None:
    if (
        name in _FORMATTERS
        or name.startswith("mkfs.")
        or (name == "diskutil" and args[:1] in {("eraseDisk",), ("eraseVolume",)})
        or (name == "dd" and any(arg.startswith("of=/dev/") for arg in args))
    ):
        return "FILESYSTEM_FORMAT", True
    if name in _SQL and _DROP.search(" ".join(args)):
        return "PERSISTENT_DELETE", True
    if name in _MIGRATORS and any(
        arg in {"--force", "--irreversible", "irreversible", "destroy", "reset", "downgrade"}
        for arg in args
    ):
        return "IRREVERSIBLE_MIGRATION", True
    if name == "docker":
        if args[:1] == ("compose",):
            operation = args[1:2]
            if operation in {("config",), ("ls",), ("ps",), ("logs",), ("stop",)}:
                return None
            if operation in {("down",), ("rm",)} and not set(args) & {"--volumes", "-v"}:
                return None
        if (
            args[:2] in {("builder", "prune"), ("buildx", "prune")}
            and any(value.startswith("until=") for value in args[2:])
            and not set(args) & {"--all", "-a"}
        ):
            return None
    if name == "kubectl" and args[:1] in {
        ("kustomize",),
        ("get",),
        ("describe",),
        ("logs",),
        ("explain",),
        ("diff",),
    }:
        return None
    if name == "terraform" and args[:1] in {("fmt",), ("validate",), ("show",), ("output",)}:
        return None
    if name in _SQL | _MIGRATORS | {"terraform", "kubectl", "docker"}:
        return "PERSISTENCE_ACTION", False
    return None


def evaluate(context: EvaluationContext) -> list[DeterministicFinding]:
    review = False
    for command in inspect(context.proposed_action).commands:
        if command.argv and (result := _reason(program(command.argv[0]), command.argv[1:])):
            reason, blocking = result
            if blocking:
                return [
                    DeterministicFinding(
                        check="filesystem",
                        triggered=True,
                        severity="high",
                        reason_code=reason,
                        blocking=True,
                    )
                ]
            review = True
    return [
        DeterministicFinding(
            check="filesystem",
            triggered=review,
            severity="medium" if review else "low",
            reason_code="PERSISTENCE_ACTION" if review else "CLEAR",
        )
    ]
