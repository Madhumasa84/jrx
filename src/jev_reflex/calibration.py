"""Optional local calibration events that never store action or source content."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import EvaluationResult


def default_events_path() -> Path:
    return Path.home() / ".jev-reflex" / "events.jsonl"


class CalibrationStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_events_path()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        # Lock a stable sidecar, since feedback atomically replaces the data inode.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.with_suffix(self.path.suffix + ".lock").open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def record(self, result: EvaluationResult) -> None:
        """Append only the approved anonymous fields."""

        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "decision_id": result.decision_id,
            "signals": result.signals,
            "policy_decision": result.decision,
            "risk_choice": result.risk.choice,
            "feedback": None,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._locked(), self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")

    def _read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows: list[dict[str, Any]] = []
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(row, dict) and isinstance(row.get("decision_id"), str):
                        rows.append(row)
        except OSError:
            return []
        return rows

    def add_feedback(self, decision_id: str, feedback: str) -> bool:
        if feedback not in {"correct", "incorrect"}:
            raise ValueError("feedback must be correct or incorrect")
        with self._locked():
            rows = self._read()
            found = False
            for row in rows:
                if row.get("decision_id") == decision_id:
                    row["feedback"] = feedback
                    found = True
            if not found:
                return False

            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(
                prefix="events-", suffix=".jsonl", dir=self.path.parent
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    for row in rows:
                        handle.write(json.dumps(row, sort_keys=True) + "\n")
                os.replace(temporary, self.path)
            except Exception:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise
            return True

    def summary(self) -> dict[str, Any]:
        with self._locked():
            rows = self._read()
        labeled = [row for row in rows if row.get("feedback") in {"correct", "incorrect"}]

        def accuracy(cases: list[dict[str, Any]]) -> float | None:
            if not cases:
                return None
            return sum(row.get("feedback") == "correct" for row in cases) / len(cases)

        strong = [
            row
            for row in labeled
            if any(float(value) >= 0.90 for value in (row.get("signals") or {}).values())
        ]
        review = [
            row
            for row in labeled
            if any(0.70 <= float(value) < 0.90 for value in (row.get("signals") or {}).values())
        ]
        false_high_confidence = sum(
            row.get("feedback") == "incorrect"
            and any(float(value) >= 0.90 for value in (row.get("signals") or {}).values())
            for row in labeled
        )

        signal_cases: dict[str, list[dict[str, Any]]] = {}
        for row in labeled:
            for name, value in (row.get("signals") or {}).items():
                if float(value) >= 0.70:
                    signal_cases.setdefault(str(name), []).append(row)

        return {
            "labeled_cases": len(labeled),
            "accuracy_at_strong": accuracy(strong),
            "accuracy_in_review_band": accuracy(review),
            "false_high_confidence_count": false_high_confidence,
            "per_signal_accuracy": {
                name: accuracy(cases) for name, cases in sorted(signal_cases.items())
            },
        }
