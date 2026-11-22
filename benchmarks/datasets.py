"""Schema and integrity checks for the frozen benchmark datasets."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    TypeAdapter,
    field_validator,
    model_validator,
)

DATASETS = {
    "benign_dev_v1.jsonl": "benign_dev",
    "owasp_asi_v1.jsonl": "owasp_asi",
    "bypass_obfuscation_v1.jsonl": "bypass_obfuscation",
}
ASI_CATEGORIES = ("ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06")
Slug = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,79}$")]
Text = Annotated[str, Field(min_length=1)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CommandInput(StrictModel):
    command: Text
    cwd: Text
    external_content: str = ""

    @field_validator("cwd")
    @classmethod
    def relative_cwd(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or "\\" in value or "\x00" in value:
            raise ValueError("cwd must be a relative POSIX path")
        if path.parts.count("..") > 1 or ".." in path.parts[1:]:
            raise ValueError("cwd may only leave the fixture workspace for a sibling directory")
        return value


class DiffInput(StrictModel):
    diff_text: Text


class MCPInput(StrictModel):
    server: Text
    tool: Text
    arguments: dict[str, JsonValue]


class CaseFields(StrictModel):
    id: Slug
    suite: Literal["benign_dev", "owasp_asi", "bypass_obfuscation"]
    owasp_asi: Literal["ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06"] | None
    attack_family: Slug
    expected_min_decision: Literal["ALLOW", "REVIEW", "HOLD"]
    expected_signals: list[Text]
    split: Literal["dev", "eval"]
    notes: Annotated[str, Field(min_length=1, max_length=240)]

    @model_validator(mode="after")
    def validate_label(self) -> CaseFields:
        benign = self.suite == "benign_dev"
        if benign != (self.owasp_asi is None) or benign != (self.expected_min_decision == "ALLOW"):
            raise ValueError(
                "benign cases need a null ASI and ALLOW, attack cases need an ASI and intervention"
            )
        return self


class CommandCase(CaseFields):
    surface: Literal["command"]
    input: CommandInput


class DiffCase(CaseFields):
    surface: Literal["stdin_diff"]
    input: DiffInput


class MCPCase(CaseFields):
    surface: Literal["mcp_call"]
    input: MCPInput


Case = Annotated[CommandCase | DiffCase | MCPCase, Field(discriminator="surface")]
CASE_SCHEMA = TypeAdapter(Case)


def _unique_members(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    obj: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON member")
        obj[key] = value
    return obj


def _reject_nonfinite(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _finite_float(value: str) -> float:
    number = float(value)
    if number in (float("inf"), float("-inf")):
        raise ValueError("out-of-range JSON number")
    return number


def read_cases(name: str, data: bytes) -> list[Case]:
    cases = []
    for line_number, line in enumerate(
        data.decode("utf-8").removesuffix("\n").split("\n"), start=1
    ):
        try:
            parsed = json.loads(
                line,
                object_pairs_hook=_unique_members,
                parse_constant=_reject_nonfinite,
                parse_float=_finite_float,
            )
            case = CASE_SCHEMA.validate_python(parsed)
        except ValueError:
            raise ValueError(f"{name} line {line_number}: invalid benchmark case") from None
        if case.suite != DATASETS[name]:
            raise ValueError(f"{name} line {line_number}: case belongs to a different suite")
        cases.append(case)
    return cases


def verify_hashes(hashes: dict[str, str], manifest: str) -> None:
    expected = {}
    for line in manifest.splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([a-z0-9_]+\.jsonl)", line)
        if not match or match[2] in expected:
            raise ValueError("invalid dataset checksum manifest")
        expected[match[2]] = match[1]
    if hashes.keys() != expected.keys():
        raise ValueError("dataset checksum manifest does not cover the exact JSONL file set")
    for name in hashes:
        if hashes[name] != expected[name]:
            raise ValueError(f"dataset checksum mismatch: {name}")


def load_datasets(directory: Path, *, verify: bool) -> tuple[list[Case], dict[str, str]]:
    files = {path.name: path for path in directory.glob("*.jsonl")}
    if files.keys() != DATASETS.keys():
        raise ValueError("the dataset directory must contain the three v1 JSONL files")
    contents = {name: files[name].read_bytes() for name in DATASETS}
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
    if verify:
        verify_hashes(hashes, (directory / "holdout_sha256.txt").read_text(encoding="ascii"))

    cases = [case for name, data in contents.items() for case in read_cases(name, data)]
    if len({case.id for case in cases}) != len(cases):
        raise ValueError("dataset case IDs must be globally unique")

    cohorts = {
        "benign_dev": ([case for case in cases if case.suite == "benign_dev"], 120),
        "bypass_obfuscation": ([case for case in cases if case.suite == "bypass_obfuscation"], 60),
        **{
            category: (
                [
                    case
                    for case in cases
                    if case.suite == "owasp_asi" and case.owasp_asi == category
                ],
                20,
            )
            for category in ASI_CATEGORIES
        },
    }
    for name, (rows, minimum) in cohorts.items():
        splits = Counter(case.split for case in rows)
        if len(rows) < minimum or not splits["dev"] or 5 * splits["eval"] < 2 * len(rows):
            raise ValueError(f"{name}: insufficient cases or eval holdout")
    return cases, hashes
