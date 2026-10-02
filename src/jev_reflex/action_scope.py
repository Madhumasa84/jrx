"""Conservative preflight capability classification; not program I/O tracing."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from .agent_state import ControlError, digest
from .checks.repo_boundary import _input_paths
from .config import ReflexConfig
from .models import EvaluationContext


def describe_action(
    context: EvaluationContext, config: ReflexConfig | None = None
) -> tuple[list[str], list[str], str]:
    action = context.proposed_action
    if len(action.model_dump_json()) > 262144:
        raise ControlError("action exceeds control size limit")
    classes: set[str] = {"unknown"}
    resources = _input_paths(action.input)
    if action.type.startswith("mcp:") and config is not None:
        for rule in config.mcp.tools:
            if action.type == f"mcp:{rule.server}.{rule.name}":
                classes = {"read" if rule.effect == "read" else "modify"}
                break
    elif action.type in {"Read", "read_file", "read_text_file"}:
        classes = {"read"}
    elif action.type in {"Edit", "Write", "write_file", "edit_file", "apply_patch"}:
        classes = {"modify"}
    elif action.type == "shell_command":
        try:
            argv = action.argv or shlex.split(action.command or "")
        except ValueError:
            argv = []
        # Compound and expanding shell syntax never acquires narrow authority.
        simple = bool(argv) and not any(re.search(r"[;&|`$()<>\n\r*?]", token) for token in argv)
        if simple:
            program = argv[0]
            if program in {
                f"{prefix}/{name}"
                for prefix in ("/bin", "/usr/bin")
                for name in ("cat", "head", "tail", "ls", "wc")
            }:
                program = Path(program).name
            if program in {"cat", "head", "tail", "ls", "wc"}:
                permitted_flags = {
                    "--",
                    "-n",
                    "-b",
                    "-v",
                    "-E",
                    "-T",
                    "-s",
                    "-A",
                    "-l",
                    "-a",
                    "-la",
                    "-al",
                    "-w",
                    "-c",
                    "-m",
                    "-L",
                }
                classes = (
                    {"read"}
                    if all(
                        not token.startswith("-") or token in permitted_flags for token in argv[1:]
                    )
                    else {"unknown"}
                )
                resources.extend(
                    token
                    for token in argv[1:]
                    if not token.startswith("-") and not token.isdecimal()
                )
            elif program in {"pytest", "python", "python3"} and (
                program == "pytest" or argv[1:3] == ["-m", "pytest"]
            ):
                classes = {"test"}
                # Running tests executes arbitrary repository code. A narrow file
                # argument does not establish narrow resource authority.
                resources = ["."]
    text = action.model_dump_json().lower()
    if re.search(
        r"(?:\.env\b|\.ssh\b|credentials|secret|passwd|/shadow\b|printenv|\benviron\b)", text
    ):
        classes.add("secrets")
    if re.search(r"(?:\bdeploy\b|\bhelm\b|\.github/|\bkubectl\b|\bterraform\b)", text):
        classes.add("deploy")
    if re.search(r"(?:\biam\b|service.account|role.binding)", text):
        classes.add("iam")
    if re.search(r"(?:\bcurl\b|\bwget\b|\bpublish\b|\bupload\b|\bgit push\b)", text):
        classes.add("publish")
    root = Path(context.repository_root).resolve()
    base = Path(context.working_directory).resolve()
    relative_resources = []
    for resource in resources or ["."]:
        candidate = Path(resource)
        try:
            relative_resources.append((base / candidate).resolve().relative_to(root).as_posix())
        except (ValueError, OSError, RuntimeError):
            relative_resources.append("../outside")
    return sorted(classes), sorted(set(relative_resources)), digest(action.model_dump(mode="json"))
