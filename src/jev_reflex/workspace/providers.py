"""Provider discovery and argument construction for official native CLIs.

Provider-specific commands stay here. JRX never reads provider credentials; it
only checks whether documented key variables are present so it can warn before
starting a CLI that may use separately billed authentication.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..context import sanitized_child_env

_VERSION = re.compile(r"(?:^|\s|v)(\d+\.\d+(?:\.\d+)?(?:[-+][\w.-]+)?)")


@dataclass(frozen=True)
class ProviderSpec:
    key: str
    display_name: str
    executable: str
    api_key_env: tuple[str, ...]
    hooks_path: str
    hook_command: tuple[str, ...]


@dataclass(frozen=True)
class ProviderStatus:
    provider: ProviderSpec
    status: str
    path: str | None
    version: str | None
    authentication: str
    auth_verified: bool
    api_key_conflict: bool
    detail: str
    structured_output: bool = False


@dataclass(frozen=True)
class ModelChoice:
    identifier: str
    display_name: str


@dataclass(frozen=True)
class ModelCatalog:
    choices: tuple[ModelChoice, ...]
    source: str
    available: bool
    detail: str = ""


PROVIDERS: tuple[ProviderSpec, ...] = (
    ProviderSpec(
        "codex",
        "OpenAI Codex CLI",
        "codex",
        ("OPENAI_API_KEY",),
        ".codex/hooks.json",
        ("codex-hook",),
    ),
    ProviderSpec(
        "claude",
        "Anthropic Claude Code CLI",
        "claude",
        ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
        ".claude/settings.json",
        ("claude-code-hook",),
    ),
    ProviderSpec(
        "antigravity",
        "Google Antigravity CLI",
        "agy",
        ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        ".agents/hooks.json",
        ("antigravity-hook",),
    ),
)

_ALL_PROVIDER_KEYS = tuple(name for item in PROVIDERS for name in item.api_key_env)


def provider_by_key(key: str) -> ProviderSpec:
    for provider in PROVIDERS:
        if provider.key == key:
            return provider
    raise ValueError(f"unknown provider: {key}")


def _probe_env() -> dict[str, str]:
    return sanitized_child_env(extra_strip=_ALL_PROVIDER_KEYS)


def _safe_authentication(spec: ProviderSpec, executable: str, cwd: Path) -> tuple[str, bool]:
    """Ask only provider-documented status commands; return a reduced label."""
    if spec.key == "codex":
        argv = [executable, "login", "status"]
    elif spec.key == "claude":
        argv = [executable, "auth", "status", "--json"]
    else:
        # Antigravity documents native login and cached-auth errors, but no
        # non-interactive authentication-status command.
        return "unknown (no documented safe status command)", False

    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=_probe_env(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown", False

    output = (completed.stdout + "\n" + completed.stderr).strip()
    if completed.returncode != 0:
        return "unknown", False
    if spec.key == "codex":
        normalized = output.lower()
        if "logged in using chatgpt" in normalized:
            return "ChatGPT account (CLI reports signed in)", True
        if "logged in using api key" in normalized:
            return "API key (CLI reports API-key auth)", True
        if "not logged in" in normalized or "not authenticated" in normalized:
            return "not authenticated", True
        return "unknown", False

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        return "unknown", False
    if not isinstance(payload, dict):
        return "unknown", False
    logged_in = payload.get("loggedIn", payload.get("isLoggedIn"))
    if logged_in is False:
        return "not authenticated", True
    if logged_in is not True:
        return "unknown", False
    # Do not echo arbitrary account fields such as email addresses. Normalize
    # only a small allow-list of documented auth labels.
    raw_method = payload.get("authMethod", payload.get("subscriptionType", ""))
    safe_values = {
        "claude.ai": "Claude account (CLI reports signed in)",
        "oauth": "OAuth account (CLI reports signed in)",
        "console": "Console/API auth (may be separately billed)",
        "api_key": "API key (may be separately billed)",
        "apikey": "API key (may be separately billed)",
    }
    label = safe_values.get(raw_method.lower()) if isinstance(raw_method, str) else None
    return label or "signed in (authentication mode unknown)", True


def _capability_status(spec: ProviderSpec, executable: str, cwd: Path) -> tuple[str, str, bool]:
    """Match required JRX features against each installed CLI's own help text."""
    required = {
        "codex": ("exec", "resume", "--model"),
        "claude": ("--model", "--resume", "--continue"),
        "antigravity": ("--model", "--conversation", "--continue"),
    }[spec.key]
    try:
        completed = subprocess.run(
            [executable, "--help"],
            cwd=cwd,
            env=_probe_env(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown", "CLI help could not be inspected; capabilities are unknown", False
    output = (completed.stdout + "\n" + completed.stderr).lower()
    if completed.returncode != 0:
        return "unknown", "CLI help returned an error; capabilities are unknown", False
    missing = [feature for feature in required if feature.lower() not in output]
    if missing:
        return (
            "unsupported",
            "installed CLI lacks required native JRX features: " + ", ".join(missing),
            False,
        )
    if spec.key == "codex":
        try:
            structured_help = subprocess.run(
                [executable, "exec", "--help"],
                cwd=cwd,
                env=_probe_env(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=False,
                shell=False,
            )
            structured = structured_help.returncode == 0 and "--json" in (
                structured_help.stdout + structured_help.stderr
            )
        except (OSError, subprocess.SubprocessError):
            structured = False
    else:
        structured = "--print" in output and "--output-format" in output
    detail = "native launch, model, and resume options detected"
    if not structured:
        detail += "; documented structured output unavailable"
    return "installed", detail, structured


def detect_provider(spec: ProviderSpec, cwd: Path | None = None) -> ProviderStatus:
    working = cwd or Path.cwd()
    path = shutil.which(spec.executable)
    conflicts = any(bool(os.environ.get(name)) for name in spec.api_key_env)
    if path is None:
        return ProviderStatus(
            spec, "missing", None, None, "unknown", False, conflicts, "executable not found on PATH"
        )

    try:
        completed = subprocess.run(
            [path, "--version"],
            cwd=working,
            env=_probe_env(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ProviderStatus(
            spec, "unknown", path, None, "unknown", False, conflicts, "version check failed"
        )
    version_text = (completed.stdout + "\n" + completed.stderr).strip()
    match = _VERSION.search(version_text)
    version = match.group(1) if match else None
    if completed.returncode != 0 or version is None:
        return ProviderStatus(
            spec,
            "unknown",
            path,
            version,
            "unknown",
            False,
            conflicts,
            "version could not be identified",
        )
    capability_status, detail, structured_output = _capability_status(spec, path, working)
    auth, auth_verified = _safe_authentication(spec, path, working)
    return ProviderStatus(
        spec,
        capability_status,
        path,
        version,
        auth,
        auth_verified,
        conflicts,
        detail,
        structured_output,
    )


def detect_providers(cwd: Path | None = None) -> tuple[ProviderStatus, ...]:
    return tuple(detect_provider(provider, cwd) for provider in PROVIDERS)


def build_native_argv(
    provider: str,
    *,
    model: str | None = None,
    resume: bool = False,
    session_ref: str | None = None,
    initial_prompt: str | None = None,
    new_session_id: str | None = None,
) -> list[str]:
    """Build exact argv for the official provider executable."""
    spec = provider_by_key(provider)
    argv = [spec.executable]
    if provider == "codex":
        if model:
            argv += ["--model", model]
        if resume:
            if session_ref:
                argv += ["resume", session_ref]
            else:
                argv += ["resume"]
            if initial_prompt:
                argv.append(initial_prompt)
        elif initial_prompt:
            argv.append(initial_prompt)
    elif provider == "claude":
        if model:
            argv += ["--model", model]
        if resume:
            if session_ref:
                argv += ["--resume", session_ref]
            else:
                argv += ["--continue"]
            if initial_prompt:
                argv.append(initial_prompt)
        else:
            # Claude Code documents this as an interactive CLI option.
            argv += ["--session-id", new_session_id or str(uuid.uuid4())]
            if initial_prompt:
                argv.append(initial_prompt)
    else:
        if model:
            argv += ["--model", model]
        if resume:
            argv += ["--conversation", session_ref] if session_ref else ["--continue"]
        elif initial_prompt:
            # Antigravity documents prompt arguments for headless mode, but
            # does not document an initial-prompt positional form for its TUI.
            argv += [f"--print={initial_prompt}"]
    return argv


def child_environment(provider: str, *, allow_api_key: bool = False) -> dict[str, str]:
    """Remove JRX and unrelated provider credentials from a managed child."""
    selected = provider_by_key(provider)
    remove = [key for key in _ALL_PROVIDER_KEYS if key not in selected.api_key_env]
    env = sanitized_child_env(extra_strip=remove)
    if not allow_api_key:
        # A selected provider's explicit API key can select a separately billed
        # account. Caller must obtain an explicit, visible confirmation first.
        for name in selected.api_key_env:
            env.pop(name, None)
    return env


def discover_models(provider: str, cwd: Path) -> ModelCatalog:
    if provider == "codex":
        return ModelCatalog(
            (),
            "Codex native /model selector",
            False,
            "The app-server model-list API is experimental; use Codex's native selector",
        )
    if provider == "claude":
        return ModelCatalog(
            (),
            "Claude Code native /model selector",
            False,
            "Claude Code does not expose a documented CLI model-list command; use its native selector",
        )
    executable = shutil.which("agy")
    if executable is None:
        return ModelCatalog((), "agy models", False, "Antigravity is not installed")
    try:
        completed = subprocess.run(
            [executable, "models"],
            cwd=cwd,
            env=child_environment("antigravity"),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ModelCatalog(
            (), "agy models", False, "model discovery failed; use Antigravity's native selector"
        )
    choices: list[ModelChoice] = []
    if completed.returncode == 0:
        for line in completed.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and re.fullmatch(r"[A-Za-z0-9._-]+", parts[0]):
                choices.append(ModelChoice(parts[0], parts[1]))
    if not choices:
        return ModelCatalog(
            (),
            "agy models",
            False,
            "model discovery unavailable; use Antigravity's native selector",
        )
    return ModelCatalog(tuple(choices), "agy models", True)
