"""Coding-agent adapters."""

from .claude_code import claude_code_hook_response, claude_code_settings_json
from .codex import codex_hook_response, codex_hooks_json
from .generic import Adapter

__all__ = [
    "claude_code_hook_response",
    "claude_code_settings_json",
    "codex_hook_response",
    "codex_hooks_json",
    "Adapter",
]
