"""Coding-agent adapters."""

from .antigravity import (
    antigravity_hook_response,
    antigravity_hooks_json,
    evaluate_antigravity_hook,
)
from .claude_code import claude_code_hook_response, claude_code_settings_json
from .codex import codex_hook_response, codex_hooks_json
from .deepseek import deepseek_hook_response, deepseek_hooks_json, evaluate_deepseek_hook
from .generic import Adapter
from .openrouter import evaluate_openrouter_hook, openrouter_hook_response
from .pi import evaluate_pi_hook, pi_hook_response

__all__ = [
    "antigravity_hook_response",
    "antigravity_hooks_json",
    "evaluate_antigravity_hook",
    "claude_code_hook_response",
    "claude_code_settings_json",
    "codex_hook_response",
    "codex_hooks_json",
    "deepseek_hook_response",
    "deepseek_hooks_json",
    "evaluate_deepseek_hook",
    "Adapter",
    "evaluate_openrouter_hook",
    "openrouter_hook_response",
    "evaluate_pi_hook",
    "pi_hook_response",
]
