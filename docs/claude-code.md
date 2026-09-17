# Claude Code integration

Claude Code currently supports `PreToolUse` command hooks configured in JSON settings files. The hook receives one JSON event on stdin and can return an explicit `allow`, `ask`, or `deny` decision:

<https://docs.anthropic.com/en/docs/claude-code/hooks>

This adapter supplies deterministic execution control around Claude Code. It
does not make Claude Code deterministic; JEV remains a probabilistic semantic
signal and local policy owns the final control decision.

## Project setup

Install JEV Reflex in the same environment as Claude Code and merge this into the project’s `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "jev-reflex claude-code-hook",
            "timeout": 30000
          }
        ]
      }
    ]
  }
}
```

If the file already has hooks, merge the `PreToolUse` matcher group instead of replacing unrelated settings. User-level `~/.claude/settings.json` applies across projects; project-level `.claude/settings.json` can be reviewed and committed with the repository.

For a Bash call, the event includes a shape like:

```json
{
  "hook_event_name": "PreToolUse",
  "cwd": "/work/project",
  "tool_name": "Bash",
  "tool_input": {"command": "pytest tests/"}
}
```

The adapter maps `HOLD` to `permissionDecision: "deny"`, `REVIEW` to `permissionDecision: "ask"` in non-advisory modes, and advisory recommendations to model-visible `additionalContext` without blocking. Degraded non-advisory evaluations are denied safely.

## Wrapper fallback

For a session or surface where hooks are disabled:

```console
$ jev-reflex exec --mode review -- pytest tests/
```

The wrapper is the stable generic contract and works independently of Claude Code.

## Task and retrieved content

PreToolUse carries tool arguments, working directory, and session metadata, but not a guaranteed canonical copy of the original user task. Pass task context through `jev-reflex check --task` when it is important. Retrieved text should be supplied as `--external-content`; JEV Reflex treats it as untrusted data and never lets its instructions modify policy.

## Security notes

Keep Claude Code’s own permission mode and sandbox controls active. Hook output is a decision signal and does not replace the host’s authorization system. Review [docs/security.md](security.md) before enabling enforce mode.
