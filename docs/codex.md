# Codex CLI integration

Codex CLI currently exposes native lifecycle hooks. The installed environment used to develop this MVP reported Codex CLI `0.154.0` with the `hooks` feature enabled. The current official hook documentation describes `PreToolUse`, JSON input on stdin, `hooks.json` or inline `config.toml` sources, and the `hookSpecificOutput.permissionDecision` response shape:

<https://developers.openai.com/codex/hooks>

The hook adds deterministic execution control around Codex; it does not make
Codex deterministic. JEV signals remain probabilistic and the local policy
engine owns the `ALLOW`/`REVIEW`/`HOLD` result.

## Project setup

Install JEV Reflex in the same environment as Codex, then create `.codex/hooks.json` in the repository:

```json
{
  "description": "JEV Reflex deterministic execution control",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|apply_patch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "jev-reflex codex-hook",
            "timeout": 30,
            "statusMessage": "JEV Reflex is checking the proposed action"
          }
        ]
      }
    ]
  }
}
```

Codex may require reviewing/trusting a new or changed project hook in its `/hooks` UI before it runs. Do not bypass that trust review unless the hook source has already been inspected and approved.

The handler reads a Codex event like:

```json
{
  "hook_event_name": "PreToolUse",
  "cwd": "/work/project",
  "tool_name": "Bash",
  "tool_input": {"command": "pytest tests/"}
}
```

It returns no decision for an advisory `ALLOW`, a model-visible `additionalContext` for advisory review/hold recommendations, `permissionDecision: "deny"` for a hold, and a deny for review mode because Codex’s current PreToolUse contract does not support an explicit `ask` decision. Enforce mode blocks hard holds and degraded evaluations; normal Codex permissions remain responsible for non-hard review signals.

## Host-side JEV transport

For sandboxed Codex, use the [host broker](broker.md) and set the hook command to
`jev-reflex codex-hook --config /absolute/path/reflex.broker.yaml`, with
`jev.transport: broker`. Start the broker in a trusted host terminal and launch
Codex without `TYPESAFE_API_KEY`. The hook keeps hard checks and final policy
local. A live response is explicitly identified as `LIVE JEV VIA BROKER`.

The current [official configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
documents per-socket allowances under
`permissions.<name>.network.unix_sockets` and
`features.network_proxy.unix_sockets`. Where supported by the installed host and
its managed policy, add only the absolute broker socket path, for example:

```toml
[permissions.your_profile.network.unix_sockets]
"/home/your-user/.jev-reflex/reflex.sock" = "allow"
```

This is a host configuration example, not a setting JEV Reflex changes. Managed
policies and installed versions can constrain availability. Verify access from
the actual PreToolUse process; a host CLI smoke test alone is insufficient. Keep
ordinary sandbox and approval controls enabled. See the
[official hook contract](https://learn.chatgpt.com/docs/hooks) for hook setup.

## Original task context

The native PreToolUse event does not reliably contain the original user task. The adapter uses a task field if a host supplies one, but it does not scrape unstable transcript formats by default. For task-sensitive checks, put the task in the generic invocation or use the wrapper:

```console
$ jev-reflex check --task "Fix session persistence" --command "python migrate.py"
```

## Wrapper fallback

If the installed Codex surface does not load hooks, use:

```console
$ jev-reflex exec --mode enforce -- python migrate.py
```

This is also the portable integration for CI and other terminal agents. It preserves argv boundaries and does not run the command through a shell.

## Agent instruction

Add the snippet in [examples/AGENTS.md](../examples/AGENTS.md) to the project’s agent instructions. It tells Codex when to call the check and makes clear that JEV is advisory probabilistic input, not ground truth.

## Limitations

Codex’s native local hook path is a useful execution-control layer, not a
complete sandbox. Hosted tools and any tool path that opts out of the local hook
path need their own integration. Keep Codex’s normal sandbox and approval
settings enabled.
