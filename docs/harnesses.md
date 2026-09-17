# Harness integrations

JEV Reflex can sit at the tool-execution boundary of Antigravity, the
OpenRouter Agent SDK, Pi, and DeepSeek Harness. Each integration sends one
structured tool event to the same bounded context and deterministic policy
engine; the host-specific adapter only translates the final result back to the
harness's native hook response.

Install JEV Reflex in the environment that launches the harness:

```console
$ pip install -e "[dev]"
```

Use `advisory` while validating a setup. Use `review` to require an explicit
approval for review-band actions and `enforce` to block holds and unavailable
semantic evaluations. The harness continues to own its model credentials;
JEV Reflex only needs `TYPESAFE_API_KEY` for direct live judgments, or the
host broker configuration described in [broker.md](broker.md).

## Antigravity

Antigravity command hooks receive a nested `toolCall` payload and expect an
`allow`, `force_ask`, or `deny` response. Copy
[examples/antigravity/hooks.json](../examples/antigravity/hooks.json) to the
workspace customization directory (normally `.agents/hooks.json`) and review
the command before enabling it.

The adapter covers file, shell, search, and collaboration tools with a
match-all `PreToolUse` matcher. In advisory mode it always returns `allow` and
includes the JEV explanation only when there is something to report.

## OpenRouter Agent SDK

The OpenRouter SDK exposes lifecycle hooks. Python applications can register
the adapter directly on both `PreToolUse` and `PermissionRequest` when the
application uses an approval gate:

```python
from jev_reflex.adapters.openrouter import evaluate_openrouter_hook
from jev_reflex.config import load_config
from openrouter_agent import HookEntry, HookName, HooksManager

config = load_config()
hooks = HooksManager()


def pre_tool(payload, _context):
    return evaluate_openrouter_hook(
        {**payload, "cwd": "."},
        config=config,
        event=HookName.PreToolUse.value,
    )[1]


def permission_request(payload, _context):
    return evaluate_openrouter_hook(
        {**payload, "cwd": "."},
        config=config,
        event=HookName.PermissionRequest.value,
    )[1]


hooks.on(HookName.PreToolUse.value, HookEntry(handler=pre_tool))
hooks.on(
    HookName.PermissionRequest.value,
    HookEntry(handler=permission_request),
)
```

`PreToolUse` can block a call. `PermissionRequest` can return `allow`,
`deny`, or `ask_user`, so review-band actions can use the SDK's normal human
approval flow. TypeScript applications can use the equivalent subprocess
bridge in [examples/openrouter/jev-reflex.ts](../examples/openrouter/jev-reflex.ts).

## Pi

Pi exposes a `tool_call` extension event that can block before execution. The
ready-to-load extension in [examples/pi/jev-reflex.ts](../examples/pi/jev-reflex.ts)
invokes `jev-reflex pi-hook` without a shell and returns Pi's native
`{ block, reason }` shape. Install or link it from `.pi/extensions/` or
`~/.pi/agent/extensions/`.

The example defaults to the repository's configured mode. Set `JRX_MODE` or
`JRX_CONFIG` in the Pi process environment when a per-session override is
needed.

## DeepSeek Harness

DeepSeek Harness can run existing Codex command hooks through its hooks bridge.
Copy [examples/deepseek/hooks.json](../examples/deepseek/hooks.json) to the
hook configuration path supplied to the `dsh-hooks-codex` package, then mount
that bridge in the harness preset. The command is explicitly named
`deepseek-hook`, but its response is Codex-shaped because that is the bridge
protocol.

The Codex bridge has no native `ask` decision. Therefore `review` mode blocks
review-band calls at this boundary; use the harness's own approval controls for
interactive review if the selected preset exposes them.

## Verification

Exercise each adapter offline before connecting a live harness:

```console
$ printf '%s\n' '{"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf ./cache"}}}' \
  | jev-reflex antigravity-hook --demo --mode enforce
$ printf '%s\n' '{"toolName":"bash","toolInput":{"command":"rm -rf ./cache"}}' \
  | jev-reflex openrouter-hook --demo --mode enforce
$ printf '%s\n' '{"toolName":"bash","input":{"command":"rm -rf ./cache"}}' \
  | jev-reflex pi-hook --demo --mode enforce
$ printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"rm -rf ./cache"}}' \
  | jev-reflex deepseek-hook --demo --mode enforce
```

All four should return a blocking response without executing the command.
