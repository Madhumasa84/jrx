# Agent Harness Integrations

JEV Reflex (`jrx`) sits at the tool-execution boundary of modern coding agents, enforcing deterministic hard rules and probabilistic semantic safety signals before code or shell execution occurs.

Each integration sends structured tool events to the same bounded context and deterministic policy engine; the host-specific adapter translates the final result back to the harness's native hook response.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Coding Agent Harness                            │
│   (Codex | Claude Code | Antigravity | OpenRouter | Pi | DeepSeek)     │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Native Tool Use Event (JSON)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     JEV Reflex Harness Adapter                         │
│                    `jrx <harness-name>-hook`                           │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Bounded Context
                                   ▼
┌──────────────────────────────────┴─────────────────────────────────────┐
│                       JEV Reflex Engine (`jrx`)                        │
│                                                                        │
│   [ 1. Hard Rules Engine ]  ──(HOLD if triggered)──────────────────┐  │
│              │ (pass)                                               │  │
│   [ 2. Semantic Evaluation ] (Direct or via Host Broker)            │  │
│              │                                                      │  │
│   [ 3. Deterministic Policy ] ──> ALLOW / REVIEW / HOLD ────────────┤  │
│              │                                                      │  │
│   [ 4. Merkle Audit Append ] ───────────────────────────────────────┘  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Native Decision (`allow` / `ask` / `deny`)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Execution Decision                              │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 1. OpenAI Codex CLI

Codex CLI exposes native lifecycle hooks via `PreToolUse` events configured in `.codex/hooks.json`.

### Setup

Create or update `.codex/hooks.json` in the root of your project:

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
            "command": "jrx codex-hook",
            "timeout": 30,
            "statusMessage": "JEV Reflex is validating proposed action"
          }
        ]
      }
    ]
  }
}
```

### Event Flow & Mapping
- Input: JSON event containing `hook_event_name: "PreToolUse"`, `cwd`, `tool_name`, and `tool_input`.
- Decisions:
  - `ALLOW`: Returns no decision restriction.
  - `REVIEW`: In `review` or `enforce` mode, returns `permissionDecision: "deny"` with rationale (Codex hooks currently lack an interactive `ask` callback).
  - `HOLD`: Returns `permissionDecision: "deny"`.
- Host Broker Setup: In sandboxed environments without direct TypeSafe API access, pass `--config reflex.broker.yaml` to route through the host broker socket.

---

## 2. Anthropic Claude Code

Claude Code supports `PreToolUse` hooks configured in `.claude/settings.json`. The hook receives JSON on `stdin` and responds with an explicit `allow`, `ask`, or `deny` decision.

### Setup

Add the following to your project's `.claude/settings.json` (or user-level `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "jrx claude-code-hook",
            "timeout": 30000
          }
        ]
      }
    ]
  }
}
```

### Event Flow & Mapping
- `ALLOW`: Returns `permissionDecision: "allow"`.
- `REVIEW`: In `review` mode, returns `permissionDecision: "ask"` to prompt the user interactively before proceeding.
- `HOLD`: Returns `permissionDecision: "deny"` with audit reasons and warnings.
- `advisory` mode: Always permits execution while appending advisory recommendations to `additionalContext`.

---

## 3. Google Antigravity

Antigravity command hooks intercept tool calls and expect an `allow`, `force_ask`, or `deny` response.

### Setup

Copy `examples/antigravity/hooks.json` into `.agents/hooks.json`:

```json
{
  "description": "JEV Reflex execution control for Antigravity",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "jrx antigravity-hook",
            "timeout": 30000
          }
        ]
      }
    ]
  }
}
```

### Event Flow & Mapping
- `ALLOW` -> `allow`
- `REVIEW` -> `force_ask` (prompts the human developer in the IDE/CLI)
- `HOLD` -> `deny`

---

## 4. OpenRouter Agent SDK

The OpenRouter SDK exposes Python and TypeScript lifecycle hooks (`PreToolUse` and `PermissionRequest`).

### Python Integration

```python
from jev_reflex.adapters.openrouter import evaluate_openrouter_hook
from jev_reflex.config import load_config
from openrouter_agent import HookEntry, HookName, HooksManager

config = load_config()
hooks = HooksManager()


def on_pre_tool(payload, _context):
    return evaluate_openrouter_hook(
        {**payload, "cwd": "."},
        config=config,
        event=HookName.PreToolUse.value,
    )[1]


def on_permission_request(payload, _context):
    return evaluate_openrouter_hook(
        {**payload, "cwd": "."},
        config=config,
        event=HookName.PermissionRequest.value,
    )[1]


hooks.on(HookName.PreToolUse.value, HookEntry(handler=on_pre_tool))
hooks.on(HookName.PermissionRequest.value, HookEntry(handler=on_permission_request))
```

TypeScript applications can utilize the subprocess bridge located in `examples/openrouter/jev-reflex.ts`.

---

## 5. Pi Agent

Pi exposes a `tool_call` extension event that intercepts calls prior to dispatch.

### Setup

Install the extension from `examples/pi/jev-reflex.ts` into `.pi/extensions/`:

```typescript
import { registerExtension } from "@pi/agent";
import { execFileSync } from "child_process";

registerExtension({
  name: "jev-reflex",
  onToolCall: async (event) => {
    try {
      const output = execFileSync("jrx", ["pi-hook"], {
        input: JSON.stringify(event),
        encoding: "utf-8",
      });
      return JSON.parse(output);
    } catch (err) {
      return { block: true, reason: "JEV Reflex evaluation failed (fail-closed)" };
    }
  },
});
```

---

## 6. DeepSeek Harness

DeepSeek Harness executes command hooks via the `dsh-hooks-codex` bridge protocol.

### Setup

Copy `examples/deepseek/hooks.json` to your hook configuration directory:

```json
{
  "description": "JEV Reflex DeepSeek Hook",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|.*",
        "hooks": [
          {
            "type": "command",
            "command": "jrx deepseek-hook",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

---

## 7. Universal CLI Wrapper Fallback

For any agent, shell, CI pipeline, or tool where native hooks are unavailable, use the direct execution wrapper:

```bash
# Advisory mode (audit and log only)
jrx exec --mode advisory -- pytest tests/

# Review mode (halts execution if review is required)
jrx exec --mode review -- make deploy

# Enforce mode (strictly halts on HOLD decisions)
jrx exec --mode enforce -- python migrate.py
```

The wrapper preserves exact `argv` boundaries, executes without subshell expansion vulnerabilities, and logs cryptographically chained audit events.

---

## 8. Offline Verification Commands

Verify all 6 harness hooks offline using demo evaluation mode:

```bash
# Codex
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | jrx codex-hook --demo --mode enforce

# Claude Code
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | jrx claude-code-hook --demo --mode enforce

# Antigravity
printf '%s\n' '{"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /"}}}' \
  | jrx antigravity-hook --demo --mode enforce

# OpenRouter
printf '%s\n' '{"toolName":"bash","toolInput":{"command":"rm -rf /"}}' \
  | jrx openrouter-hook --demo --mode enforce

# Pi
printf '%s\n' '{"toolName":"bash","input":{"command":"rm -rf /"}}' \
  | jrx pi-hook --demo --mode enforce

# DeepSeek
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | jrx deepseek-hook --demo --mode enforce
```

All commands output blocking decisions (`deny` or `block: true`) and exit with non-zero status codes where appropriate.
