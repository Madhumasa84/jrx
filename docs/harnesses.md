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

Run `jrx setup --provider codex --apply` in the repository, or create `.codex/hooks.json` yourself with the policy path pinned (hooks run in the agent's current directory, which moves):

```json
{
  "description": "JEV Reflex deterministic execution control",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|exec_command|shell_command|apply_patch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "jrx codex-hook --config /absolute/path/to/repo/reflex.yaml",
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

Claude Code supports `PreToolUse` hooks configured in `.claude/settings.json`. The hook receives JSON on `stdin` and responds with an `ask` or `deny` decision, or with no decision when the action is allowed.

### Setup

Run `jrx setup --provider claude --apply`, or add the following to your project's `.claude/settings.json`. To stop the agent's user from removing or editing the hook, put it in Claude Code's managed settings instead (`/etc/claude-code/managed-settings.json` on Linux, `/Library/Application Support/ClaudeCode/managed-settings.json` on macOS); user and project settings cannot remove managed hooks.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|MultiEdit|Write|NotebookEdit|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "jrx claude-code-hook --config \"$CLAUDE_PROJECT_DIR\"/reflex.yaml",
            "timeout": 30,
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

Claude Code hook timeouts are in seconds. Without `"onFailure": "block"` (Claude Code 2.1.295 or later), Claude Code lets the tool call proceed when the hook exits with a status other than 0 or 2, prints invalid JSON, or times out. jrx answers every failure it can catch with a `deny`, but only the host can act when jrx cannot start or is killed.

### Event Flow & Mapping
- `ALLOW`: Returns no `permissionDecision`, so Claude Code's normal permission rules still apply.
- `REVIEW`: In `review` or `enforce` mode, returns `permissionDecision: "ask"` to prompt the user interactively before proceeding (`deny` when `strict_review_required` is set).
- `HOLD`: Returns `permissionDecision: "deny"` with audit reasons and warnings.
- Degraded evaluation: Returns `permissionDecision: "deny"` in `review` and `enforce` mode.
- `advisory` mode: Permits execution while appending advisory recommendations to `additionalContext`; host guard denials are still denied.

---

## 3. Google Antigravity

Antigravity command hooks intercept tool calls and expect an `allow`, `force_ask`, or `deny` response.

### Setup

Copy `examples/antigravity/hooks.json` into `.agents/hooks.json` (`jev-reflex` and `jrx` are the same command):

```json
{
  "jev-reflex": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "jev-reflex antigravity-hook",
            "timeout": 30
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

TypeScript applications can utilize the subprocess bridge located in `examples/openrouter/jev-reflex.ts`. It blocks the call (or denies the permission request) when `jev-reflex` cannot start, exits with a non-zero status, prints anything but a JSON object, or does not answer within `JRX_HOOK_TIMEOUT_MS` (default 30000).

---

## 5. Pi Agent

Pi exposes a `tool_call` extension event that intercepts calls prior to dispatch.

### Setup

Install the extension from `examples/pi/jev-reflex.ts` into `.pi/extensions/`. It sends each `tool_call` to `jev-reflex pi-hook` and blocks the call when jrx blocks it, cannot start, exits with a non-zero status, prints anything but a JSON object, or does not answer within `JRX_HOOK_TIMEOUT_MS` (default 30000). `JRX_CONFIG` and `JRX_MODE` in the environment Pi starts with become `--config` and `--mode`; set them from host configuration, not from anything the agent can change. Its behaviour is tested in `tests/test_typescript_adapters.py`.

---

## 6. DeepSeek Harness

DeepSeek Harness executes command hooks via the `dsh-hooks-codex` bridge protocol. Like Codex, that contract has no interactive `ask`, so `REVIEW` returns `permissionDecision: "deny"` in `review` and `enforce` mode; `HOLD` and degraded results are denied too.

### Setup

Copy `examples/deepseek/hooks.json` to your hook configuration directory:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "jev-reflex deepseek-hook",
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

All commands output blocking decisions (`deny` or `block: true`) and exit with status 0: native hooks always carry the decision, including failures jrx catches, in the JSON on stdout, because hosts disagree about what a non-zero exit means. PostToolUse recording failures exit 2.
