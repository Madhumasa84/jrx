# Enforcement guarantees

JEV Reflex decides; something else has to stop the action. This page states, for every
supported integration, what reaches the component that can actually stop execution, and
separates what JRX detects from what the host physically prevents. Every row of the
matrix below is executed through the real entry points by
[`tests/test_enforcement_matrix.py`](../tests/test_enforcement_matrix.py), which also
checks that this table matches the tested expectations.

## The default installation

The quickstart (`jrx init --preset dev-safe`, then `jrx setup --provider NAME --apply`)
installs a policy in `enforce` mode with the local ONNX evaluator, and a native hook
pinned to that policy with `--config`. With that installation:

- **HOLD is denied** by every hook, and `jrx exec` does not start the process.
- **REVIEW never runs unattended.** Hosts that can ask (Claude Code, Antigravity, OpenRouter
  `PermissionRequest`) put the question to the user; the others deny. `jrx exec` asks on
  the terminal (no terminal means no) and `jrx check` exits 2.
- **Evaluation failures deny.** An unavailable or silent semantic judge (no model, no key,
  broker down or timing out), malformed hook input, and a missing or invalid policy all
  produce the adapter's deny response, with exit status 0 so the host reads it.
- **Crashes and timeouts outside jrx** are the host's to handle. `jrx setup` writes
  `"onFailure": "block"` for Claude Code so a hook that cannot start, crashes or times out
  blocks the call (Claude Code 2.1.295 or later). For Codex and Antigravity, how a
  non-zero exit or timeout is treated is not documented; jrx never relies on it.
- **Nothing is physically prevented by JRX itself.** A hook only works while the host runs
  it and honours its answer; see [What each layer contributes](#what-each-layer-contributes).

Without any `reflex.yaml`, `jrx check` and `jrx exec` fall back to built-in `advisory`
defaults (report only), while hooks deny. Always pass `--config` to wrappers that enforce.

## Matrix

`proceed`: JRX does not stop the call and the host's own permission flow decides (JRX never
grants a permission: Claude Code receives no decision and Antigravity's `allow` delegates
to its default policy). `ask`: the host prompts the user. `deny`: the host refuses the call.
In `review` mode every non-HOLD result becomes `REVIEW`. Inputs: `ALLOW` is
`pytest tests/`, `REVIEW` is `ssh build-host ls` (remote execution), `HOLD` is
`rm -rf ./cache`; the judge rows use the real evaluator with no key, or a broker that
accepts connections and never answers.

<!-- matrix:start -->
| Adapter | Mode | `ALLOW` | `REVIEW` | `HOLD` | judge unavailable | judge timeout | malformed JSON | empty input | missing policy | invalid policy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `claude` | `advisory` | proceed | proceed | proceed | proceed | proceed | deny | deny | deny | deny |
| `claude` | `review` | ask | ask | deny | deny | deny | deny | deny | deny | deny |
| `claude` | `enforce` | proceed | ask | deny | deny | deny | deny | deny | deny | deny |
| `antigravity` | `advisory` | proceed | proceed | proceed | proceed | proceed | deny | deny | deny | deny |
| `antigravity` | `review` | ask | ask | deny | deny | deny | deny | deny | deny | deny |
| `antigravity` | `enforce` | proceed | ask | deny | deny | deny | deny | deny | deny | deny |
| `openrouter-permission` | `advisory` | proceed | proceed | proceed | proceed | proceed | deny | deny | deny | deny |
| `openrouter-permission` | `review` | ask | ask | deny | deny | deny | deny | deny | deny | deny |
| `openrouter-permission` | `enforce` | proceed | ask | deny | deny | deny | deny | deny | deny | deny |
| `codex` | `advisory` | proceed | proceed | proceed | proceed | proceed | deny | deny | deny | deny |
| `codex` | `review` | deny | deny | deny | deny | deny | deny | deny | deny | deny |
| `codex` | `enforce` | proceed | deny | deny | deny | deny | deny | deny | deny | deny |
| `deepseek` | `advisory` | proceed | proceed | proceed | proceed | proceed | deny | deny | deny | deny |
| `deepseek` | `review` | deny | deny | deny | deny | deny | deny | deny | deny | deny |
| `deepseek` | `enforce` | proceed | deny | deny | deny | deny | deny | deny | deny | deny |
| `openrouter-pre` | `advisory` | proceed | proceed | proceed | proceed | proceed | deny | deny | deny | deny |
| `openrouter-pre` | `review` | deny | deny | deny | deny | deny | deny | deny | deny | deny |
| `openrouter-pre` | `enforce` | proceed | deny | deny | deny | deny | deny | deny | deny | deny |
| `pi` | `advisory` | proceed | proceed | proceed | proceed | proceed | deny | deny | deny | deny |
| `pi` | `review` | deny | deny | deny | deny | deny | deny | deny | deny | deny |
| `pi` | `enforce` | proceed | deny | deny | deny | deny | deny | deny | deny | deny |
<!-- matrix:end -->

`jrx check` cannot ask, so it exits 0 for `proceed` and 2 otherwise. `jrx exec` runs
`proceed` actions, asks for `REVIEW` (and for `HOLD` in `review` mode, or in `enforce`
mode with `policy.allow_hold_override`), and runs nothing when the answer is not yes.
Host-guard findings (control-file tampering, credential taint, agent controls, required
audit write failure) deny in every mode, including `advisory`.

## Coverage of each integration

| Integration | What it sees | What it does not see |
| --- | --- | --- |
| Claude Code hook | `Bash` (and `Monitor` commands), `Edit`, `Write`, legacy `MultiEdit`/`NotebookEdit`, every `mcp__*` tool, also inside subagents | `Read`, `Glob`, `Grep`, `WebFetch`, `WebSearch`, `Agent`, `PowerShell`; `@file` mentions |
| Codex hook | `Bash`, `exec_command`, `shell_command`, `apply_patch`, `mcp__*` | Other Codex tools |
| Antigravity hook | Every tool (`*`) | Surfaces where Antigravity does not fire `PreToolUse` |
| DeepSeek hook | Every tool (`.*`) through the Codex-compatible bridge | — |
| OpenRouter / Pi bridges | Every tool call the SDK routes to the bridge | Calls made outside the SDK |
| `jrx mcp serve` | `tools/call` requests | Every other MCP request and notification is forwarded unevaluated |
| `jrx exec` | Commands routed through it | Anything run without it |
| `jrx check` | The command it is given | Nothing is executed |
| Workspace deep harness | Writes, commands and memory writes, each after a human approval of that exact call | The approval prompt runs before evaluation and does not show JRX's reason |

Hooks run outside any host sandbox and only while the host runs them: a user or agent who
can edit the host's hook settings can remove them. Claude Code managed settings
(`/etc/claude-code/managed-settings.json`, `/Library/Application Support/ClaudeCode/managed-settings.json`)
cannot be removed by user or project settings.

## What each layer contributes

**Deterministic checks (always on, no model).** Bounded inspection of the proposed
command, patch or tool arguments: destructive commands and their wrappers, secrets,
Git history rewrites, untrusted install sources and pipe-to-interpreter, repository and
workspace boundaries, writes to agent instructions, hook settings and policy files,
remote, container and privileged execution, unresolved shell expansions. CI workflow
files (`.github/workflows/*`) are not control files: writing them is not flagged unless
another rule applies. A blocking
finding is a `HOLD` before any model signal is read. Detection is by inspection of text,
not by observing execution: see [shell inspection limits](security.md#threats-and-mitigations).

**The optional semantic model.** Adds signals the rules cannot express (prompt injection,
goal hijacking, risky intent) that can raise a decision to `REVIEW` or `HOLD`. It never
removes a deterministic finding. When it is required but unavailable, slow or malformed,
the result is degraded and denied in `review` and `enforce` mode.

**Host permissions and sandboxes (the only physical prevention).** What the host or the
operating system refuses to do: the host not running a denied tool call; Claude Code's
sandbox limiting `Bash` writes to the working directory (its `Edit`/`Write` tools follow
permission rules instead); OS users and file ownership keeping trust inputs away from the
agent ([trust anchors](security.md#trust-anchors-which-files-the-evaluating-user-must-not-control));
JRX's optional Docker sandbox for `jrx exec`. An agent that can run code outside every
hooked path is limited only by these.

## Known gaps

- Read and web tools are outside the Claude Code and Codex matchers.
- The MCP gateway evaluates only `tools/call`.
- Hosts without a documented failure setting (Codex, Antigravity) may let a call proceed if
  jrx cannot start or is killed by the host's timeout.
- The deep harness asks for approval before JRX evaluates, so a `REVIEW` there rests on an
  approval that did not show JRX's reason.
- Writes to CI workflow files are not flagged by the control-file rules.
- A tool call with no arguments is denied in every mode, which adds friction for
  argument-less MCP tools.
