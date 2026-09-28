# Managed agent harness

JRX offers an optional harness for work that benefits from a plan, resumable turns, persistent notes and independent research/review workers. It combines [Deep Agents](https://github.com/langchain-ai/deepagents) (MIT) with the [Agent Client Protocol Python SDK](https://github.com/agentclientprotocol/python-sdk) (Apache-2.0). Deep Agents supplies the planning loop, context management and delegation; ACP supplies a standard bidirectional session and permission protocol for installed agents such as [Codex ACP](https://github.com/zed-industries/codex-acp).

Install the optional integration and start a managed task:

```console
pip install -e ".[harness]"
jrx harness run "Review the cache invalidation logic" --model openai:gpt-6-astra --workspace .
jrx harness status SESSION_ID --workspace .
jrx harness resume SESSION_ID --workspace . --decision reject
jrx harness resume SESSION_ID --workspace . --task "Now fix the confirmed bug"
```

The interactive workspace also starts it with `p`. The model identifier selects the API integration and credential source; JRX does not silently choose a model or API account. Managed execution requires a Git workspace and `mode: enforce`. Enterprise access configurations need their dedicated approval service and cannot be loaded by this managed path.

The coordinator can inspect bounded, nonsensitive repository paths, propose a write, and run commands through JRX policy evaluation and the configured execution sandbox. Repository edits, commands and persistent memory writes pause for a one-time approval. JRX blocks a `HOLD` or degraded decision even after approval. Each file write also requires a SHA256 read precondition. Symlinks, hard-linked files, protected credential/configuration paths and oversized files are excluded. The research and review workers receive only read-only repository tools. They share the coordinator's call budget; their files, outputs and recalled notes remain evidence, never policy instructions. Their workspaces are isolated scratch state, while the coordinator owns repository mutations.

Plans, graph checkpoints, and shared notes live under `$XDG_STATE_HOME/jev-reflex/harness/` (or `~/.local/state/jev-reflex/harness/`) with owner-only permissions. A session is bound to its canonical workspace, model identifier and policy fingerprint. A changed repository invalidates a pending approval; reject it and ask the coordinator to inspect and re-plan. Interrupted tool calls may have partial effects, so recovery requires `--recover` after you inspect the workspace. Recovery does not replay the interrupted action automatically. Status and checkpoint records contain task and model conversation data; protect the local account and state directory accordingly.

Model turn and tool call budgets default to 60 and 120, and a turn may run for at most 600 seconds. Override these with `--max-model-calls`, `--max-tool-calls` and `--timeout`. The underlying model SDK may make an additional summarization request while managing long context; that internal request is controlled by the SDK and is not included in JRX's reported model-turn count. A new model or policy requires a new session.

## ACP agents

For an installed ACP-compatible executable, JRX can manage a bidirectional session and handle only one-time permission choices:

```console
jrx harness acp --task "Inspect the test failures" --workspace . -- codex-acp
jrx harness acp --task "Continue the investigation" --workspace . --resume-session ACP_SESSION_ID -- codex-acp
```

JRX filters credential variables unless an explicit provider is selected. Passing `--allow-api-key --provider codex` is an explicit choice to expose that provider's API key and possible API billing. Permission requests are shown with their arguments, checked by JRX, and checked again after user review. Unknown request types and implicit or session-wide grants are denied. ACP filesystem and terminal callbacks are disabled. ACP is a transport: it does not sandbox a third-party ACP agent executable, which must be configured with its own supported execution controls.

## Limits

The local filesystem tools and execution sandbox still determine the hard boundary. Deep Agents' built-in filesystem tools use private scratch state and its default local shell tool is unavailable; repository access goes through JRX's bounded tools. Subagents are read-only, and the graph uses SQLite checkpoints. Cloud tracing is not enabled by default. Test with an installed model provider and ACP agent under your own account before relying on its behavior; offline tests exercise the real graph and protocol against scripted fake models and local fake agents.
