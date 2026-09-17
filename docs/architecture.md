# Architecture

JEV Reflex sits between a coding agent’s proposed action and the host’s normal
execution or permission path.

```text
user task + repository state + proposed action
                    ↓
             ContextProvider
                    ↓
       deterministic redaction + bounds
                    ↓
          DeterministicChecks
             /           \
            /             \
           ↓               ↓
  hard local findings   JEVSemanticEvaluator
           \             /
            \           /
             ↓         ↓
        DeterministicPolicyEngine
                    ↓
             ALLOW / REVIEW / HOLD
                    ↓
       generic CLI, wrapper, or native hook
```

The important boundary is not “make the agent deterministic.” The agent and
JEV remain probabilistic. The boundary is that policy evaluation is normal
code with explicit inputs and no network, model call, randomness, or hidden
state.

## Layers

### ContextProvider

`RepositoryContextProvider` collects a compact `EvaluationContext`:

- original task when the host supplies it
- repository name and canonical repository root
- canonical working directory
- proposed action, preserving argv where available
- bounded changed-file list and Git diff
- optional tests, recent context, and retrieved content

Git inspection uses fixed argv and `shell=False`. Context size limits are
deterministic and applied before evaluation.

### Redaction

`redaction.py` runs before terminal output, model transmission, debugging, or
calibration. It replaces common credentials and secret values with
`<REDACTED_SECRET>`. The redactor is heuristic and is not a complete DLP
system.

### DeterministicChecks

`src/jev_reflex/checks/` contains model-free checks. Each returns structured
`DeterministicFinding` values such as:

```json
{
  "check": "repo_boundary",
  "triggered": true,
  "severity": "high",
  "reason_code": "TARGET_OUTSIDE_REPO",
  "blocking": true
}
```

The MVP checks secret patterns, plainly destructive commands, canonical path
escapes, known dangerous Git operations, filesystem/database hazards, and a
small safe-command allow-list. Checks handle obvious cases only; ambiguous
intent remains a semantic-evaluation problem.

### JEVSemanticEvaluator

`JEVSemanticEvaluator` is the semantic layer. It builds 18 independent `Noul`
judgments plus a `Choice` and `Score` risk classification, for 20 small
structured primitives in one System One request. It consumes probabilities and
risk metadata only. It never returns or chooses `ALLOW`, `REVIEW`, or `HOLD`.

The TypeSafe-specific implementation is isolated in
`src/jev_reflex/integrations/typesafe.py`. This boundary uses the official
`TypeSafeClient().system_one(...)`, reads only `TYPESAFE_API_KEY`, and can be
replaced with a fake or another semantic backend without changing policy.

### DeterministicPolicyEngine

`src/jev_reflex/policy.py` exposes the pure `decide(...)` function and the
`DeterministicPolicyEngine` class. It combines local findings, normalized
probabilities, risk metadata, and validated configuration.

Default behavior:

1. Any triggered blocking deterministic finding produces `HOLD`.
2. A configured hold signal at or above the strong/hold threshold produces
   `HOLD`.
3. Review-band signals, configured review signals, medium/high risk, low
   confidence, human review, review mode, or degraded JEV evaluation produce
   `REVIEW`.
4. Otherwise the result is `ALLOW`.

Security-sensitive signals default to `REVIEW`, not automatic `HOLD`.
Conservative boundary mode treats probabilities near a threshold as
`BOUNDARY_UNCERTAIN` and returns `REVIEW` unless a local hard rule also
matches. The `majority` stability policy requires explicit multiple samples;
the default is one sample with strict thresholds.

The policy function has no timestamps, randomness, network calls, model calls,
or mutable decision state. Therefore identical structured inputs produce the
same policy result, including the same ordered explanation rules.

### StabilityEvaluator

`StabilityRunner` evaluates the same context repeatedly, applies the policy on
each result, and passes the results to `build_report`. It reports:

- `decision_consistency = max(decision_counts) / runs`
- `decision_flip_rate = 1 - decision_consistency`
- per-signal mean, population standard deviation, min, max
- threshold crossings and crossing rate
- high-confidence disagreement rate
- degraded-run count

This measures observed stability of the overall control decision. It does not
claim that JEV or the coding agent is deterministic.

## State contract

The redacted model-facing state is intentionally narrow:

```json
{
  "user_task": "...",
  "repository": "...",
  "repository_root": "...",
  "working_directory": "...",
  "proposed_action": {
    "type": "shell_command",
    "command": "...",
    "argv": []
  },
  "changed_files": [],
  "git_diff": "...",
  "test_results": "...",
  "recent_context": "...",
  "external_content": "..."
}
```

Every field other than configuration is evaluated as untrusted data. Text in a
diff or retrieved document cannot update thresholds or policy lists. Large
fields are bounded before the SDK call, and a malformed response is rejected
as degraded rather than treated as approval.

## Adapters and extension path

The stable public contract is the JSON CLI:

```console
$ jev-reflex check --json --command "..."
```

`exec`, Codex, and Claude Code adapters translate host actions into the same
context/result types. The contracts are intentionally reusable for future MCP
firewalls, research agents, browser agents, and CI/PR gates. The first product
stays focused on coding-agent execution control.
