# Execution Lineage and Intent Drift Guard

**Implemented, optional, disabled by default.** This initial control uses conservative
preflight classification. Its enforcement code and local adversarial tests are implemented;
deployment in actual autonomous agent hosts remains experimental.

An operator creates an envelope for a host-assigned session. It binds the exact task hash,
canonical repository, effective configuration revision, permitted literal relative path
prefixes, permitted/forbidden capability classes and maximum cumulative drift evidence.
Every evaluated action records a UUID, prior action ID, action fingerprint, redacted
resource labels, capability classes, the ordinary policy decision and drift evidence.
`scope_creep` probabilities accumulate; deterministic resource/capability violations,
task changes and policy changes deny independently of semantic scoring.

## Host setup

Store keys, policy and state outside the agent-readable filesystem. The store directory
must be owned by the host account with mode 0700; files must be private regular files.
For example, configure protected `reflex.yaml`:

```yaml
mode: enforce
intent:
  enabled: true
  path: /var/lib/jrx/controls/intent.sqlite3
  key_path: /var/lib/jrx/controls/host.key
  max_sessions: 1000
  max_actions_per_session: 1000
  max_records: 100000
```

Create the key once. Key generation refuses to overwrite an existing key:

```bash
jrx intent keygen --config /etc/jrx/reflex.yaml --repository /srv/repo
jrx intent create test-session --config /etc/jrx/reflex.yaml \
  --repository /srv/repo --task 'Fix a failing unit test' \
  --scope tests --capability read --capability modify \
  --forbidden secrets --forbidden deploy --forbidden publish --forbidden iam
jrx intent status test-session --config /etc/jrx/reflex.yaml
jrx intent explain test-session --config /etc/jrx/reflex.yaml
jrx intent stop test-session --config /etc/jrx/reflex.yaml
```

The trusted host supplies `JRX_SESSION_ID=test-session` on every invocation and the exact
approved task through `--task` or native hook task metadata. Changing the task, repository
or effective configuration requires a new envelope/session. Configuration includes the
control limits themselves; CLI sample/mode overrides also change its revision.

Operators use OIDC `admin` permission to create/stop envelopes and `view` to inspect
when `access` is configured. Without OIDC, administration relies on protected host OS
access. The Python store APIs are host APIs, not unauthenticated remote endpoints.

## Supported scope checks

Scopes are literal relative directory/file prefixes; `.` means the repository. Arbitrary
globs, traversal, absolute scopes and symlink escapes are rejected. Prefix containment
uses path components, so `tests_evil` is outside `tests`. Simple `cat`, `head`, `tail`,
`ls` and `wc` calls use explicit path arguments and a limited option allowlist. Exact
`/bin/NAME` and `/usr/bin/NAME` spellings for those programs are recognized. The host
must protect executable resolution and PATH. Compound shells, unknown options,
interpreters, wrappers and arbitrary programs receive `unknown` capability. Pytest is
classified as `test` with repository-wide resource scope because tests execute arbitrary
code. A narrow test filename does not imply narrow process authority.

MCP capability classification uses the protected rule's `effect`, with explicit path
fields for resource checks. Native shell hooks share the same gate. Generic file tools
whose adapter has no trusted capability mapping remain `unknown`; do not grant broad
authority to conceal unsupported integrations. Add tested host mappings before deploying
narrow envelopes for those tool surfaces.

## Failure and persistence

Missing envelopes, missing/corrupt keys, malformed state, lineage deletion, storage
exhaustion and lock failures deny with `agent_control:INTENT_DENIED`. Configured control
denials cannot be overridden with `--yes`, ordinary approvals or CLI advisory mode.
Stop state is checked again immediately before CLI launch/MCP forwarding. Hooks rely on
the host to execute promptly after its hook returns.

Records use HMAC-SHA256 under a separate host key. SQLite `BEGIN IMMEDIATE` protects
lineage append plus cumulative drift update across processes. Limits refuse additional
records rather than discarding security evidence. There is no automatic pruning; archive
state and provision fresh sessions under operator control when reaching limits.
Ordinary decision audit logs retain blocking findings; `intent explain` provides the
authenticated trajectory, including allowed actions.

## Limitations

This does not understand intent perfectly, trace runtime file access, attest remote
agents, prevent all TOCTOU or replace a sandbox. Scripts/tests can touch more resources
than their argv suggests. Scope detection is deliberately conservative and cannot prove
the actual behavior of a program. Semantic drift accumulation depends on evaluator
quality and is additional evidence; disabled/unavailable semantics do not remove scope
checks. Under non-advisory execution, degraded semantic evaluation still blocks.

HMAC detects altered records without key access. A missing linked lineage record is
detected, but deletion/rollback of the entire database to a previously valid snapshot
requires host storage protection or an external checkpoint. Same-UID agents able to
read the key, alter config, select their own session IDs or run outside JRX can bypass
the boundary. JRX does not configure OS separation for you. Resource labels use
heuristic redaction; fingerprints/task hashes are not encryption of confidential data.
