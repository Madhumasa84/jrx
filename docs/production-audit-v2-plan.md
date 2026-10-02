# Production audit V2 architecture and implementation plan

The user has authorized autonomous audit, repairs, regression tests and two optional
controls. Implementation runs inline on `hardening/production-audit-v2`, isolated
from the original dirty checkout. Paid API tests and external infrastructure are excluded.

## Trust map

Agent-controlled task, command, argv, nested tool inputs and repository content enter
native adapters / CLI / MCP. Context collection runs fixed Git inspection commands
against private metadata; the repository's executable Git configuration is excluded.
Deterministic checks inspect original actions. Redaction precedes the semantic
evaluator; TypeSafe/broker responses remain advisory structured evidence. Policy
combines checks and signals. CLI/hooks/MCP gate forwarding, OIDC verifies host identity,
approvals bind risky execution to Git/action/policy/environment, sessions atomically
reserve budgets, audit records decisions, and optional Docker isolates execution.

Trusted host assets: installed Python code, executable search path, protected bootstrap,
signed policy public key, OIDC configuration, gateway upstream command, broker runtime,
audit signing key, persistent databases, Docker daemon and operator administration.
Untrusted network assets: semantic output, JWKS until HTTPS verification, remote policy
until signature verification, MCP catalog until pin verification, proxy DNS until address checks.
Process boundaries: Git, secret scanner, provider CLIs, MCP upstream, Docker CLI and proxy.
Persistent state: approvals/grants, session counters, rollout file, audit chain, harness
checkpoints, workspace handoffs. Cryptographic state: Ed25519 policy/audit keys and JWT keys.
Environment: host identity/session IDs, credentials, PATH and transport settings must
be supplied by the trusted host. Allowing an agent to change these defeats the boundary.

Bypass surfaces: omit hooks, modify policy/bootstrap, invoke executor outside JRX,
change commands/files after evaluation, exploit parsing differences, reuse approvals,
race session reservations, alter state, spoof identity/session, change MCP schemas,
replace host binaries, request direct network egress. These are tested or explicitly
bounded; JRX is not an OS reference monitor.

## Feature design

Use two separate optional host-side stores with a shared authenticated SQLite helper.
Rows have canonical JSON and HMAC-SHA256 under a separately protected 32-byte host key.
SQLite BEGIN IMMEDIATE serializes authorization plus mutations. Explicit limits cap
objects and action records; at capacity fail closed instead of evicting replay evidence.
No raw task, command, token or arguments are stored; fingerprints and canonical resource
paths provide evidence. Missing/corrupt keys/state fail closed. Operator key creation is explicit.
HMAC detects row changes without key access; deletion/rollback of all state requires
host storage protection and externally retained evidence. This is not remote attestation.

Intent envelopes bind session, task hash, canonical repository, policy revision, allowed
literal relative directory prefixes, allowed/forbidden capabilities and cumulative drift.
Every action records its parent, fingerprint, resources, capabilities, decision and
evidence. Scope and capability violations block deterministically; cumulative semantic
`scope_creep` evidence can also stop a trajectory. Disabled semantic evaluation does
not bypass deterministic checks. Unsupported command syntax is classified `unknown`,
requiring explicit broad authority; scoped execution cannot infer arbitrary program I/O.

Authority leases bind issuer, subject identity, child session, repository, environment,
policy, literal resource prefixes, capabilities, issue/expiry, nonce, parent and depth.
Issuance checks attenuation under the entire live ancestor chain. Child paths must be
contained by parent prefixes; capabilities subset; environment/repository exact;
expiry no later than parent; forbidden classes accumulate. No lease grants human
review/admin privilege. Authorization consumes a unique action nonce in the same
transaction as validation; duplicate nonce rejects. Parent revocation cascades by
checking ancestors on every use. Host authenticates subjects using OIDC when configured;
without OIDC it asserts identity through a protected process environment.

Integration point: the shared `evaluate_context` adds blocking deterministic findings
for envelope/lease failures; CLI/hooks cannot override these findings. MCP retains its
existing allowlist, schemas, identity and live-write requirements. Neither feature
replaces normal policy or human approvals. The semantic broker remains keyless with
respect to the new stores; enforcement occurs in the trusted host gateway process.

## Novelty check

Current JRX has per-action approvals, cumulative budgets and task-bearing context, but
no authenticated task envelope or attenuating authority graph. Compare existing work:
[Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
controls filesystem/network confinement; [SPIFFE](https://spiffe.io/docs/latest/spiffe/concepts/)
provides workload identity; [OpenFGA conditional tuples](https://openfga.dev/blog/conditional-tuples-announcement)
provide contextual/expiring authorization relationships. These concepts overlap with
our building blocks. No global novelty claim is justified. The integrated controls are
novel relative to the current JRX architecture; the reviewed sources do not establish
whether equivalent integrations exist across all coding-agent systems.

## Execution and validation

1. Record base/environment, baseline, architecture and historical reproduction evidence.
2. Confirm defects in tests, write findings before implementation, fix each boundary.
3. Run regression and neighboring suites, then baseline again.
4. Add intent contract/adversarial tests before implementation; implement persistence,
   deterministic scopes, cumulative drift and CLI inspection/stop.
5. Add delegation adversarial tests before implementation; implement attenuation,
   cryptographic state validation, revocation, replay and CLI inspection/tree.
6. Exercise integration through CLI/hooks/MCP and concurrent processes.
7. Run complete suite, static checks, golden tests, package/install, Docker and Helm.
8. Update docs after verification, produce exact results and limits, commit logical groups.

Review focus: agents must not choose trusted session/identity metadata; unknown shell
syntax must not be interpreted as a narrow read; same-prefix string attacks and symlinks
must fail path containment; stopped/revoked ancestors remain invalid after restart;
state limits must preserve nonce records instead of re-enabling replay.
