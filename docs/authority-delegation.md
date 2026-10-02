# Scoped Agent Authority Leases

**Implemented, optional, disabled by default.** These are authenticated host-side leases,
not portable bearer JWTs. Integration into deployed agent orchestrators is experimental.
OIDC and human approvals retain their existing roles.

An operator issues root authority for a subject and child session. Delegation binds
issuer identity/session, subject identity/session, canonical repository, environment,
effective policy revision, path prefixes, capability classes, issue/expiry timestamps,
random lease nonce, parent ID and depth. The payload is authenticated with HMAC-SHA256
in a protected host SQLite store. A lease ID alone grants no authority: validation
checks the host-authenticated subject and session.

## Configure and issue

```yaml
mode: enforce
authority:
  enabled: true
  environment: development
  path: /var/lib/jrx/controls/authority.sqlite3
  key_path: /var/lib/jrx/controls/host.key
  max_depth: 4
  max_ttl_seconds: 1800
  max_leases: 10000
  max_records: 100000
```

Use `jrx authority keygen` once if the host key does not already exist (intent can share
the same key). The containing database directory must be host-owned and mode 0700.

```bash
jrx authority issue orchestrator parent-session --config /etc/jrx/reflex.yaml \
  --repository /srv/repo --scope . --capability read --capability modify \
  --capability test --ttl-seconds 1800 --forbidden secrets --forbidden iam
jrx authority inspect LEASE_ID --config /etc/jrx/reflex.yaml
jrx authority tree LEASE_ID --config /etc/jrx/reflex.yaml
```

Root issuance/revocation requires OIDC `admin` authorization for the repository when
enterprise access is configured. Inspection requires `view`. Without OIDC, these are
trusted OS operator commands. A parent delegate supplies its authenticated identity
and original session through the trusted host:

```bash
# These values are injected by the host, not chosen by agent-authored shell code.
JRX_AGENT_ID=orchestrator JRX_SESSION_ID=parent-session \
  jrx authority issue backend-agent backend-session --config /etc/jrx/reflex.yaml \
  --repository /srv/repo --parent-id PARENT_LEASE_ID --scope src/backend \
  --scope tests/backend --capability read --capability modify --ttl-seconds 300
jrx authority revoke PARENT_LEASE_ID --config /etc/jrx/reflex.yaml
```

With OIDC, `JRX_ID_TOKEN` supplies the verified subject instead of `JRX_AGENT_ID`, and
delegation also requires existing `execute` authorization. The configured authority
environment is authoritative. The authority configuration does not grant OIDC roles.

## Attenuation

Each child must use the parent's subject/session as issuer, the same repository,
environment and policy revision, path prefixes contained by the parent's prefixes,
a subset of capabilities, an expiry no later than its parent, and depth within the
configured maximum. Forbidden capabilities accumulate. Review/admin/approval privilege
is outside the capability vocabulary and cannot be delegated. Unknown or forged parents,
cycles and invalid ancestor relationships reject. Every use checks the entire ancestor
chain; parent revocation or expiry invalidates descendants.

The host injects `JRX_AUTHORITY_LEASE_ID`, `JRX_SESSION_ID` and verified identity.
For CLI/hook actions it must supply a fresh unique `JRX_ACTION_NONCE` per action.
Repeated nonces reject atomically. MCP derives nonces from the lease/session/request ID,
so request IDs must be unique over a lease's lifetime, including gateway restarts.
Different MCP calls in one gateway do not reuse a launch-wide nonce.

Validation and nonce insertion run in one `BEGIN IMMEDIATE` transaction; concurrent
replays yield one successful reservation. Use records and signed use counts detect
individual nonce-record deletion. A nonce is a reservation, not a claim that execution
completed. Evaluation consumes it even if later policy or execution rejects; the host
must generate a new nonce for a new attempt.

## Integration and evidence

CLI, native shell hooks and MCP use the shared evaluator's blocking
`agent_control:AUTHORITY_DENIED` finding. Such denials cannot be overridden by a human
approval, `--yes` or advisory-mode CLI flag. CLI and MCP recheck revocation before
launch/forwarding. Normal OIDC scope, approval binding, session limits, MCP schemas and
semantic write-tool requirements still apply. The semantic broker receives no lease key
and remains an evaluator; the host gate validates leases locally.

`authority tree` gives issuance lineage; `inspect` includes revocation and use count.
Authenticated use records retain nonce, subject/session, redacted resource labels and
capabilities. Enabled normal decision audits also retain blocking control findings.
Storage is bounded; exhaustion fails closed. There is no background pruning or remote
revocation service. Provision fresh protected state and reissue leases under operator
control when retiring a store.

## Limits

This constrains preflight authority between sessions, not arbitrary subprocess I/O.
See [intent scope limitations](intent-lineage.md#supported-scope-checks). Arbitrary
programs cannot acquire narrow read authority merely by resembling a known executable.
Use OS sandboxing for actual runtime filesystem/network isolation.

The host must isolate policy, keys, SQLite state and identity/session metadata. An
unsandboxed child sharing the host account and key access is not separated by leases.
An agent able to choose `JRX_AGENT_ID`/`JRX_SESSION_ID` can impersonate host assertions
when OIDC is absent. OIDC token confidentiality is also required. Whole-store rollback
to a valid snapshot can resurrect old state unless an external checkpoint or protected
storage prevents it; HMAC alone does not establish freshness. Revocation after the
last preflight check can race execution. Wall-clock expiry requires a trustworthy host
clock. Remote attestation, portable signed leases and runtime descendant confinement
are future work.
