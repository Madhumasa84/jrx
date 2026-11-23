# Security and threat model

JEV Reflex runs on an execution boundary. The design goal is probabilistic
semantic judgment wrapped in deterministic local policy, not a claim that JEV
or a coding agent is deterministic or that a model can make agents safe.

## Assets

- TypeSafe API keys and other credentials in command text, diffs, environment-derived output, or retrieved content.
- Repository source, paths, diffs, and persistent state.
- The integrity of the host agent's permission and execution flow.
- User intent and the configured hard/review rules.

## Trust boundaries

1. The user and host agent provide the task and proposed action.
2. Repository files, diffs, tests, transcripts, and retrieved content are treated as untrusted data.
3. `redaction.py` and `context.py` deterministically bound and sanitize state before the TypeSafe gateway.
4. TypeSafe returns advisory structured judgments; repeated responses can vary.
5. Deterministic checks identify obvious local hazards without JEV.
6. `policy.py` is trusted local code and decides `ALLOW`, `REVIEW`, or `HOLD` from fixed configuration, structured findings, and normalized numbers.
7. The host agent or wrapper decides whether to execute after the policy result.

Configuration is loaded separately from evaluated state. Text inside a command, diff, or retrieved document cannot change `hold_on`, `review_on`, thresholds, or mode.

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Secret sent to TypeSafe | Redact before API calls, logs, hook output, and calibration; common credential flags, URL query keys, and secret-looking object fields are covered; only `TYPESAFE_API_KEY` is read for authentication. |
| Prompt injection in retrieved content | Supply it in an explicit untrusted field; every question says not to follow state instructions; policy is local and deterministic. |
| Destructive command | Obvious forms, including recursive `rm` through common wrappers and shell evaluation, produce a deterministic hard finding; semantic destructive signals also hold at the configured threshold. Native hooks or the enforce wrapper stop the resulting `HOLD`. |
| API/network failure | Advisory mode warns; review/enforce produce degraded `REVIEW`; non-advisory `exec` does not run degraded results. Confirmed fail-closed behavior for: TypeSafe API timeout, 5xx errors, malformed/unparseable JSON, missing signal keys, SDK missing, missing API key, network unreachable (DNS failure), revoked API key (401). Broker failures (socket doesn't exist, connection refused, timeout/hang) also fail closed. All modes surface degradation to user/agent; enforce and review modes never return ALLOW on degraded evaluations. |
| Shell metacharacter injection | `exec` uses a preserved argv list and `shell=False`; `--command` is parsed once with `shlex`. |
| Malformed model response | Missing/wrong/out-of-range answers are rejected; no partial model output becomes policy approval. Non-advisory modes fail closed to `REVIEW`. |
| Wrong repository or symlink path | Working directories are canonicalized before Git inspection and execution; repository context is bounded. |
| Calibration data leakage | Events contain only timestamp, anonymous ID, probabilities, policy decision, risk choice, and feedback. |
| Hook bypass | Documented as a limitation; retain the host sandbox/permission system and use wrappers for surfaces without supported hooks. |

The wrapper canonicalizes the working directory for context collection and again uses that
canonical path for child execution. This reduces path ambiguity, but no user-space pre-check can
eliminate races if another process changes files or links between evaluation and execution.

## Redaction limits

Redaction uses a hybrid approach combining regex patterns and gitleaks for secret detection:

- **Regex patterns**: Detect common API keys, bearer headers, GitHub tokens, AWS access keys, private-key blocks, password/token/secret assignments, credential flags, and secret-looking object fields. This is heuristic and fast, but not comprehensive.
- **Gitleaks integration**: When available, gitleaks provides additional heuristic secret detection using its extensive rule set covering many more patterns than the regex approach.

**Gitleaks is optional but recommended:**

- If gitleaks is installed on PATH, JEV Reflex automatically uses it for enhanced secret detection
- If gitleaks is not available, JEV Reflex falls back to regex-only redaction with a one-time warning
- On gitleaks failure (timeout, error, or crash), JEV Reflex fails toward MORE redaction: the entire context is treated as potentially containing secrets and marks evaluation degraded and forces a REVIEW decision; non-advisory execution denies degraded results
- To install gitleaks: https://github.com/gitleaks/gitleaks#installation

**The hybrid approach:**

- Regex patterns run in all cases and catch project-specific patterns that gitleaks may miss
- Gitleaks extends coverage of standard secret formats when available
- Both redaction layers are applied; their findings are unioned, not replaced
- This ensures no degradation in redaction coverage when gitleaks is added

**Configuration:**

No configuration is required. Gitleaks is automatically detected and used if available. To disable gitleaks, simply remove it from PATH or set an environment variable to control detection (future enhancement).

Do not use JEV Reflex as a guarantee that arbitrary high-entropy secrets or sensitive business data will be removed. Avoid putting secrets in command arguments in the first place.

`TYPESAFE_API_KEY` is passed to the official SDK only as the authentication credential. Its value is never placed in the model-facing state, result, logs, or events.

## Policy and stability limits

Probabilities are not proofs. Thresholds can be overridden, JEV can be wrong,
and a low score does not make an action safe. Identical policy inputs produce
identical policy outputs, but identical JEV requests may produce different
inputs. Stability reports measure observed final-decision consistency; they do
not establish model determinism or security. Hard rules are the deterministic
first layer, but users still need ordinary code review, tests, least
privilege, sandboxing, and backups.

Native hook coverage follows the host agent's current interfaces. A specialized or hosted tool may bypass a local hook. Enforce mode should therefore be paired with the host's own permission and sandbox controls.

## Reporting

If you find a secret-handling bug, do not include the secret in a public issue. Rotate the credential, describe the pattern generically, and report the problem through the project's private security channel if one is configured.

## Audit log

JEV Reflex provides an optional append-only, tamper-evident audit log for policy decisions. The audit log is a hash-chained JSONL file that records each policy decision with cryptographic integrity guarantees.

### Guarantees

- **Tamper-evidence**: Each entry is cryptographically linked to the previous entry via SHA-256 hashing. Changes to protected fields break the hash chain. Canonical JSON hashing does not authenticate whitespace. Removing a valid trailing segment leaves a valid chain unless an externally trusted checkpoint fixes its expected tip.
- **Append-only writes**: The log uses O_APPEND mode and file locking to ensure entries are only appended, never modified in place.
- **Sequence integrity**: Entries are numbered sequentially; gaps or reordering are detected during verification.
- **Secret redaction**: All action summaries are redacted using the same deterministic patterns as the rest of JEV Reflex before being written to the log.
- **File permissions**: Appends require an owner-only regular file and reject symlinks or additional hard links; new files use 0600 permissions.
- **Concurrent safety**: File locking prevents corruption when multiple processes write to the same log file.

### What the audit log does NOT guarantee

- **Protection against attackers with write access**: An attacker who can write to the log file and rewrite the entire chain from genesis can successfully tamper with the log. This is a known limitation that will be addressed in a future update by adding cryptographic signatures.
- **Protection against log deletion**: An attacker with filesystem access can delete the entire log file. Regular backup and monitoring of the audit log directory is recommended.
- **Real-time monitoring**: The audit log is a passive record; it does not provide real-time alerts or monitoring capabilities.
- **Perfect secret detection**: Redaction is heuristic and may miss novel secret patterns. The same limitations that apply to the rest of JEV Reflex's redaction system apply to the audit log.

### Configuration

The audit log is configured in `reflex.yaml` under the `audit` block:

```yaml
audit:
  enabled: false
  path: ~/.jev-reflex/audit.log
  rotate_mb: 100
```

The audit log is written when either `audit.enabled` is true OR `privacy.store_requests` is true. These are separate controls; audit logging does not depend on `store_requests`.

### Usage

Verify the integrity of the audit log:

```bash
jrx audit verify [--path /path/to/audit.log]
```

View recent entries:

```bash
jrx audit tail [-n 10] [--json] [--path /path/to/audit.log]
```

### Known limitations

1. **Trusted checkpoints**: Optional Ed25519 or Cosign signatures authenticate audit entries. Detecting deletion of an entire log or a valid trailing segment still requires an independently retained checkpoint or copy.
2. **No automatic rotation**: While a `rotate_mb` configuration option exists, automatic log rotation is not yet implemented. Administrators should monitor log size and rotate manually as needed.
3. **No compression**: Logs are stored as plain text JSONL. Compression or archival strategies are left to the administrator.

## Fail-closed semantic evaluation

JEV Reflex is designed to fail closed when semantic evaluation (TypeSafe API or broker) is unavailable or returns malformed data. This ensures that degraded evaluations never silently downgrade to ALLOW in enforce or review mode.

### Confirmed failure modes

The following failure modes have been tested and confirmed to fail closed:

**TypeSafe API failures:**
- API timeout
- 5xx server errors
- Malformed/unparseable JSON response
- Missing expected signal keys in response
- Missing answers field entirely
- Invalid answer types
- Invalid risk choice values
- SDK missing/not installed
- Missing API key
- Network unreachable (DNS failure)
- Revoked API key (401 unauthorized)

**Broker failures:**
- Unix socket doesn't exist
- Socket exists but connection refused
- Socket accepts connection then hangs (no response within timeout)

### Confirmed behavior

For each failure mode, the following behavior is verified:

1. **Degradation logging**: The failure is logged via the audit module with a distinct degradation reason code
2. **Advisory mode**: Surfaces the degradation to the user/agent via warnings while still returning a decision
3. **Review mode**: Never returns ALLOW purely on hard-rule-pass-with-missing-semantic-signal; returns REVIEW or HOLD
4. **Enforce mode**: Never returns ALLOW on degraded evaluations; returns REVIEW or HOLD

### Testing

Run the fail-closed self-test to verify behavior:

```bash
jrx check --fail-closed-check
```

This command runs a comprehensive test matrix against mock failure modes and reports pass/fail status for each mode (advisory, review, enforce). The self-test is designed for post-deployment smoke testing.

### Known limitations

- Broker responses are bound to request IDs and checked for finite timestamps and bounded clock skew.
  Protect host time synchronization and broker credentials separately.
- The fail-closed behavior applies to semantic evaluation failures; hard rules (deterministic checks) continue to function independently

## Central policy mode

JEV Reflex supports fetching policy from a central source (git repository, HTTPS endpoint, or local file) to scale policy management across multiple teams. This is configured in `bootstrap.yaml`:

```yaml
policy_source:
  type: git  # or "https" or "local"
  uri: https://github.com/org/policy-repo.git
  ref: main  # Git branch/ref (required for git type)
  poll_interval_seconds: 300  # Default 5 minutes
  pinned_signature_pubkey: |
    -----BEGIN PUBLIC KEY-----
    MCowBQYDK2VwAyEA...
    -----END PUBLIC KEY-----
```

**Central policy requirements:**

- Remote policies MUST be signed (signature verification is mandatory)
- The `pinned_signature_pubkey` is used to verify the signature
- On signature verification failure, the old cached policy remains active and an event is logged
- The broker refuses to start if it cannot fetch a verified policy and has no cached version

**Local policy overrides:**

- Local `reflex.yaml` becomes an override layer that can only TIGHTEN policy, never loosen it
- Local can add new `hold_on` or `review_on` entries
- Local cannot remove entries from central policy
- Local cannot raise thresholds above central's thresholds (lower = stricter)
- Local can lower thresholds (making them stricter)
- Local mode merging uses the actual execution strictness: advisory < enforce < review; review requires human handling of REVIEW decisions
- Attempted loosening is logged and ignored

**The merge invariant is enforced by code, not just documentation:**

The `PolicyMerger.merge_policies()` function explicitly enforces the tighten-only invariant with tests proving the behavior.

**Policy reload:**

- Broker fetches remote policy on startup and at `poll_interval_seconds` intervals
- When policy changes, it is hot-reloaded and logged to the audit module with the new `policy_version_hash`
- Signature verification happens on every fetch
- On fetch failure with no cached policy, the broker refuses to issue ALLOW decisions (fail-closed)

**Status checking:**

Use `jrx policy status` to see:
- Active policy source type and URI
- Last fetch time
- Current policy version hash
- Whether local overrides are in effect

## Cryptographic signing

### Key management

JEV Reflex follows a bring-your-own-key (BYOK) model, consistent with the existing `TYPESAFE_API_KEY` approach:

- **Key generation**: Keys are generated by the operator using `jrx policy sign` or external tools
- **Key storage**: JEV Reflex does not manage key rotation or storage. Keys must be stored securely using your organization's key management system (e.g., KMS, HSM, or secure file storage)
- **Key distribution**: Public keys must be distributed to systems that need to verify signatures (bootstrap config for policy verification, audit verification for decision signatures)
- **Key rotation**: Operators must manage key rotation manually by generating new keys, re-signing policy files, and updating public key references

### Policy file signing

Policy files can be cryptographically signed to prevent unauthorized modifications to thresholds, rules, and mode settings.

**Setup:**

1. Generate a keypair:
   ```bash
   jrx policy sign reflex.yaml
   ```
   This outputs a public key and private key in PEM format. Save the private key securely.

2. Save the public key to a secure location (e.g., `/etc/jrx/public_key.pem`).

3. Create a bootstrap configuration:
   ```yaml
   # /etc/jrx/bootstrap.yaml or ~/.jev-reflex/bootstrap.yaml
   require_signature: true
   public_key_path: /etc/jrx/public_key.pem
   signer_type: ed25519
   ```

4. Sign the policy file:
   ```bash
   jrx policy sign reflex.yaml --key /path/to/private_key.pem
   ```
   This creates `reflex.yaml.sig`.

**Behavior:**

- When `require_signature: true` is set in the bootstrap config, JEV Reflex refuses to load `reflex.yaml` unless a valid signature exists
- Missing or invalid signatures cause the engine to fail closed (refuse to start) rather than falling back to defaults
- This prevents attackers with filesystem write access from silently modifying policy settings

**Signer types:**

- `ed25519`: Local Ed25519 keypair using the cryptography library (recommended, fully implemented)
- `cosign`: Local detached key signatures using the Cosign CLI. Install Cosign
  2.6 or 3.x, generate a local key with `cosign generate-key-pair`, and supply
  its password through `COSIGN_PASSWORD`. JRX signs private policy/audit bytes
  without uploading them to Rekor and verifies against the pinned public key
  offline. This adapter uses raw detached signatures, rather than Sigstore bundles.

  ```bash
  jrx policy sign reflex.yaml --key cosign.key --signer-type cosign
  jrx policy verify reflex.yaml --public-key cosign.pub --signer-type cosign
  ```

  Set `signer_type: cosign` in the protected bootstrap configuration when
  requiring these policy signatures. Signature formats are specific to the
  selected signer. See [Cosign blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
  for the upstream CLI protocol.

### Decision signing

Audit log entries can be cryptographically signed to provide non-repudiation for policy decisions.

**Setup:**

Configure decision signing in `reflex.yaml`:
```yaml
signing:
  private_key_path: /path/to/private_key.pem
  signer_type: ed25519
```

**Behavior:**

- When signing is configured, each audit log entry includes a `decision_signature` field
- The signature covers the entry hash, ensuring that any modification to the entry invalidates the signature
- Signing is optional to configure. Once configured, signing failure refuses the audit
  append; enabled audit failure blocks non-advisory execution.

**Verification:**

Verify audit log signatures:
```bash
jrx audit verify --public-key /path/to/public_key.pem
```

This checks both hash chain integrity and decision signatures, reporting any missing or invalid signatures separately.

### Limitations

- **Cosign scope**: The local adapter requires the Cosign executable and a local
  key. It does not support keyless identities, KMS references, transparency log
  attestations, or bundle verification. A missing binary or a 30-second command
  timeout causes signing/verification to fail.
- **Key rotation**: Manual key rotation is required; there is no automated key rotation mechanism
- **Audit log performance**: Signing adds a small performance overhead to audit log writes
- **Bootstrap config protection**: The bootstrap config file itself is not signed; protect it with filesystem permissions (mode 0600, owned by root or a dedicated user)

## Production audit hardening and optional controls

Security YAML rejects duplicate/unknown keys, aliases and excessive size/depth instead
of silently selecting a value. Existing configurations with ignored keys must be corrected.
Audit append rejects symlinks and unsafe file ownership/permissions; enabled audit write
failure produces a degraded HOLD in non-advisory modes. Ordinary semantic degradation
cannot be bypassed with `exec --yes` in non-advisory modes.

Set `audit.enabled: true` with `audit.fail_closed: true` to require successful
decision and override records before execution. `policy.strict_review` blocks
REVIEW until JRX verifies an action-bound approval through enterprise access.
The production preset enables both controls.

The optional [intent guard](intent-lineage.md) and [authority leases](authority-delegation.md)
use authenticated host state and atomic transactions. Their denials remain binding
under advisory mode, ordinary approvals and `--yes`. Both require host protection of
keys, state, configuration and identity/session assertions. They are implemented but
autonomous host deployment remains experimental; they do not establish runtime
confinement, perfect intent understanding or freshness against whole-store rollback.

## Local control-file protection and session evidence

Tier-0 recognizes explicit writes to agent instructions, hook settings, Git hooks,
policy inputs, and user shell startup files. It inspects shell write targets,
supported file-editing tools, and proposed patches. Read-only inspection of
control files is allowed. An operator can add an exact path to
`local_checks.protected_path_allowlist` in trusted policy. Relative exceptions
are scoped to the repository root and other local checks still apply.

The local evaluator also checks executable shell constructs, executable Git
settings, and untrusted install sources. An operator can replace
`local_checks.trusted_package_hosts` with exact approved HTTPS hostnames.
Package-host exceptions apply to package sources. Piping a remote download to
an interpreter still triggers a HOLD.

These session controls are independent of the optional session call limits.

```yaml
session:
  track_secret_taint: true
  pin_protected_files: true
```

Set a distinct `JRX_SESSION_ID` in the trusted host environment for each session.
Give the same environment and trusted policy to PreToolUse and PostToolUse.
The Claude Code and Codex hook commands accept both event types, and their
settings helpers include PostToolUse. A custom harness can pipe a compatible
JSON event to `jrx post-tool-use --config /path/to/trusted-policy.yaml`.
Without a host session ID, the two optional session checks are inactive.

- **Secret taint** records salted SHA-256 fingerprints of credential values in
  tool output and paths from recognized credential-file reads. The database
  stores no raw values, paths, or tool output. In a tainted session, recognized
  network actions and opaque shell execution block. A subsequent action also
  blocks if a literal value matches a saved credential fingerprint, and that
  action is withheld from semantic evaluation and public output. The store
  keeps up to 256 fingerprints per session and fails closed on overflow.
- **Integrity pinning** records SHA-256 file hashes on the first evaluation for
  each session and repository. Later additions, removals, or content changes
  in the protected set cause HOLD. Keep the host policy and session database
  under host control, outside the agent's writable workspace. Signed policy
  loading protects the settings that enable these checks. Operators should
  establish a new session when they intentionally change pinned files.

Control-file and taint HOLDs also block through advisory hooks and execution.
These checks use bounded inspection of supported commands, payloads, and
workspaces. Use OS-level egress enforcement when the host must restrict what
arbitrary programs can send. [Execution sandbox](execution-sandbox.md)

## Controlled Linux Agent Runner

Run the agent as an untrusted process in a separate container or OS account.
Keep the Host Broker and a trusted runner outside that boundary. The runner
accepts structured tool requests, supplies the checkout, policy, deployment
environment, OIDC identity and session ID from host-controlled state, and routes
commands through `jrx exec`. Feed tool results through `jrx post-tool-use`
with the same policy and host session ID before accepting the next request.

Keep deployment credentials, `TYPESAFE_API_KEY`, broker and OIDC credentials,
audit and approval stores, and the policy outside every writable agent mount.
Give the agent and command container only the workspace access they need. Keep
host controls read-only, withhold the Docker socket and broker socket from the
agent, and deny direct access to deployment endpoints. The Host Broker returns
semantic judgments to the runner. The runner launches approved commands in
short-lived Docker containers with a read-only root, no inherited credentials,
and no network by default. If an agent skips its hooks and runs a command
directly, OS confinement still keeps host credentials and deployment capabilities
out of reach.

Generate the host policy with `jrx init --preset production`. Supply real OIDC
issuer and JWKS URLs, role mappings for the canonical host checkout, and a
preloaded worker image pinned by SHA-256 digest. Use
`jrx policy lint --profile production --config PATH --json` to validate enforce
mode, strict REVIEW, required audit writes, bounded sessions, file drift and
PostToolUse taint tracking, protected-file rules, OIDC and two independent
reviewers, Docker and broker configuration, and required semantic evaluation
without non-loopback cleartext HTTP. Lint checks policy configuration offline.
`jrx doctor --config PATH` also reports the production controls.

REVIEW requires a single-use approval ID tied to the requester, command,
checkout, execution environment, Git state, and policy. The runner records
approval consumption before dispatch. Semantic degradation and audit write
failure stop execution regardless of approval. HOLD overrides require an
explicitly configured and documented exception, and host guard denials remain
binding. After credential exposure, production blocks further shell and tool
execution in the tainted session, including indirect invocations. Start a new
host-assigned session after resolving the exposure.
