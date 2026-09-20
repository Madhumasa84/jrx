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
- **Gitleaks integration**: When available, gitleaks provides comprehensive secret detection using its extensive rule set covering many more patterns than the regex approach.

**Gitleaks is optional but recommended:**

- If gitleaks is installed on PATH, JEV Reflex automatically uses it for enhanced secret detection
- If gitleaks is not available, JEV Reflex falls back to regex-only redaction with a one-time warning
- On gitleaks failure (timeout, error, or crash), JEV Reflex fails toward MORE redaction: the entire context is treated as potentially containing secrets and forces a REVIEW decision
- To install gitleaks: https://github.com/gitleaks/gitleaks#installation

**The hybrid approach:**

- Regex patterns run in all cases and catch project-specific patterns that gitleaks may miss
- Gitleaks provides comprehensive coverage of standard secret formats when available
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

- **Tamper-evidence**: Each entry is cryptographically linked to the previous entry via SHA-256 hashing. Any modification to a single byte in the log will break the hash chain and be detected by `jrx audit verify`.
- **Append-only writes**: The log uses O_APPEND mode and file locking to ensure entries are only appended, never modified in place.
- **Sequence integrity**: Entries are numbered sequentially; gaps or reordering are detected during verification.
- **Secret redaction**: All action summaries are redacted using the same deterministic patterns as the rest of JEV Reflex before being written to the log.
- **File permissions**: Log files are created with 0600 permissions (read/write only by owner) when possible.
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

1. **No cryptographic signing**: The current implementation uses hash chaining but does not include cryptographic signatures. This will be added in a future update to protect against attackers who can rewrite the entire chain.
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

- Clock skew detection (broker response timestamp validation) is not yet implemented and will be added in Prompt 1.3 with cryptographic signing
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
- Local can tighten mode (advisory → review → enforce), but cannot loosen it
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
- `cosign`: Cosign integration (stub for future implementation)

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
- Signatures are optional; audit logging continues even if signing fails

**Verification:**

Verify audit log signatures:
```bash
jrx audit verify --public-key /path/to/public_key.pem
```

This checks both hash chain integrity and decision signatures, reporting any missing or invalid signatures separately.

### Limitations

- **Cosign signer**: The CosignSigner stub is not yet fully implemented; use Ed25519Signer for now
- **Key rotation**: Manual key rotation is required; there is no automated key rotation mechanism
- **Audit log performance**: Signing adds a small performance overhead to audit log writes
- **Bootstrap config protection**: The bootstrap config file itself is not signed; protect it with filesystem permissions (mode 0600, owned by root or a dedicated user)
