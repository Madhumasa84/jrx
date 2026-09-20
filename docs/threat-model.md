# Threat Model for JEV Reflex (jrx)

This document provides an explicit statement of what JEV Reflex protects against and what it explicitly does NOT protect against. For detailed security architecture and implementation details, see [docs/security.md](security.md) and the [Known Limitations](../README.md#known-limitations) section in the README.

## What JEV Reflex Protects Against

JEV Reflex is designed to protect against specific classes of threats in autonomous coding agent workflows:

### 1. Destructive Local Commands
- **Threat**: Autonomous agents executing destructive commands like `rm -rf`, disk wipes, or other destructive operations before human review.
- **Protection**: Deterministic hard rules identify obvious destructive patterns (recursive deletions, destructive commands through common wrappers). Semantic evaluation via TypeSafe JEV provides probabilistic assessment of destructive intent. Policy engine can block (HOLD) or require review (REVIEW) based on configured thresholds.
- **See**: [docs/security.md](security.md#threats-and-mitigations) - "Destructive command" row

### 2. Credential Leakage in Agent-Generated Diffs
- **Threat**: Agent-generated code changes or diffs containing API keys, tokens, passwords, or other credentials being committed to repositories or exposed in logs.
- **Protection**: Hybrid redaction system (regex patterns + optional gitleaks integration) scrubs common credential patterns before transmission to TypeSafe, logging, hook output, and calibration. Only `TYPESAFE_API_KEY` is read for authentication and never placed in model-facing state.
- **See**: [docs/security.md](security.md#redaction-limits)

### 3. Unreviewed High-Risk Actions
- **Threat**: Agents performing security-sensitive, persistence-sensitive, or backwards-compatibility-impacting actions without human oversight.
- **Protection**: Configurable thresholds and rule sets can require explicit review for actions tagged as `security_sensitive`, `persistence_sensitive`, `backwards_compatibility`, or `human_review`. Execution modes (`review`, `enforce`) can halt execution until approval is obtained.
- **See**: [README.md](../README.md#key-concepts--policy-decisions)

### 4. Prompt Injection in Retrieved Content
- **Threat**: Retrieved content (file reads, web fetches) containing prompt injection attempts that could subvert the semantic evaluator.
- **Protection**: Retrieved content is supplied in an explicit untrusted field to TypeSafe JEV. Every evaluation request explicitly instructs the evaluator not to follow state-changing instructions. Policy evaluation is local and deterministic, never directly controlled by model output.
- **See**: [docs/security.md](security.md#threats-and-mitigations) - "Prompt injection in retrieved content" row

### 5. Repository Boundary Escapes
- **Threat**: Agents attempting to modify files outside the intended repository boundary or using symlink attacks to escape containment.
- **Protection**: Working directories are canonicalized before Git inspection and execution. Repository context is bounded. Hard rules detect `wrong_repo` and `wrong_repo_semantic` conditions.
- **See**: [docs/security.md](security.md#threats-and-mitigations) - "Wrong repository or symlink path" row

### 6. Semantic Evaluation Failures (Fail-Closed Behavior)
- **Threat**: Degraded or unavailable semantic evaluation silently downgrading security posture.
- **Protection**: Confirmed fail-closed behavior for TypeSafe API failures (timeout, 5xx errors, malformed JSON, missing keys, network issues, revoked API key) and broker failures (socket issues, connection refused, timeouts). Advisory mode surfaces warnings; review/enforce modes never return ALLOW on degraded evaluations.
- **See**: [docs/security.md](security.md#fail-closed-semantic-evaluation)

### 7. Unauthorized Policy Modifications
- **Threat**: Attackers with filesystem write access silently modifying policy settings (thresholds, rules, mode) to weaken security controls.
- **Protection**: Optional cryptographic signing of policy files (ed25519). When `require_signature: true` is set in bootstrap config, JEV Reflex refuses to load unsigned or invalidly signed policy files. Central policy mode with signature verification prevents unauthorized remote policy changes.
- **See**: [docs/security.md](security.md#cryptographic-signing)

### 8. Audit Log Tampering
- **Threat**: Unauthorized modification of audit log entries to hide malicious actions or falsify decision history.
- **Protection**: Append-only, tamper-evident audit log with SHA-256 hash chaining. Each entry is cryptographically linked to the previous entry. Optional decision signing provides non-repudiation. File permissions (0600) and file locking protect against concurrent corruption.
- **See**: [docs/security.md](security.md#audit-log)

## What JEV Reflex Does NOT Protect Against

JEV Reflex has explicit limitations and does not claim to protect against the following threats:

### 1. Compromised Host with Root Access
- **Limitation**: If an attacker has root access to the host system, they can bypass all JEV Reflex protections by:
  - Modifying the JEV Reflex binary or Python installation
  - Changing filesystem permissions to circumvent security checks
  - Modifying or deleting the bootstrap configuration
  - Intercepting or modifying network traffic to TypeSafe
  - Directly modifying the audit log file (hash chaining can be rewritten from genesis)
- **Mitigation**: JEV Reflex assumes a trusted host. Protect the host with standard security practices: least privilege, regular updates, monitoring, and access controls.
- **See**: [docs/security.md](security.md#audit-log) - "What the audit log does NOT guarantee"

### 2. Attacker Controlling TypeSafe API Response AND Local Hard-Rule Bypass
- **Limitation**: JEV Reflex assumes the TypeSafe API acts as an independent semantic evaluator. If an attacker can both:
  1. Control or compromise the TypeSafe API response (return malicious semantic signals), AND
  2. Bypass or disable local hard rules (deterministic checks)
  Then they could potentially trick the policy engine into approving malicious actions.
- **Mitigation**: Local hard rules are designed to be difficult to bypass (they run in the same process as the policy engine). TypeSafe operates independently with its own security controls. The defense-in-depth approach requires compromising both layers simultaneously.
- **See**: [README.md](../README.md#known-limitations) - "Observation vs Determinism Proof"

### 3. Supply-Chain Compromise Prior to Signing
- **Limitation**: If the JEV Reflex source code, dependencies, or build artifacts are compromised before the release signing process, the signed artifact will still be malicious.
- **Mitigation**: The release workflow added in Phase 1 includes Docker image signing with cosign (keyless OIDC via GitHub Actions) and SBOM generation. However, this protects against post-signing tampering, not pre-signing compromise. Use trusted build environments, signed commits, and dependency verification (e.g., pip-audit, sigstore-python).
- **See**: [README.md](../README.md#known-limitations) - "Supply-chain compromise" (implied)

### 4. Novel Secret Patterns
- **Limitation**: The redaction system uses regex patterns for common credential formats and optional gitleaks integration. Novel or custom secret patterns not covered by these rules may not be detected and redacted.
- **Mitigation**: Do not rely on JEV Reflex as a substitute for proper secret management. Avoid putting secrets in command arguments, diffs, or code in the first place. Use dedicated secret management systems.
- **See**: [docs/security.md](security.md#redaction-limits)

### 5. Time-of-Check to Time-of-Use (TOCTOU) Race Conditions
- **Limitation**: User-space pre-execution checks cannot eliminate all concurrent filesystem race conditions. If another process modifies files or symlinks between evaluation and execution, security guarantees may be compromised.
- **Mitigation**: JEV Reflex canonicalizes working directories and uses bounded context, but cannot eliminate all TOCTOU issues. Use additional safeguards like filesystem permissions, mandatory access controls, and least privilege.
- **See**: [README.md](../README.md#known-limitations) - "Time-of-Check to Time-of-Use (TOCTOU)"

### 6. Hook Bypass
- **Limitation**: Commands executed outside the configured agent hook or wrapper bypass local inspection entirely.
- **Mitigation**: Documented as a limitation. Retain the host sandbox/permission system and use wrappers for surfaces without supported hooks. Enforce mode should be paired with host permission controls.
- **See**: [docs/security.md](security.md#threats-and-mitigations) - "Hook bypass" row

### 7. Model Non-Determinism
- **Limitation**: JEV Reflex does not make coding agents or semantic models deterministic. Probabilities are not proofs. Identical JEV requests may produce different semantic signals across runs.
- **Mitigation**: JEV Reflex wraps probabilistic judgment in deterministic policy. Stability metrics measure observed consistency but do not establish model determinism. Continue to apply normal code review, testing, and monitoring practices.
- **See**: [README.md](../README.md#known-limitations) - "Observation vs Determinism Proof"

### 8. Bootstrap Configuration Protection
- **Limitation**: The bootstrap configuration file itself is not cryptographically signed. An attacker with filesystem write access could modify bootstrap settings (e.g., disable signature verification).
- **Mitigation**: Protect bootstrap config files with filesystem permissions (mode 0600, owned by root or a dedicated user). Use filesystem-level immutable attributes where available.
- **See**: [docs/security.md](security.md#cryptographic-signing) - "Limitations"

### 9. Perfect Secret Detection
- **Limitation**: Redaction is heuristic and may miss novel secret patterns or high-entropy data that resembles secrets.
- **Mitigation**: This is a known limitation of all heuristic secret detection systems. Use proper secret management practices, avoid embedding secrets in code/commands, and rely on dedicated secret scanning tools in CI/CD pipelines.
- **See**: [docs/security.md](security.md#audit-log) - "What the audit log does NOT guarantee"

## Defense in Depth

JEV Reflex implements a defense-in-depth architecture:

1. **Deterministic Hard Rules**: Instant local checks for obvious threats (destructive commands, secret patterns, repo escapes)
2. **Semantic Evaluation**: Bounded probabilistic judgment via TypeSafe JEV for subtle context-aware risks
3. **Deterministic Policy Engine**: Pure function over findings + signals, producing ALLOW/REVIEW/HOLD decisions
4. **Execution Control**: Hooks and wrappers that enforce policy decisions at the execution boundary
5. **Audit Trail**: Tamper-evident logging with optional cryptographic signing
6. **Supply Chain Security**: Signed releases with SBOM generation

Each layer is designed to fail independently and safely. Compromising any single layer should not be sufficient to bypass security controls.

## Assumptions

JEV Reflex makes the following security assumptions:

1. **Trusted Host**: The host system running JEV Reflex is not compromised with root access
2. **Independent Semantic Evaluator**: TypeSafe API operates independently and is not controlled by the same attacker attempting to bypass local rules
3. **Controlled Build Pipeline**: The release build environment is trusted and not compromised before signing
4. **Filesystem Permissions**: Users protect configuration files with appropriate permissions (mode 0600 for sensitive files)
5. **Network Security**: Network connections to TypeSafe are not intercepted or modified in transit (TLS is used)
6. **Agent Sandbox**: The agent itself runs within some form of sandbox or permission boundary (even if minimal)

## References

- [Security Documentation](security.md) - Detailed security architecture and implementation
- [README: Known Limitations](../README.md#known-limitations) - General limitations and caveats
- [Architecture Documentation](architecture.md) - System architecture and design principles
- [Broker Documentation](broker.md) - Host-side broker security considerations
