# Production audit V2 findings (before implementation)

Base: `38759d2d8b9de8cba5d3db18744cb2e203309619`. Reproductions:
`tests/test_production_audit_v2.py`; initial run: **11 failed in 2.88s**.
No destructive command was executed. Git commands were evaluated as data;
the only execution marker was a temporary file created by `touch`.

## Confirmed defects

### V2-001 — High — Degraded enforcement can be overridden

- Category / boundary: fail closed; CLI authorization → process execution.
- Affected: `cli.exec_action`.
- Reproduction: enforce-mode `exec --yes -- touch TEMP_MARKER`, no TypeSafe key.
- Expected: exit 2, no marker. Actual: exit 0, marker created.
- Impact: unavailable semantic enforcement can be bypassed by automatic confirmation.
- Root cause: degraded results enter the ordinary human override branch.
- Fix: refuse degraded execution in non-advisory modes before override handling.
- Regression: `test_enforce_unavailable_judge_cannot_be_overridden_with_yes`.

### V2-002 — High — Redaction failure loses degraded state

- Category / boundary: secret handling; redactor → execution decision.
- Affected: `evaluator.evaluate_context` result construction.
- Reproduction: inject Gitleaks failure, disable semantic evaluation, evaluate safe command.
- Expected: degraded, execution denied. Actual: REVIEW with `degraded=False`, permitted by enforce.
- Impact: a failed privacy dependency does not reliably prevent execution.
- Root cause: final flag considers only semantic degradation.
- Fix: carry redaction failure into the final degraded flag.
- Regression: `test_redaction_failure_remains_degraded_without_semantic`.

### V2-003 — Medium — Audit writer follows symlinks

- Category / boundary: filesystem-controlled log path → trusted persistent audit.
- Affected: `AuditLog._write_with_lock_atomic`, `write_human_override`.
- Reproduction: symlink audit path to a private empty temporary target; append.
- Expected: reject; target untouched. Actual: target receives audit entry.
- Impact: redirects evidence and writes into another file accessible to the host account.
- Root cause: path-based touch/open with no descriptor validation.
- Fix: O_NOFOLLOW, fstat regular-file/owner/permissions/link-count validation, fsync.
- Regression: `test_audit_append_rejects_symlink`.

### V2-004 — Medium — Ambiguous security YAML is accepted

- Category / boundary: policy-controlled inputs → effective configuration.
- Affected: configuration models and YAML loaders.
- Reproduction: duplicate `mode: enforce` followed by `mode: advisory`; typo in policy field.
- Expected: reject. Actual: last duplicate wins; unknown keys silently discarded.
- Impact: ambiguous operator configuration can weaken intended enforcement.
- Root cause: SafeLoader last-key behavior and `extra="ignore"`.
- Fix: bounded duplicate-rejecting YAML loader; forbid unknown configuration keys.
- Regressions: `test_config_rejects_duplicate_security_keys`, `test_config_rejects_misspelled_security_keys`.

### V2-005 — High — Valid Git options evade destructive checks

- Category / boundary: agent command → deterministic enforcement.
- Affected: destructive and Git-risk checks.
- Reproduction: `git -c color.ui=false reset --hard`, `git branch --force --delete old`,
  `git -c color.ui=false branch -D old`, `git -c color.ui=false push --force` through full evaluation.
- Expected: HOLD. Actual: ALLOW with semantic disabled.
- Impact: documented local protections depend on superficial option order.
- Root cause: regexes require adjacency and a fixed deletion flag order.
- Fix: extract Git subcommands after recognized global options; inspect flags independent of order.
- Regression: parameterized `test_destructive_git_variants_hold_in_full_pipeline`.

### V2-006 — Medium — Duplicate JSON members forwarded across MCP boundary

- Category / boundary: untrusted protocol JSON → upstream MCP parser.
- Affected: `mcp_gateway._load_message` / `_handle`.
- Reproduction: duplicate `method` keys (`tools/call`, then `ping`).
- Expected: reject before forwarding. Actual: raw ambiguous message forwarded.
- Impact: parser disagreement can evade the gateway with an upstream using first-key semantics.
  Exploitation depends on upstream behavior; no claim that all MCP servers are vulnerable.
- Root cause: gateway accepts duplicates then forwards original bytes.
- Fix: reject duplicate JSON object members, including nested objects.
- Regression: `test_mcp_duplicate_method_cannot_bypass_gateway`.

### V2-007 — Medium — Enabled audit failure permits unrecorded enforcement

- Category / boundary: persistent evidence dependency → enforce execution.
- Affected: `evaluator.evaluate_context` audit exception handling.
- Reproduction: inject audit I/O failure under enabled audit, enforce, safe action.
- Expected: block with dependency failure. Actual: ALLOW, warning only.
- Impact: configured recording can fail while actions continue without evidence.
- Root cause: logging exceptions never affect decision/degraded state.
- Fix: enabled audit failure holds non-advisory execution; advisory reports warning.
- Regression: `test_required_audit_failure_blocks_enforce`.

### V2-008 — High — Explicit nested shell deletion evades deterministic checks

- Boundary: agent shell syntax → checks. Affected: `checks.destructive`.
- Reproduction: newline-separated rm, find -exec rm, and command-substitution rm
  through `test_explicit_nested_destructive_commands_hold`. All four added cases failed
  before correction (including nested Git variant of V2-005).
- Expected HOLD; actual ALLOW with semantic disabled. Explicit deletion can proceed.
- Root cause: newlines treated as whitespace; find not treated as a wrapper; substitution
  parentheses not treated as boundaries. Fix bounded shell token recognition.
- Regression: `test_explicit_nested_destructive_commands_hold`.

## Design limitations and hardening opportunities

- Shell detection is heuristic, not a general shell interpreter or a kernel confinement boundary.
  Arbitrary scripts, aliases, dynamically constructed commands and executable replacement need sandboxing.
- Same-UID agents with host state/key/policy access can bypass host-side controls. Separate those assets.
- File contents can change after a preflight decision. Approval snapshots narrow but do not eliminate TOCTOU.
- Hash chains cannot prove absence of deleted suffixes without external checkpoints.
- Audit tail reads the entire file; rotation option is not implemented. Retention needs operator controls.
- OIDC subjects are case sensitive by specification; case folding identities would merge distinct principals.
- Reviewer roles are verified at grant time, not revalidated at consumption against an identity directory.
- Unpinned action tags/base images and broad dependency bounds reduce reproducibility.
- Cosign Python signer is explicitly unimplemented and fails closed; not a newly found bypass.

Historical findings are separately revalidated in the final report; this register does not inherit
the historical report's severity labels or assume its assertions are correct.

## V2-009 — Medium — Local credential files enter Docker build context

Dockerfile uses COPY . ., while the current .dockerignore omits .env and .aws.
The original checkout has a local .env (its contents were never read). These files
can enter builder layers or exported build caches; no published real secret leakage
is asserted. Test `test_docker_context_excludes_local_credentials` failed before
adding excludes. Fix excludes .env*, .aws, host agent configuration directories and
private .key files, retaining .env.example. Disposable Docker COPY reproduction
uses synthetic credentials only.

## New-feature review corrections

Before final verification, three independent-review reproductions caught CLI mode
overrides disabling intent enforcement, GNU wc --files0-from scope ambiguity and
traversing executable paths classified by basename. All have failing-before-fix
regressions in test_intent_authority.py. These were development defects in the new
features, not present at the base SHA. Additional new-feature tests caught repeated
MCP nonce reuse and raw secret-looking filename persistence; per-request nonces
and resource redaction correct them.
