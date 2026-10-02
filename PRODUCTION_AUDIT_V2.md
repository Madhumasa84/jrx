# JRX Production Audit V2

The [complete verification follow-up](COMPLETE_TEST_REPORT.md) records subsequent
Python 3.11/3.12 installed-package tests, the V2-010 state-validation fix and retained
intermittent test failures. Its tested implementation is `3e676b2`; the final serial
source suite passed **699 tests**, with one paid live test skipped. The initial audit
results below retain their original chronology.

## 1. Executive Summary

The audit reproduced **nine current defects**, repaired them with regression tests,
and implemented two optional controls: Execution Lineage & Intent Drift Guard and
Scoped Agent Authority Leases. The original checkout and its five pre-existing
modified files were preserved. Changes are on `hardening/production-audit-v2` in
`/tmp/jrx-production-audit-v2`. The branch was subsequently pushed at the user's request;
no main merge or release publication occurred.

Baseline: **628 passed, 1 skipped**. Post-change verification: **696 passed, 1 skipped**.
The only skipped test requires paid TypeSafe access, which was not authorized.
There are 68 additional test cases. This is evidence of improved behavior under the
examined conditions, **not a blanket production-readiness certification**.

Both new controls are implemented, disabled by default and tested locally. Deployment
inside real autonomous hosts remains experimental. Protect host keys/configuration,
authenticated identities, session assertions and execution routing before enabling them.

## 2. Repository / Environment

| Item | Value |
| --- | --- |
| Repository | Madhumasa84/jrx, JEV Reflex 0.1.0 |
| Base SHA | `38759d2d8b9de8cba5d3db18744cb2e203309619` |
| Original branch | `feat/unified-agent-workspace` |
| Implementation SHA | `d0cb4f5be1825e28141e98202ce29ada9f2c1e8c` |
| Final SHA | Retrieve with `git rev-parse hardening/production-audit-v2`; the final documentation commit necessarily follows this report's recorded implementation SHA. |
| Platform | Linux x86_64, WSL2 kernel 6.18.40.1 |
| Python tested | 3.11.15, existing development venv plus two clean package venvs |
| System Python | 3.10.16, below project minimum; not used for verification |
| Git | 2.34.1 |
| Docker | 29.6.1; local daemon available with execution permission |
| Container integration image | Cached `kindest/node:v1.31.12` |
| Broker build | Fresh `jrx-production-audit-v2:local`, Python 3.11 slim |
| Tools | Ruff, mypy, Bandit, pip-audit, build, uv, Helm, Gitleaks |

[Environment and dependency versions](docs/audit-v2-evidence/environment.json) and
[installed development dependencies](docs/audit-v2-evidence/dependencies.json) record
exact versions. Clean package installations resolved 34 core dependencies without
optional harness dependencies. Cryptography resolved to 50.0.2 versus development
50.0.1; the successful runs do not establish compatibility with every allowed version.

## 3. Architecture Reviewed

Reviewed configuration, README/contribution instructions, historical report, architecture,
security, threat model, broker/MCP/sandbox/observability/harness documentation, Python
source and tests, package metadata, Dockerfile, Helm and workflows.

Boundary sequence: agent → adapter/hook → bounded Git/context collection → redaction
→ deterministic checks → semantic evaluator/broker → policy → optional intent/authority
→ host identity/approval/session enforcement → audit/telemetry → subprocess/MCP
forwarding → Docker/egress proxy/external service. Different entrypoints apply the
identity and session gates at different points; ordinary policy remains a pure function.

The [trust map and design](docs/production-audit-v2-plan.md) identifies trusted host
code, executable resolution, protected policy/bootstrap and public keys, identity settings,
private keys/state, Docker daemon and host gateway. Agent text, repository files,
symlinks, nested arguments, model output, upstream MCP catalogs and network responses
are untrusted. Policy signatures/JWT verification protect distinct trust boundaries.
Subprocesses include Git, scanners, provider CLIs, MCP upstream, Docker and proxy.
Persistent assets include approval/session SQLite, rollout state, audit chain and
workspace/harness checkpoints. New controls add HMAC-protected SQLite objects.

Potential bypasses include omitting hooks, modifying host config/PATH/session metadata,
changing files after evaluation, parser disagreement, identity spoofing, stale approvals,
concurrent reservations, schema drift and direct execution outside JRX. JRX is not an
OS reference monitor and cannot close all these paths without host confinement.

## 4. Testing Performed

Baseline normal verification preceded implementation. Each reported defect has a safe
reproduction; [AUDIT_FINDINGS.md](AUDIT_FINDINGS.md) records boundaries, expected/actual
behavior, cause, repair and regression. Original reproductions produced 11 failing cases;
additional nested-shell and Docker-context reproductions were added before their fixes.

Tests exercised full evaluation, CLI execution using disposable marker files, hook output,
MCP protocol parsing/forwarding, real local TLS and Unix sockets, mocked semantic APIs,
synthetic JWTs/secrets, persistent databases, concurrent threads/processes, disposable
containers, golden fixtures, package installation and Helm rendering.

Fuzz/property checks use fixed seeds and finite permutations, avoiding an additional
Hypothesis dependency. They cover protected audit-field mutations, Git flag/whitespace
permutations, YAML structural limits and atomic state invariants. This is bounded
adversarial testing, not exhaustive fuzzing of arbitrary shells or programs.

## 5. Confirmed Defects

| ID | Severity | Component | Problem | Reproduced | Fixed | Regression test |
| --- | --- | --- | --- | --- | --- | --- |
| V2-001 | High | CLI execution | `--yes` bypassed degraded enforce evaluation | Yes, temporary marker created | Yes | `test_enforce_unavailable_judge_cannot_be_overridden_with_yes` |
| V2-002 | High | Redaction/evaluator | Gitleaks failure lost degraded state with semantic evaluation disabled | Yes | Yes | `test_redaction_failure_remains_degraded_without_semantic` |
| V2-003 | Medium | Audit persistence | Audit append followed symlink | Yes, disposable target modified | Yes | `test_audit_append_rejects_symlink` |
| V2-004 | Medium | Configuration | Duplicate YAML keys/unknown keys silently reinterpreted policy | Yes | Yes | Duplicate/misspelled config tests |
| V2-005 | High | Git checks | Global options and reordered destructive flags bypassed checks | Yes, full evaluation | Yes | `test_destructive_git_variants_hold_in_full_pipeline` |
| V2-006 | Medium | MCP JSON | Duplicate members created authorization/parser ambiguity | Yes | Yes | `test_mcp_duplicate_method_cannot_bypass_gateway` |
| V2-007 | Medium | Audit/evaluator | Enabled audit write failure retained ALLOW in enforce mode | Yes | Yes | `test_required_audit_failure_blocks_enforce` |
| V2-008 | High | Shell detection | Newlines, substitution and `find -exec` obscured recursive deletion | Yes, evaluated as data | Yes | `test_explicit_nested_destructive_commands_hold` |
| V2-009 | Medium | Docker context | Ignore rules admitted local credentials into builder/cache | Yes, structural assertion and synthetic Docker COPY | Yes | `test_docker_context_excludes_local_credentials` plus Docker probe |
| V2-010 | Low | Optional control state | Malformed SQLite BLOB/Unicode fields raise uncontrolled errors | Yes, three cases on `9107b0d` | Yes, `3e676b2` | `test_malformed_authenticated_fields_produce_controlled_denial` |

No malicious/destructive command was executed on the host. Severity reflects the
examined deployments and actual behavior; no Critical defect was confirmed. Detection
repairs cover reproduced forms, not every equivalent implementation of destructive intent.

## 6. Historical Findings Revalidated

Historical findings are not presumed current. Baseline tests and source inspection were
repeated, with targeted regression suites rerun after implementation.

| Old finding | Current status | Evidence |
| --- | --- | --- |
| DEF-001 colon-prefixed secret redaction | FIXED before this audit | `test_colon_delimited_preceding_label_does_not_leak_secret` passed |
| DEF-002 nonexistent TLS context constructor | FIXED before this audit | Actual trusted/untrusted client mTLS handshake test passed |
| DEF-003 uppercase `git branch -D` | FIXED; REGRESSION INTRODUCED ELSEWHERE | Original case passed; different valid Git syntax reproduced V2-005 |
| DEF-004 central review/enforce hierarchy | FIXED before this audit | 3×3 mode merge matrix and execution-mode tests passed |
| DEF-005 broker container directory permissions | FIXED before this audit | Dockerfile 0700; fresh image non-root writable directory and default-startup probe |
| DEF-006 missing explicit configuration | FIXED before this audit | CLI/config/broker missing-path tests reject rather than default |
| DEF-007 omitted wheel golden fixtures | FIXED before this audit | 24 fixtures in wheel; installed wheel and sdist golden commands passed |
| DEF-008 dirty checkout test sensitivity | FIXED for examined tests | Temporary test working directories and both changed/clean checkout suites passed; Git-dependent demo output remains contextual by design |
| DEF-009 QEMU and PyPI release work | PARTIALLY FIXED | QEMU step exists; no PyPI publication job. External release execution not attempted |
| DEF-010 missing adapter exports | FIXED before this audit | Adapter package exports reviewed; imports used by passing adapter tests |
| DEF-011 missing Docker ignore file | FIXED; hardening gap elsewhere | Ignore file existed; credential-specific exclusions were incomplete (V2-009) |
| Cosign policy signer stub | STILL PRESENT | Explicit `NotImplementedError` tests pass; unsupported backend, not implemented security |
| Clock-skew validation absent | FIXED before this audit | Stale response and finite timestamp/skew-boundary tests passed |
| Audit rotation absent | STILL PRESENT | `rotate_mb` exists but automatic rotation does not; documented limitation |

[Historical regression output](docs/audit-v2-evidence/historical-revalidation.log).
Pipeline inspection is not evidence that an external release or multiarch deployment succeeded.

## 7. Security Tests

| Attack category | Evidence exercised | Limit of evidence |
| --- | --- | --- |
| A: command bypass | Full-pipeline Git global/reordered flags, quoting, nested shell, newline/substitution/find forms; neighboring check suite | Aliases, arbitrary Python programs and arbitrary Unicode spellings cannot be proven equivalent by this detector |
| B: dependency failure | Mock timeouts, malformed/non-finite semantic output, missing credentials, broker refusal/hang/stale response, invalid policy/signature/JWT, scanner failure, audit I/O failure | No paid API chaos or external JWKS outage campaign |
| C: TOCTOU | Approval repository/policy binding, schema pin/catalog drift, symlink containment, intent task/policy binding, pre-dispatch stop/revocation | Concurrent file replacement after last check remains possible |
| D: concurrency | Atomic approvals/budgets, audit writers, lineage/drift appends, nonce consumption | No distributed database/host partition testing |
| E: audit | Protected-field mutation, malformed/truncated tail, concurrency, symlink refusal, large-chain streaming, valid suffix deletion | Full-store/valid suffix rollback needs external checkpoint; automatic rotation absent |
| F: secrets | Existing redactor/scanner/mock/fallback suites; synthetic sensitive filename persistence check | Unknown secret formats are heuristic; no complete DLP guarantee |
| G: identity/approval | JWT signature/claims/scopes, requester self-review, distinct reviewers, expiry, binding changes and concurrent consumption | Real identity provider rotation/administrative revocation not exercised |
| H: MCP | Allowlist/schema/argument constraints, nested paths, local refs, catalog pin changes, duplicate JSON, process/environment/timeout cases | Exhaustive recursive schemas and malicious upstream protocol fuzzing not performed |
| I: sandbox | Runtime environment/filesystem isolation, root write denial, no-network, timeout and controlled proxy tests; command resource flags | No kernel exploit, device escalation or sustained CPU/memory exhaustion campaign |
| J: broker/IPC/TLS | Unsafe socket/directory checks, lifecycle, request bounds, busy worker timeout, stale/skew/non-finite output, real mTLS | Expired certificate/time rollback and all PID/socket replacement races not exhaustively tested |
| K: parsing | Duplicate/unknown keys, malformed YAML, aliases, depth/node/byte bounds, threshold/model validation | Input files/network responses may be read before size rejection |
| L: supply chain | Build/install/artifact checks, pip-audit, workflow and image inspection | Mutable dependency/action/base-image tags remain; no release publication |
| M: resources | Existing context/protocol limits, YAML structural limits, record caps, bounded per-session lineage, streaming verify | Audit append/tail and some fetches remain unbounded; no huge disk fill |
| N: platforms | Linux/WSL execution; path, Git/worktree/reftable and socket code inspection | macOS/Python 3.12/ARM runtime not run locally; Windows not claimed |

Exceptions and secrets were tested with synthetic data; original `.env` contents were
never read. Existing scanner-unavailable tests intentionally produce fallback warnings.
Semantic output never substitutes for deterministic scope/delegation checks.

## 8. Concurrency Tests

Four processes made 40 session reservation attempts against a limit of 12; successful
reservations and persisted counters both equaled 12. Sixteen concurrent grants by one
reviewer yielded one grant; a second identity was required. Twenty-four consumers
produced one successful approval use. Existing audit concurrent append tests remained
passing. Twenty-four lineage actions retained unique IDs, parent links and cumulative
state. Twenty-four same-nonce lease validations produced one success.

Authenticated use counts detect deleted nonce records; authenticated lineage counts
and parent links detect deleted linked records. SQLite immediate transactions serialize
checks plus mutations. These tests do not prove behavior under networked storage or
whole-database rollback. See `tests/test_audit_v2_properties.py` and
`tests/test_intent_authority.py`.

## 9. Packaging Tests

Wheel and sdist built successfully with `python -m build --no-isolation`. Each installed
in a separate clean Python 3.11 venv, without optional harness dependencies. Tests ran
from `/tmp` with `PYTHONPATH` removed, preventing source-checkout imports.

Each installation passed 28 CLI checks: both entrypoints, offline check, 24 packaged
policy cases, audit/session/broker/MCP/benchmark command help, one-run offline stability
benchmark, actual audit verify/tail, session stop/status, unavailable broker status,
unknown MCP call denial without upstream forwarding, intent keygen/create/status/explain/stop and authority issue/inspect/tree/revoke.
These are installed-package CLI functional checks, not the entire pytest suite running
against wheel dependencies. Original development dependency resolution also passed.

[Artifact hashes](docs/audit-v2-evidence/artifacts.json),
[wheel CLI checks](docs/audit-v2-evidence/wheel-cli-checks.json),
[sdist CLI checks](docs/audit-v2-evidence/sdist-cli-checks.json).
License and module/fixture contents were inspected. No repository dependency constraints were changed. Clean wheel dependency scanning
reported no known vulnerabilities; the unpublished project itself has no PyPI advisory entry.

## 10. Container / Deployment Tests

Docker integration tests ran, rather than skipped, in baseline and final full suites.
They exercise workspace mounting, host secret/environment exclusion, read-only root,
network isolation, timeout cleanup and allowlisted proxy behavior. Resource-limit flags
have separate unit coverage; this does not establish measured limits under load.

Fresh broker image built locally. Default broker startup, keyless health and the
implemented offline fail-closed self-check passed. Non-root UID, private writable 0700 broker directory,
Gitleaks 8.30.1 and installed golden fixtures were exercised with network disabled.
A synthetic `.env` Docker COPY probe distinguishes the old and repaired ignore rules.
No real credentials were placed in a container or build context.

Helm lint: one chart, zero failures, informational recommended icon. Template rendering
passed and Helm tests ran. No Kubernetes deployment, remote infrastructure, multiarch
runtime or registry publication was performed. An attempted `broker self-test` command
was unsupported (exit 2); verification uses the implemented `check --fail-closed-check`.

## 11. MCP Tests

The existing subprocess-backed gateway tests verify denied unknown/write calls, upstream
timeout/death handling and credential-environment stripping. Argument/schema and pin
suites exercise nested resource constraints and catalog changes. Duplicate JSON members
now reject before dispatch, including nested objects. Optional authority derives a
per-request nonce bound to lease/session/request ID; separate authorized requests can
proceed while replayed request IDs fail. Stop/revocation is checked before forwarding.

This requires a trusted host gateway and protected upstream rule configuration. A
malicious server can perform additional operations after accepting a permitted request;
preflight schema validation does not confine its runtime behavior.

## 12. Broker Tests

Real Unix lifecycle and local generated-certificate mTLS tests passed. Existing bounded
request handling, worker timeouts, unsafe permissions/symlinks, redaction, request IDs,
stale responses and skew checks were retained. Semantic evidence is validated locally;
a remote decision cannot erase a local destructive finding. Paid live broker integration
was intentionally skipped. No TLS verification was weakened.

## 13. Feature 1 — Execution Lineage & Intent Drift

Threat: a series of plausible actions expands beyond the original approved task.
Implementation: immutable task/repository/policy envelope, literal path/capability scope,
forbidden capabilities, persistent UUID/parent lineage, fingerprints, cumulative semantic
`scope_creep`, host HMAC and bounded SQLite transactions. Deterministic violations deny
without semantic evidence. CLI exposes create/status/explain/stop and explicit keygen.

Tests include immediate scope violations, gradual drift, 60 benign actions, persistence,
concurrent appends, task/policy alteration, stop, missing key/state, authenticated-row
mutation/deletion, storage limits, sensitive filename redaction, symlink scope escape,
unknown options/executable traversal and full evaluation/CLI enforcement.

Limitations: conservative supported preflight mappings; no perfect intent understanding
or actual process access tracing; exact task/config binding may require fresh sessions
for routine policy updates. Host metadata must be authenticated. Whole-store rollback
and the final execution race need external/OS controls. See [dedicated docs](docs/intent-lineage.md).

## 14. Feature 2 — Scoped Agent Authority Leases

Threat: collaborating children inherit broad parent authority. Implementation:
HMAC-authenticated host-side leases bind issuer/subject sessions, repository, environment,
policy, resources, capabilities, issue/expiry, nonce, parent and depth. Every live ancestor
is authenticated and checked. Child scope/time/capabilities must be subsets; forbidden
classes accumulate. Revocation cascades through ancestor checks. Unique action nonce
consumption and authenticated use count are atomic. No reviewer/admin authority can be
leased. OIDC remains identity authority; ordinary policy and human approval still apply.

Tests cover valid/nested leases, amplification in every bound dimension, expiry,
revocation, replay/concurrency, forged/modified parents, excessive depth/cycle,
sibling subject/session mismatch, cross-repository/environment/policy use, deleted replay
records, full CLI execution and MCP independent request nonces. CLI issue/inspect/revoke/tree
was exercised from source and installed packages.

Limitations: protected host equivalent, not portable signed bearer tokens or remote
attestation; same-UID key/config/environment access defeats isolation. Action IDs must
remain unique for a lease lifetime. State capacity refuses authorization; operator
archival is manual. Trustworthy wall clock and externally protected freshness are needed.
See [dedicated docs](docs/authority-delegation.md).

Novelty research examined official Claude Code sandboxing, SPIFFE workload identity and
OpenFGA conditional authorization. The controls are novel relative to current JRX;
those sources do not prove global novelty or absence in other coding-agent products.
No global novelty or marketing priority claim is made.

## 15. Remaining Risks

- Routing enforcement and protected host assets are deployment requirements; same-account
  agents able to alter keys/configuration/PATH or execute outside hooks bypass JRX.
- Preflight parsers cannot prove arbitrary shell/program behavior or close filesystem TOCTOU.
- Valid audit suffix deletion and valid whole-control-store rollback require trusted checkpoints.
- Audit automatic rotation is absent; append/tail and some file/network reads have remaining
  resource growth concerns. Control limits bound objects, not a complete disk quota.
- Broad minimum dependency constraints, mutable GitHub Action tags and mutable Docker
  base tags reduce reproducibility. CI has no explicit top-level permission restriction;
  actual token permissions depend on repository settings. Release permissions are broad.
- Cosign policy backend is unsupported and fails explicitly. PyPI release automation absent.
- Heuristic redaction cannot guarantee removal of arbitrary novel secrets or business data.

## 16. Unsupported / Untested Areas

Paid TypeSafe calls, real provider credentials, external JWKS changes, real agent-host
security separation, remote deployments/Kubernetes, multiarch runtime, macOS runtime,
Windows, disk-fill/kill-during-write campaigns, live metadata service
access and kernel privilege escalation were not performed. Some cases have local mocks
or configuration tests, which are not equivalent to deployment evidence. The user
explicitly permitted skipping work that cannot be performed safely.
Python 3.12 was subsequently tested in the complete verification follow-up.

## 17. Verification Results

All Python commands below used `/home/masa84/jev_reflex/.venv/bin/python` (3.11.15)
with `PYTHONPATH` selecting the isolated checkout. The TypeSafe credential was empty;
Docker integration used the cached fixture image. Clean package commands used each venv's
installed executable, removed `PYTHONPATH`, and ran outside the repository.

| Command / run | Result |
| --- | --- |
| Baseline `python -m pytest -ra` | 628 passed, 1 skipped, 4 warnings, 320.20s |
| Final `python -m pytest -ra` | 696 passed, 1 skipped, 4 warnings, 559.11s |
| `python -m ruff check .` | All checks passed |
| `python -m ruff format --check .` | 136 files already formatted |
| `python -m mypy` | No issues in 70 source files |
| `python -m bandit -c pyproject.toml -r src/jev_reflex -ll` | Exit 0; zero medium/high; 49 low findings retained |
| `make policy-test lint format` | Exit 0; 24/24 golden cases; no formatting changes |
| Clean committed checkout `make test` with `PYTEST_ADDOPTS=-ra` | 696 passed, 1 skipped, 4 warnings, 435.96s; 24/24 golden cases |
| Clean checkout `make lint format`, mypy, Bandit | Exit 0; 133 files unchanged, 70 source files typed, no medium/high issues |
| `python -m build --no-isolation` | Wheel + sdist built successfully |
| Separate clean wheel / sdist installations | Both successful, 28 CLI checks each |
| `python -m pip_audit --local --skip-editable` | No known vulnerabilities found in examined development environment |
| `docker build --progress=plain -t jrx-production-audit-v2:local .` | Exit 0 |
| `helm lint helm/jrx-broker` | 1 chart, 0 failures |
| `helm template jrx helm/jrx-broker` | Exit 0 |
| New adversarial suites | 68 passed in 35.45s |
| Clean wheel dependency `pip-audit --path ...` | No known vulnerabilities; project itself absent from PyPI advisory database |
| `git diff --check` | Exit 0 |
| TODO/FIXME/XXX/pass/NotImplementedError/print/skip scan | Reviewed; Cosign stub and existing cleanup/protocol/test uses retained; no new skipped tests or debugging prints |

[Evidence directory](docs/audit-v2-evidence) retains before-fix reproductions, final
outputs, dependency metadata and package checks. Restricted initial IPC/network runs
failed because the execution sandbox prohibited sockets/DNS; permitted local reruns
succeeded. These environmental failures are not reported as repository vulnerabilities.
Development runs also exposed a message-compatibility failure, corrected without
weakening the existing degraded-execution test, and new-feature review issues corrected
with failing regressions before rerunning. No failing test was deleted or disabled.

## 18. Production Readiness Gaps

Before rollout, establish actual host/agent account separation and immutable routing,
keys/policy protection, checkpoint/backup retention, audit rotation/quotas, dependency
and image pinning appropriate to the deployment, and staging evidence for the actual
OIDC provider, agent hosts, MCP servers, sandbox image and platforms. Review explicit
unsupported action mappings rather than granting `unknown` broad authority. Both new
controls should undergo staged deployment and operational review. The repaired branch
is reviewable with concrete local evidence; universal production readiness is not claimed.
