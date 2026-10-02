# Complete JRX verification follow-up

Date: 2026-10-02. Initial pushed SHA: `9107b0db87676195e21f49c2de5862d8f5657fbb`.
Tested implementation SHA: `3e676b23c1f5cc0b243ac2b185aba64d51e111e3` on `hardening/production-audit-v2`.

A follow-up documentation commit contains this report; runtime source and tests remain identical to the tested SHA.

## Final results

| Environment | Gitleaks | Passed | Skipped | Failed | Pytest seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| final-wheel311-fallback | unavailable | 697 | 3 | 0 | 186.62 |
| final-wheel312-fallback | unavailable | 697 | 3 | 0 | 162.34 |
| final-source-scanner | installed | 699 | 1 | 0 | 645.8 |

All 18 final required command checks passed. The full matrix ran serially.
Each full suite collected 700 cases. Broker/TLS, MCP, audit, approval, session, concurrency, harness, disposable Docker, intent and authority tests are included.
The installed-wheel suites remove PYTHONPATH and use pytest importlib mode. Recorded origins confirm site-packages imports and matching repaired source hashes.

The source run includes both real-Gitleaks tests and 24/24 policy golden cases. Missing-scanner wheel runs intentionally exercise the regex fallback deployment mode: only the two binary-dependent tests and paid live evaluator test skip. No tests were deleted or disabled.

Three separate installed packages (wheel 3.11, wheel 3.12, core sdist 3.11) each passed 28 CLI checks, for 84 checks. These cover both entrypoints, offline evaluation, golden policy fixtures, audit verify/tail, session status/stop, unavailable broker status, unknown MCP denial without forwarding, benchmark and intent/authority lifecycle.

## Commands and evidence

| Check | Exit | Command seconds |
| --- | ---: | ---: |
| [final-source-scanner](final-source-scanner.log) | 0 | 712.17 |
| [final-wheel311-fallback](final-wheel311-fallback.log) | 0 | 191.25 |
| [final-wheel312-fallback](final-wheel312-fallback.log) | 0 | 167.79 |
| [final-wheel311-cli](final-wheel311-cli.log) | 0 | 32.59 |
| [final-wheel312-cli](final-wheel312-cli.log) | 0 | 32.85 |
| [final-sdist311-cli](final-sdist311-cli.log) | 0 | 35.57 |
| [final-ruff](final-ruff.log) | 0 | 0.48 |
| [final-format](final-format.log) | 0 | 0.55 |
| [final-mypy](final-mypy.log) | 0 | 73.21 |
| [final-bandit](final-bandit.log) | 0 | 4.62 |
| [final-helm-lint-correct](final-helm-lint-correct.log) | 0 | 0.22 |
| [final-helm-render-correct](final-helm-render-correct.log) | 0 | 0.17 |
| [final-diff](final-diff.log) | 0 | 0.39 |
| [final-build-isolated](final-build-isolated.log) | 0 | 15.21 |
| [final-docker-build](final-docker-build.log) | 0 | 108.12 |
| [final-docker-smoke](final-docker-smoke.log) | 0 | 199.69 |
| [final-wheel311-pip-audit](final-wheel311-pip-audit.log) | 0 | 14.73 |
| [final-wheel312-pip-audit](final-wheel312-pip-audit.log) | 0 | 14.38 |

Exact argv, working directories, durations and exit codes are in [results.json](results.json); JUnit XML and console transcripts are retained. Console/JUnit presentation trailing whitespace is normalized for git checks; adjacent .raw.gz files preserve the original bytes, with SHA256s in console-normalization.json. The serial matrix and package/container drivers are included as .py.txt files. Command durations include setup and, for make test, the separate golden-policy command.

Ruff, formatting, mypy (70 sources), requested Bandit -ll, Helm lint/render and git diff --check pass. Bandit retains 49 low findings and reports zero medium/high findings under the requested exclusions.
Both installed dependency scans report no known vulnerabilities. The unpublished jev-reflex distribution itself has no PyPI advisory entry and is reported as unauditable by that service.
The isolated wheel and sdist build passed. Every uncompressed file in each rebuilt artifact matches its corresponding tested artifact; SHA256 records and comparison results are retained.
The fresh non-root container passes default broker startup, keyless health, private 0700 runtime storage, all 14 offline failure scenarios in each of three modes, and synthetic old/new build-context credential exclusion assertions.

## Confirmed follow-up fix: V2-010 (Low)

SQLite TEXT affinity permits BLOB fields. Malformed BLOB/Unicode authenticators or BLOB payloads raised uncaught TypeError in the authenticated store instead of controlled denial. Three new full-evaluator/operator-CLI regression cases failed on 9107b0d before the fix.
AuthenticatedStore.get now checks string types, bounded payload length and exact lowercase hexadecimal MAC format before hashing/comparison. Those cases and 68 neighboring adversarial cases pass (71 total). Native hooks already denied exceptions, so no execution bypass was demonstrated. The findings register documents this as a reliability defect in optional control state.

## Earlier runs and retained failures

| Run | SHA | Passed | Skipped | Failed |
| --- | --- | ---: | ---: | ---: |
| [source-suite](source-suite.log) | 9107b0d | 696 | 1 | 0 |
| [wheel311-suite](wheel311-suite.log) | 9107b0d | 696 | 1 | 0 |
| [wheel312-suite](wheel312-suite.log) | 9107b0d | 696 | 1 | 0 |
| [revised-source-scanner](revised-source-scanner.log) | 3e676b2 | 698 | 1 | 1 |

- One repaired source run failed the existing broker lifecycle test; its isolated repeat and final serial matrix passed. Occupying loopback port 9090 independently reproduces a test failure. This does not prove the original intermittent failure was a port collision. The shared default port and five-second startup window remain unchanged at the user’s request.
- The first container driver timed out at its external 120-second limit during concurrent tests. That transcript is retained. The final repaired-image run passed with a 300-second driver limit; JRX security timeouts and enforcement were unchanged.
- One operator Helm command used a nonexistent chart path. The incorrect-path transcripts are retained; lint and render passed for helm/jrx-broker.

## Environment and limits

Linux x86_64 WSL2 kernel 6.18.40.1; Python 3.11.15 and 3.12.13; Git 2.34.1; Docker 29.6.1. Clean local clones, temporary virtual environments, synthetic secrets, mocked evaluators, local certificates and disposable containers were used. Existing source-checkout edits were preserved.
No paid live API, real credentials, external infrastructure, release, main merge or publication was used. macOS/Windows/ARM, other Python versions, deployed agent separation, actual OIDC/JWKS provider changes, kernel escape campaigns and exhaustive arbitrary-shell interpretation remain untested.
Passing this bounded local matrix is not a claim that every production attack is covered. Existing preflight/TOCTOU, same-UID key/config access, whole-state rollback, audit retention and unpinned supply-chain limitations remain documented in PRODUCTION_AUDIT_V2.md.
