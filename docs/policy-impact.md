# Preview policy changes on pull requests

`jrx policy impact` replays recorded policy decisions against a proposed policy. The PR status shows coverage, new ALLOWs, HOLD-to-REVIEW transitions when present, and new HOLDs. For example,

```text
500/540 replayed, 2 new ALLOW, 4 HOLD->REVIEW, 3 new HOLD
```

The workflow summary gives all six transition counts and the number of legacy records, baseline hash mismatches, and decision mismatches skipped. Outcomes describe the replayed sample. Actual execution depends on the integration and its enforcement mode.

## Run a preview locally

```sh
jrx policy impact --audit audit.jsonl --baseline baseline.yaml --candidate candidate.yaml
```

| Exit | Meaning |
| --- | --- |
| 0 | At least one matching decision was replayed and both configured limits were satisfied. |
| 1 | A completed replay exceeded a configured limit. |
| 2 | Unassessed. Examples include invalid policies, unsupported changes, failed audit verification and zero replayable decisions. |

Both limits take nonnegative integers. `--max-new-allows 0` rejects either REVIEW → ALLOW or HOLD → ALLOW. `--max-relaxations 0` also rejects HOLD → REVIEW. Without either flag the check reports counts without a transition gate. `--github-output FILE` appends the single-line `counts` field after an assessed replay, including a limit breach.

Use the original collector configuration as the baseline. JRX checks the hash chain, matches the complete effective policy hash, and recomputes the recorded decision before comparing the candidate. Supply the captured evidence path with `--audit` and leave the collector’s configured paths intact. Changes to decision inputs such as thresholds are replayable. Changes to sampling, access rules or MCP tool schemas require separate validation.

### Signed audits

When the trusted baseline configures `signing.public_key_path`, replay verifies every decision signature. Use `--public-key /trusted/producer.pub` to supply that public key at its CI location. The explicit path takes precedence. A missing or invalid verification key, a missing signature, or an invalid signature makes a keyed replay unassessed.

Replay never needs the producer’s private key. With only `signing.private_key_path` configured it verifies the hash chain. If `signing.require_signature` is true, a trusted public key is mandatory. Protect snapshot provenance and completeness separately. A hash chain alone cannot authenticate its producer or detect removal of a valid suffix.

## Enable the GitHub check

1. Land the workflow, its `.github/scripts/policy-impact-inputs.sh` helper and the collector’s baseline at `policies/agent.yaml` on `main`. Both baseline and candidate must be non-executable regular Git blobs no larger than 1 MiB.
2. Store a complete `audit.jsonl` as a regular, non-executable file at the root of a separate private evidence repository. Record its full 40-character commit SHA.
3. Create a GitHub Actions environment named `jrx-impact`, restrict deployment to trusted `main` workflows, and set these environment values.

   | Name | Kind | Value |
   | --- | --- | --- |
   | `JRX_EVIDENCE_REPO` | Variable | Private evidence repository as `owner/repo` |
   | `JRX_EVIDENCE_SHA` | Variable | Full evidence commit SHA |
   | `JRX_EVIDENCE_TOKEN` | Secret | Token with read-only Contents permission on the evidence repository |
   | `JRX_AUDIT_PUBLIC_KEY` | Optional variable | Trusted audit verification public key in PEM format |
   | `JRX_MAX_NEW_ALLOWS` | Optional variable | Maximum new ALLOWs |
   | `JRX_MAX_RELAXATIONS` | Optional variable | Maximum total relaxations |

4. Set the **repository** Actions variable `JRX_POLICY_IMPACT_ENABLED` to `true`. Open a PR targeting `main` and inspect the `jrx/policy-impact` commit status on its head SHA.

The **detect** job runs without the evidence environment. It fetches GitHub’s test merge as data and verifies both parents. An unchanged policy gets `Policy file unchanged.`. A missing merge ref or stale parents produce an actionable error. A fork changing the policy requires a maintainer to review the change and open a same-repository PR for replay.

The **replay** job enters `jrx-impact` only for a changed, valid same-repository proposal. It rechecks the detected merge before extracting the policy blobs and installs JRX from the exact trusted workflow revision (`github.sha`). It then reads the pinned evidence into `$RUNNER_TEMP/evidence` and runs the installed interpreter with `-I`. The proposed source tree is never checked out. Only aggregate results reach the PR.

Start with an advisory check while evaluating sample coverage. To enforce it, configure limits, require `jrx/policy-impact` and require branches to be current with `main`. Restrict who can edit trusted workflows, set environment values and publish commit statuses. Update the evidence pin when replacing a snapshot, then rerun checks against the current PR revision.
