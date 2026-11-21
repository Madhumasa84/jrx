# Preview policy changes on pull requests

JRX Policy Impact replays historical policy decisions against a proposed policy and reports which decisions would move between `ALLOW`, `REVIEW` and `HOLD`. The PR status shows replay coverage and the counts of new `ALLOW` and `HOLD` decisions. Its workflow summary shows all six transitions and the reasons records were skipped. These are policy decisions. Execution also depends on the integration and its enforcement mode.

## Run a preview locally

```sh
jrx policy impact --audit audit.jsonl --baseline baseline.yaml --candidate candidate.yaml
```

| Exit code | Result |
| --- | --- |
| 0 | At least one matching decision was replayed and any configured limit was satisfied. |
| 1 | Replay completed and exceeded the `--max-new-allows` limit. |
| 2 | Impact was unassessed, for example because the inputs were invalid, the audit chain failed verification, the change was outside replay's scope, or no records matched. |

Set `--max-new-allows 0` to reject either `REVIEW → ALLOW` or `HOLD → ALLOW` in the replayed sample. `HOLD → REVIEW` remains visible in the report. Review the coverage and sample before relying on a passing result. JRX reuses recorded findings and semantic scores, so changes such as sampling or MCP authorization rules require separate validation.

## Enable the GitHub check

1. Land the workflow and the team's baseline at `policies/agent.yaml` on `main`. Use that policy to collect evidence with audit logging enabled. The check compares that file in the base and proposed merge.
2. Export a complete audit snapshot to `audit.jsonl` at the root of a separate private evidence repository. Record its full commit SHA. Keep the effective baseline configuration used by the collector, including its original audit path. The path to the downloaded snapshot is passed separately to `--audit`.
3. Create a GitHub Actions environment named `jrx-impact` for trusted `main` workflows. Add `JRX_EVIDENCE_REPO` (`owner/repo`) and `JRX_EVIDENCE_SHA` as environment variables. Add `JRX_EVIDENCE_TOKEN` as an environment secret with read-only contents access to that repository.
4. Set the repository Actions variable `JRX_POLICY_IMPACT_ENABLED` to `true`. Open a policy PR, then check the `jrx/policy-impact` status and its **Details** link. A PR with no change at the policy path succeeds without fetching the private evidence.

The workflow executes JRX from the trusted base commit. It reads the proposed policy as a bounded Git blob after verifying both parents of GitHub's test merge. Keep raw evidence in the trusted repository and publish only aggregate counts. Replay verifies the audit hash chain and matches the baseline policy hash. Evidence provenance comes from the protected source and pinned snapshot revision. CI needs no producer signing key.

Keep the check advisory while judging whether the sample represents the actions your team cares about. To use the new-`ALLOW` limit as a merge gate, set the optional environment variable `JRX_MAX_NEW_ALLOWS` and require `jrx/policy-impact` on `main`. Require branches to be current with `main` and restrict who can modify trusted workflows or publish commit statuses. Refresh the evidence pin when you collect a replacement snapshot and rerun checks whose evidence or base has changed.
