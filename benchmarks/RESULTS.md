# jrx Step 3 Hardened Tier-0 deterministic benchmark

This benchmark measures **Tier-0 deterministic rules only**, with no semantic model.
The benchmark covers single-step pre-execution classification of synthetic cases.
Session taint and integrity pinning are measured by the integration tests.
The out-of-scope OWASP categories are **ASI07** (Insecure Inter-Agent Communication),
**ASI08** (Cascading Failures), **ASI09** (Human-Agent Trust Exploitation), and
**ASI10** (Rogue Agents).

## Reproduce

Run from the repository root with jrx installed in the active Python environment.

```sh
python -B -m benchmarks.run --backend deterministic --verify-hashes --out benchmarks/results/v0.2.0-step3-deterministic.json --render-md benchmarks/RESULTS.md --baseline benchmarks/results/v0.2.0-deterministic.json
```

## Frozen eval holdout comparison

Both revisions evaluated the same frozen cases. Recall is REVIEW or HOLD.
Individual rates include two-sided Wilson 95% intervals.

| Metric | v0.2.0 Baseline | Step 3 Hardened Tier-0 |
| --- | --- | --- |
| Benign Hard FPR | 16.67% (10/60) [9.31%, 28.03%] | 3.33% (2/60) [0.92%, 11.36%] |
| Benign Friction Rate | 25.00% (15/60) [15.78%, 37.23%] | 5.00% (3/60) [1.71%, 13.70%] |
| Overall attack recall | 12.22% (11/90) [6.96%, 20.57%] | 47.78% (43/90) [37.76%, 57.98%] |
| OWASP ASI01–ASI06 recall | 11.67% (7/60) [5.77%, 22.18%] | 40.00% (24/60) [28.57%, 52.63%] |
| ASI01 recall | 0.00% (0/10) [0.00%, 27.75%] | 10.00% (1/10) [1.79%, 40.42%] |
| ASI02 recall | 40.00% (4/10) [16.82%, 68.73%] | 40.00% (4/10) [16.82%, 68.73%] |
| ASI03 recall | 30.00% (3/10) [10.78%, 60.32%] | 40.00% (4/10) [16.82%, 68.73%] |
| ASI04 recall | 0.00% (0/10) [0.00%, 27.75%] | 30.00% (3/10) [10.78%, 60.32%] |
| ASI05 recall | 0.00% (0/10) [0.00%, 27.75%] | 60.00% (6/10) [31.27%, 83.18%] |
| ASI06 recall | 0.00% (0/10) [0.00%, 27.75%] | 60.00% (6/10) [31.27%, 83.18%] |
| Bypass recall | 13.33% (4/30) [5.31%, 29.68%] | 63.33% (19/30) [45.51%, 78.13%] |
| Warm in-process p50 / p95 | 0.461 / 0.727 ms | 0.893 / 2.332 ms |
| Cold CLI p50 / p95 | 448.433 / 495.154 ms | 829.113 / 1021.481 ms |

**v0.2.0 Baseline top missed families** — `delegated_execution` (5), `encoded_execution_surrogate` (5), `hidden_indirect_injection` (5).

**Step 3 Hardened Tier-0 top missed families** — `hidden_indirect_injection` (4), `encoded_execution_surrogate` (3), `goal_hijack_diff` (3).

## Current eval holdout details

Rates show the observed fraction and its two-sided Wilson 95% confidence interval.
Attack recall is the intervention rate (REVIEW or HOLD). Strict block counts HOLD only.

| Metric | Rate [95% CI] |
| --- | --- |
| Benign Hard FPR | 3.33% (2/60) [0.92%, 11.36%] |
| Benign Friction Rate | 5.00% (3/60) [1.71%, 13.70%] |

| Attack cohort | Recall [95% CI] | Strict block [95% CI] | Below expected minimum [95% CI] |
| --- | --- | --- | --- |
| All attacks | 47.78% (43/90) [37.76%, 57.98%] | 26.67% (24/90) [18.62%, 36.62%] | 53.33% (48/90) [43.10%, 63.29%] |
| OWASP ASI01–ASI06 | 40.00% (24/60) [28.57%, 52.63%] | 26.67% (16/60) [17.13%, 39.01%] | 61.67% (37/60) [49.02%, 72.91%] |
| ASI01 Goal hijack | 10.00% (1/10) [1.79%, 40.42%] | 10.00% (1/10) [1.79%, 40.42%] | 90.00% (9/10) [59.58%, 98.21%] |
| ASI02 Tool misuse | 40.00% (4/10) [16.82%, 68.73%] | 40.00% (4/10) [16.82%, 68.73%] | 60.00% (6/10) [31.27%, 83.18%] |
| ASI03 Privilege and secret abuse | 40.00% (4/10) [16.82%, 68.73%] | 30.00% (3/10) [10.78%, 60.32%] | 70.00% (7/10) [39.68%, 89.22%] |
| ASI04 Supply chain | 30.00% (3/10) [10.78%, 60.32%] | 10.00% (1/10) [1.79%, 40.42%] | 70.00% (7/10) [39.68%, 89.22%] |
| ASI05 Unexpected code execution | 60.00% (6/10) [31.27%, 83.18%] | 10.00% (1/10) [1.79%, 40.42%] | 40.00% (4/10) [16.82%, 68.73%] |
| ASI06 Context and memory poisoning | 60.00% (6/10) [31.27%, 83.18%] | 60.00% (6/10) [31.27%, 83.18%] | 40.00% (4/10) [16.82%, 68.73%] |
| Obfuscation bypass | 63.33% (19/30) [45.51%, 78.13%] | 26.67% (8/30) [14.18%, 44.45%] | 36.67% (11/30) [21.87%, 54.49%] |

Clean minus obfuscated recall was **-23.33 pp** (Newcombe 95% interval [-42.03, -1.49] pp).
The suites contain different cases and attack mixes, so this unpaired difference
combines obfuscation with other differences between the suites.

## Top known misses & false positives

Families are ordered by count, with ties broken alphabetically. The tables show up to
three families per outcome and up to three case IDs per family.

| Outcome | Family | Count | Sample case IDs |
| --- | --- | ---: | --- |
| Attack ALLOW | hidden_indirect_injection | 4 | `bypass-051`, `bypass-053`, `bypass-055` |
| Attack ALLOW | encoded_execution_surrogate | 3 | `bypass-023`, `bypass-025`, `bypass-027` |
| Attack ALLOW | goal_hijack_diff | 3 | `asi-001`, `asi-003`, `asi-005` |
| Attack below expected minimum | hidden_indirect_injection | 4 | `bypass-051`, `bypass-053`, `bypass-055` |
| Attack below expected minimum | encoded_execution_surrogate | 3 | `bypass-023`, `bypass-025`, `bypass-027` |
| Attack below expected minimum | goal_hijack_diff | 3 | `asi-001`, `asi-003`, `asi-005` |
| Benign HOLD | ordinary_changes | 1 | `benign-093` |
| Benign HOLD | shell_pipelines | 1 | `benign-055` |
| Benign REVIEW | development_workflows | 1 | `benign-069` |

## Latency

Each mode ran 10 warm-ups and 100 timed iterations of the git status check.

| Mode | p50 (ms) | p95 (ms) | p99 (ms) | Peak RSS (MiB) |
| --- | ---: | ---: | ---: | ---: |
| Warm in-process | 0.893 | 2.332 | 4.395 | 56.70 |
| Cold jrx CLI | 829.113 | 1021.481 | 1159.287 | 60.46 |

Warm peak RSS covers the runner process, including imports and loaded fixtures.
Cold peak RSS is the child-process high-water mark, including warm-ups.

Environment: Linux, Python 3.11.15, 12 logical CPUs, built-in regex redaction.
The raw JSON includes dataset hashes, per-case decisions, all family counts and
intervals, and the dev split. See the [benchmark guide](README.md) for scope and methodology.
