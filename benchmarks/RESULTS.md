# jrx v0.2.0 deterministic benchmark

This baseline measures **Tier-0 deterministic rules only**, with no semantic model.
The benchmark covers single-step pre-execution classification of synthetic cases.
The out-of-scope OWASP categories are **ASI07** (Insecure Inter-Agent Communication),
**ASI08** (Cascading Failures), **ASI09** (Human-Agent Trust Exploitation), and
**ASI10** (Rogue Agents).

## Reproduce

Run from the repository root with jrx installed in the active Python environment.

```sh
python -B benchmarks/run.py --backend deterministic --verify-hashes --out benchmarks/results/v0.2.0-deterministic.json --render-md benchmarks/RESULTS.md
```

## Eval holdout headline results

Rates show the observed fraction and its two-sided Wilson 95% confidence interval.
Attack recall is the intervention rate (REVIEW or HOLD). Strict block counts HOLD only.

| Metric | Rate [95% CI] |
| --- | --- |
| Benign Hard FPR | 16.67% (10/60) [9.31%, 28.03%] |
| Benign Friction Rate | 25.00% (15/60) [15.78%, 37.23%] |

| Attack cohort | Recall [95% CI] | Strict block [95% CI] | Below expected minimum [95% CI] |
| --- | --- | --- | --- |
| All attacks | 12.22% (11/90) [6.96%, 20.57%] | 12.22% (11/90) [6.96%, 20.57%] | 87.78% (79/90) [79.43%, 93.04%] |
| OWASP ASI01–ASI06 | 11.67% (7/60) [5.77%, 22.18%] | 11.67% (7/60) [5.77%, 22.18%] | 88.33% (53/60) [77.82%, 94.23%] |
| ASI01 Goal hijack | 0.00% (0/10) [0.00%, 27.75%] | 0.00% (0/10) [0.00%, 27.75%] | 100.00% (10/10) [72.25%, 100.00%] |
| ASI02 Tool misuse | 40.00% (4/10) [16.82%, 68.73%] | 40.00% (4/10) [16.82%, 68.73%] | 60.00% (6/10) [31.27%, 83.18%] |
| ASI03 Privilege and secret abuse | 30.00% (3/10) [10.78%, 60.32%] | 30.00% (3/10) [10.78%, 60.32%] | 70.00% (7/10) [39.68%, 89.22%] |
| ASI04 Supply chain | 0.00% (0/10) [0.00%, 27.75%] | 0.00% (0/10) [0.00%, 27.75%] | 100.00% (10/10) [72.25%, 100.00%] |
| ASI05 Unexpected code execution | 0.00% (0/10) [0.00%, 27.75%] | 0.00% (0/10) [0.00%, 27.75%] | 100.00% (10/10) [72.25%, 100.00%] |
| ASI06 Context and memory poisoning | 0.00% (0/10) [0.00%, 27.75%] | 0.00% (0/10) [0.00%, 27.75%] | 100.00% (10/10) [72.25%, 100.00%] |
| Obfuscation bypass | 13.33% (4/30) [5.31%, 29.68%] | 13.33% (4/30) [5.31%, 29.68%] | 86.67% (26/30) [70.32%, 94.69%] |

Clean minus obfuscated recall was **-1.67 pp** (Newcombe 95% interval [-19.05, +11.56] pp).
The suites contain different cases and attack mixes, so this unpaired difference
combines obfuscation with other differences between the suites.

## Top known misses & false positives

Families are ordered by count, with ties broken alphabetically. The tables show up to
three families per outcome and up to three case IDs per family.

| Outcome | Family | Count | Sample case IDs |
| --- | --- | ---: | --- |
| Attack ALLOW | delegated_execution | 5 | `bypass-041`, `bypass-043`, `bypass-045` |
| Attack ALLOW | encoded_execution_surrogate | 5 | `bypass-021`, `bypass-023`, `bypass-025` |
| Attack ALLOW | hidden_indirect_injection | 5 | `bypass-051`, `bypass-053`, `bypass-055` |
| Attack below expected minimum | delegated_execution | 5 | `bypass-041`, `bypass-043`, `bypass-045` |
| Attack below expected minimum | encoded_execution_surrogate | 5 | `bypass-021`, `bypass-023`, `bypass-025` |
| Attack below expected minimum | hidden_indirect_injection | 5 | `bypass-051`, `bypass-053`, `bypass-055` |
| Benign HOLD | example_credentials | 7 | `benign-021`, `benign-023`, `benign-025` |
| Benign HOLD | shell_pipelines | 2 | `benign-055`, `benign-057` |
| Benign HOLD | local_cleanup | 1 | `benign-001` |
| Benign REVIEW | local_cleanup | 3 | `benign-003`, `benign-013`, `benign-017` |
| Benign REVIEW | development_workflows | 1 | `benign-069` |
| Benign REVIEW | example_credentials | 1 | `benign-039` |

## Latency

Each mode ran 10 warm-ups and 100 timed iterations of the git status check.

| Mode | p50 (ms) | p95 (ms) | p99 (ms) | Peak RSS (MiB) |
| --- | ---: | ---: | ---: | ---: |
| Warm in-process | 0.461 | 0.727 | 1.503 | 55.41 |
| Cold jrx CLI | 448.433 | 495.154 | 583.025 | 56.04 |

Warm peak RSS covers the runner process, including imports and loaded fixtures.
Cold peak RSS is the child-process high-water mark, including warm-ups.

Environment: Linux, Python 3.11.15, 12 logical CPUs, built-in regex redaction.
The raw JSON includes dataset hashes, per-case decisions, all family counts and
intervals, and the dev split. See the [benchmark guide](README.md) for scope and methodology.
