# Offline benchmark

The runner evaluates synthetic proposals using Tier-0 deterministic rules, local
CPU ONNX, or local CPU ONNX through a warm Unix broker. After model setup each
backend runs offline without an API key. Proposed actions remain inputs to the
evaluator. [Frozen holdout comparison](RESULTS.md)

## Reproduce

From the repository root, use Python 3.11 or later with jrx already installed
in that Python environment. The full latency run uses the jrx console script
on Linux or macOS and requires default system bootstrap settings.

```bash
output_dir=$(mktemp -d)
python -B -m benchmarks.run --backend deterministic --verify-hashes \
  --out "$output_dir/step3-deterministic.json" \
  --render-md "$output_dir/step3-deterministic.md" \
  --baseline benchmarks/results/v0.2.0-deterministic.json
```

Install `jev-reflex[local]` and run `jrx model pull` before the local run.
Use `local-broker` as the backend and a separate output filename to measure
the warm Unix broker. [Local ONNX results](RESULTS.md)

```bash
python -B -m benchmarks.run --backend local --verify-hashes \
  --out "$output_dir/local-onnx.json" --render-md "$output_dir/local-onnx.md"
```

Use the CI command for a decision-only comparison that skips latency.

```sh
make bench-deterministic
```

The existing `jrx benchmark stability` and `jrx benchmark live` suites have
their own fixtures and methodology. [Live benchmark methodology](../docs/live-benchmark.md)

To measure detection and operator friction on recorded, independently labeled agent
workloads by what each host would do (proceed, ask or deny, per adapter, mode and
backend), use the separate [labeled workload evaluation](../eval/workloads/README.md).
It does not change these frozen datasets or their baselines.

## Frozen datasets

| Dataset | Dev | Eval | Coverage |
| --- | ---: | ---: | --- |
| [Benign development](datasets/benign_dev_v1.jsonl) | 60 | 60 | Local cleanup, example credentials, shell pipelines, development workflows, diffs, and MCP calls |
| [OWASP ASI01–ASI06](datasets/owasp_asi_v1.jsonl) | 60 | 60 | 20 per category, with 10 dev and 10 eval cases each |
| [Obfuscation](datasets/bypass_obfuscation_v1.jsonl) | 30 | 30 | Compound shell state, token construction, encoding, interpreters, delegated execution, and hidden injection |

Each line is one object conforming to the [validated schema](datasets.py).
Command payloads contain a command, a workspace-relative working directory, and
optionally external content such as a synthetic log. Diff payloads contain
supplied diff text. MCP payloads name a synthetic server and tool and supply
structured arguments. Labels describe the minimum expected decision. An attack
labeled HOLD that receives REVIEW counts as an intervention and also falls below
its expected minimum. Expected signals annotate fixture intent for future
comparisons. This Tier-0 benchmark scores decisions.

The [SHA-256 manifest](datasets/holdout_sha256.txt) pins the complete files,
including labels and split assignments. Use only dev cases for tuning. The eval
holdout is public and relies on experiment discipline. Changes to fixtures, labels,
or split assignments require a new dataset version and a new baseline.

## What the runner measures

The deterministic backend calls `evaluate_context(..., use_jev=False)`, the
public evaluator used by `jrx check --no-jev`. It supplies default policy
settings and a temporary synthetic workspace and home directory. A controlled
`PATH` selects the runtime's built-in regex redaction even on hosts with Gitleaks
installed. The command and diff surfaces represent the evaluator inputs to
`jrx check`. The MCP surface represents the call context passed to the
evaluator. Gateway allowlists, schema pinning, authorization, and forwarding
are outside this measurement. Execution and transfer fixtures use synthetic
resources, inert canaries, or mock destinations.

OWASP coverage is grouped by **ASI01** (Agent Goal Hijack), **ASI02** (Tool
Misuse and Exploitation), **ASI03** (Identity and Privilege Abuse), **ASI04**
(Agentic Supply Chain Vulnerabilities), **ASI05** (Unexpected Code Execution),
and **ASI06** (Memory and Context Poisoning). **ASI07** (Insecure Inter-Agent
Communication), **ASI08** (Cascading Failures), **ASI09** (Human-Agent Trust
Exploitation), and **ASI10** (Rogue Agents) are out of scope for these
single-step pre-execution micro-benchmarks.

- **Hard FPR** counts benign HOLDs. **Friction rate** counts benign REVIEWs and
  HOLDs.
- **Strict block rate** counts attack HOLDs. **Intervention rate** is attack
  recall and counts REVIEWs and HOLDs. Per-ASI JSON rates include both a
  clean-suite view and a combined view. Per-family rates include all attacks
  assigned to the family.
- **Clean vs. obfuscated recall delta** subtracts the obfuscation suite's
  intervention rate from the OWASP suite's intervention rate. It is an unpaired
  comparison across different attack mixes.
- **Confidence intervals** are two-sided 95% Wilson score intervals for
  individual rates and a Newcombe interval derived from Wilson bounds for the
  delta. The fixtures are curated. These intervals quantify sampling
  uncertainty under a binomial model for a cohort and should not be treated
  as estimates of production incident rates.
- **Regression gate** compares exact eval counts with matching dataset hashes,
  backend, schema version, and denominators. It fails if benign Hard FPR or
  friction increases or intervention decreases overall, in the OWASP or bypass suite,
  or in any of the six clean ASI cohorts. Dev results remain available in the
  JSON for tuning.
- **Latency** measures ten warm-ups and 100 timed iterations per mode on
  `git status` in an empty temporary workspace. Warm timing includes the
  public evaluator on prebuilt context. Cold timing includes startup, CLI
  context collection, and formatting through `jrx check`. The deterministic
  backend uses `--no-jev`. Percentiles use nearest ranks.
  Peak RSS is the OS process high-water mark, reported in MiB. It includes
  warm-ups and, for the warm run, runner imports and dataset loading. Timing
  and memory will vary across machines.

Reports export allowlisted environment fields, dataset hashes, case IDs,
decisions, and aggregate statistics. [Raw v0.2.0 data](results/v0.2.0-deterministic.json) · [Raw Step 3 data](results/v0.2.0-step3-deterministic.json) · [Raw v0.3.0 local ONNX data](results/v0.3.0-local-coba68m.json)
