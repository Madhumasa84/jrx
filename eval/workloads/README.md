# Labeled workload evaluation

This directory holds the protocol and data for measuring detection quality and operator
friction on recorded agent tool calls, by what each host would actually do. It is
separate from the frozen 300-case benchmark (`benchmarks/`, kept comparable across
releases) and from the JRX-01 authorization pilot (`eval/jrx-01/`, five development
samples with a different label type).

**Status: no independently labeled holdout exists.** The scorer, the protocol checks and
a 16-record synthetic development set are in place. Every number produced so far comes
from records written and labeled by the maintainer and is not evidence of production
quality.

## What is measured

Each record is one host hook event (an inert, recorded tool call; nothing is executed)
and a label saying whether the action was **risky**: it should not run unattended in the
workspace it came from. `python -B -m benchmarks.workloads` runs every record through the
pipeline the hooks use (payload normalization, evaluation, `host_verdict`) for each
mode and backend and reports, per adapter, mode and backend, with counts and
denominators and Wilson 95% intervals:

| Metric | Meaning |
| --- | --- |
| `risky_proceeded` | Risky actions the host runs unattended (missed). |
| `risky_asked` | Risky actions flagged for a user decision. Not prevention: the user may approve. |
| `risky_denied` | Risky actions the host refuses (prevented). |
| `benign_denied` | Benign actions refused (hard friction). |
| `benign_asked` | Benign actions sent to the user (review friction). |
| `latency_ms` | In-process evaluation time, p50 and p95, per record. |

`--backend deterministic` uses only the local rules; `model-assisted` adds the local
ONNX model when it is installed (`jrx model pull`), and is reported as not run otherwise.

## Protocol

1. **Records** use schema `jrx.workload.v1` (see `development/synthetic_v1.jsonl`): `id`,
   `split`, `adapter` (`claude`, `codex`, `deepseek`, `antigravity`, `openrouter-pre`,
   `openrouter-permission`, `pi`), the host `event`, `label.risky` with a rationale,
   `labeling` (`labeler`, `independent`, `method`) and `provenance` (`source`,
   `authorized`, `collected`, `sampling`). Replace secrets and private identifiers with
   consistent placeholders before a record enters the repository.
2. **Development** records may be written or relabeled freely and used for tuning.
3. **Holdout** records must come from an authorized, non-synthetic source, be labeled by
   someone independent of the change being evaluated, and be sampled by a documented
   method (for example every Nth tool call of consenting sessions). They are never used
   for tuning.
4. **Thresholds first.** `thresholds.json` holds proposed acceptance limits. Before any
   holdout record is scored, the release owner reviews them, sets `status` to
   `registered` with `registered_by` and `registered_at`, and pins the file's SHA-256 in
   `manifest.json`. The scorer refuses the holdout otherwise, and any later change to
   the limits changes the pinned hash in history.
5. **Freeze, then score.** Add holdout files to `holdout/`, pin each file's SHA-256 in
   `manifest.json`, commit, and only then run
   `python -B -m benchmarks.workloads --split holdout --backend both`. Strata below
   `minimum_samples` are reported as `insufficient sample`, not pass or fail.
6. **Report** every stratum with counts and denominators, including failures, and keep
   the JSON output with the release evidence.

## Commands

```bash
python -B -m benchmarks.workloads --self-test          # protocol checks + development run
python -B -m benchmarks.workloads --modes enforce      # development report as JSON
python -B -m benchmarks.workloads --split holdout --backend both --out holdout.json
```
