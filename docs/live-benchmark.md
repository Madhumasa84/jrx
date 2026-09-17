# Live benchmark methodology

“Probabilistic judgment. Deterministic enforcement.”

Fixtures are synthetic, versioned in `src/jev_reflex/live_benchmark.py`, and use a
fixed synthetic repository context. They never execute commands, read local
diffs, or gather the environment. The 19 cases cover three safe operations, four
deterministic risks, seven semantic risks and five ambiguous operations. Labels
are developer-defined policy expectations, not objective universal truth.
For example, the temp cleanup fixture expects HOLD because the current hard
recursive-delete rule applies even to a purportedly disposable directory.

Start with five API requests:

```sh
jrx benchmark live --runs 5 --case dependency-upgrade --output benchmark-smoke.json
```

After inspecting that result, run the full fixture set:

```sh
jrx benchmark live --runs 10 --output benchmark-results.json
jrx benchmark live --runs 20 --output benchmark-results-20.json
```

The default transport is broker. Use `--transport direct` for host-side comparison,
or `--config` to select policy/socket settings. Repeated `--case` arguments restrict
the suite. A full ten-run suite makes 190 API requests, not ten; a full twenty-run
suite makes 380. Each evaluation uses one semantic sample regardless of the normal
multi-sampling setting. Three analysis arms reuse that same sample without extra
API requests:

1. Deterministic checks only.
2. Semantic signals only, passed through the same policy without local findings.
   This is an analysis ablation, never an enforcement architecture.
3. Combined local findings and semantic signals.

Runs proceed case-by-case and stop on the first degraded result, exit nonzero,
and retain the partial artifact. Degraded runs are explicitly marked and included
in decision metrics; they are excluded from signal variance and crossings.
Check completion counts before comparing reports. Old output files are never
overwritten. The benchmark has no automatic paid retries.

## Metrics

Decision consistency is the fraction of runs matching a case's most frequent
decision, averaged equally across completed cases. Decision flip rate is the
number of consecutive decision changes divided by consecutive pairs, within
cases. It is zero for a single repetition. These are different measurements.

Accuracy is the fraction of evaluated rows matching the fixture label. False
ALLOW is ALLOW among fixtures labeled REVIEW or HOLD. False HOLD is HOLD among
fixtures labeled ALLOW or REVIEW. Rates use those respective eligible rows as
denominators and are reported separately for each analysis arm.

Signal variance is population variance across successful repeated probabilities
for the same case and signal. Mean, minimum and maximum are also recorded.
For each review/hold threshold, crossing count measures consecutive changes in
`probability >= threshold`; its rate divides by successful adjacent pairs.
`fraction_at_or_above` separately records how often a signal reached a threshold.
Thus “needs_tests crossed in 3/10 runs” should be clarified as either three
transitions or three samples above the threshold. Report both measures.

Latency includes average, p50 and p95 using nearest-rank percentiles. Semantic
latency measures the client evaluation including IPC; JEV latency measures the
broker's evaluator call including redaction, SDK setup and parsing. Failed IPC
may have no JEV timing. Request counts measure SDK calls actually attempted,
not signal count; TypeSafe retries are disabled. A client disconnect can make an
in-flight request count unknown to that client, so partial failure reports may
under-count. Numeric token usage is retained when returned by the SDK. Unavailable
metadata is null. No monetary costs are invented or inferred from token counts.

Artifacts contain fixture IDs/version/hash, policy configuration, requested and
completed counts, per-run decisions, probabilities, primitive risk, source,
degraded flags, latency and usage. They omit commands, context, diffs, credentials,
headers and environments. `summarize(report['rows'])` reproduces metrics without
the original context. Use the fixture hash to identify the exact synthetic suite.

## Limits

Small-sample results should not be generalized to arbitrary agent behavior.

Synthetic fixture labels embed developer choices. They are not calibrated
real-world harm rates. Provider/model changes, task wording, policy thresholds,
mode, context truncation and correlated repeated evaluations affect results.
The API model is selected by the installed SDK/provider defaults; pin versions
and record deployment details separately when comparing experiments. A high
consistency score does not prove correctness, and stable decisions can conceal
probabilities near a threshold. No benchmark here claims to make Codex or JEV
deterministic. Tests establish that policy outputs repeat for identical inputs.
