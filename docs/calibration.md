# Calibration logging

Calibration is optional and off by default. Enable it in `reflex.yaml`:

```yaml
calibration:
  enabled: true
  # Optional; defaults to ~/.jev-reflex/events.jsonl
  # path: ~/.jev-reflex/events.jsonl
```

When enabled, each result records only:

- timestamp
- anonymous decision ID
- signal probabilities
- policy decision
- risk choice
- optional user feedback

It never records command contents, code, diffs, repository paths, raw model responses, API keys, or secrets.

Use the decision ID printed by `check`:

```console
$ jev-reflex feedback 0123456789abcdef --correct
$ jev-reflex feedback 0123456789abcdef --incorrect
$ jev-reflex calibration
```

The summary reports labeled cases, overall feedback accuracy for cases with a strong (`>=0.90`) signal, accuracy for the review band (`0.70–0.90`), false high-confidence feedback, and a simple per-signal view for signals that were at least `0.70`. These figures describe user feedback about decisions; they are not a claim that individual signal labels are ground truth.

For repeated-request behavior, use `jev-reflex stability` instead. Stability
reports observed final-decision consistency and semantic signal variance; they
are separate from calibration feedback and do not imply that JEV itself is
deterministic.
