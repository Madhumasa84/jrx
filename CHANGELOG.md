# Changelog

## [0.3.0]

### Added

- Run the Apache-2.0 `coba-68m-ternary` model on CPU with `jev-reflex[local]`. The Host Broker can keep the ONNX model warm over Unix sockets or mTLS without `TYPESAFE_API_KEY`.
- Download, inspect, and verify local models with `jrx model pull`, `jrx model status`, and `jrx model verify`. The model loader uses `O_NOFOLLOW` and SHA-256 verification of the exact bytes consumed by the runtime.
- Generate `dev-safe`, `strict-ci`, `enterprise`, or `production` policies with `jrx init --preset`. Validate deployment controls offline with `jrx policy lint --profile production`.
- Set per-rule `rule_modes` and use hardened Tier-0 shell, Git, supply-chain, and protected-file checks. Sessions can detect protected-file drift and track credentials seen in PostToolUse results.
- Run the 300-case frozen offline benchmark suite with deterministic or local semantic evaluation. [Benchmark results and reproduction](benchmarks/RESULTS.md)

### Changed / Security

- Production enforces strict REVIEW with an action-bound, single-use approval from two independent reviewers. JRX rejects `--yes` and self-reported approvers.
- `audit.fail_closed` blocks dispatch when a required decision, override, or approval consumption record cannot be persisted.
- Linux broker clients verify the live peer UID over owner-only Unix sockets created with mode `0600`.
- Deferred CLI imports keep `onnxruntime`, `numpy`, `tokenizers`, and `huggingface_hub` out of CLI startup and `jrx check --no-jev`.

### Breaking / Upgrade Notes

- Reissue approvals created under `enforce` mode before upgrading. In v0.3.0 the approval binding includes the sanitized execution environment.

[v0.3.0 release and publication notes](docs/releases/v0.3.0.md) · [v0.2.0 release notes](docs/releases/v0.2.0.md)
