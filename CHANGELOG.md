# Changelog

## [Unreleased]

### Security

- `runuser -u USER [--] COMMAND` payloads are inspected as local commands. The parser only understood the `-c` script form, so `runuser -u svc -- rm -rf ./cache` was a `REVIEW` for privileged execution instead of a `HOLD` for the recursive delete.
- A hook event whose tool arguments are neither an object nor text (a number, boolean or list) is denied as having no arguments; it used to be evaluated as an argument-less tool call that `enforce` mode let proceed. Found by the new bounded property tests (`tests/test_security_properties.py`), which also check that the shell parser splits words exactly as Bash does, that equivalent quoting gets the same decision, that protected-path writes stay protected after path normalization, and that every decision the evaluator records replays identically.
- Hook failures reach the host as denials. `jrx setup` writes `"onFailure": "block"` on the Claude Code hook, so a hook that cannot start, crashes before answering or times out blocks the call instead of letting it proceed (Claude Code 2.1.295 or later), and `jrx doctor` reports an existing hook without it as incomplete. Interrupts inside a hook (`KeyboardInterrupt`, `SystemExit`) now produce the adapter's deny response instead of a non-zero exit that Claude Code treats as non-blocking. The OpenRouter and Pi TypeScript bridges block on a non-zero exit, a non-object answer and a missing answer after `JRX_HOOK_TIMEOUT_MS` (default 30 s), no longer crash the host when jrx exits without reading its input, and deny an OpenRouter `PermissionRequest` in its own response shape. When jrx cannot read an OpenRouter event at all it now denies in both shapes (`block` and `decision: deny`); it used to answer in the `PreToolUse` shape only, which a `PermissionRequest` does not read.
- `REVIEW` no longer runs unattended in `enforce` mode. `jrx exec` asks for confirmation as it does in `review` mode (default no; non-interactive input counts as no), and `jrx check` exits 2. Hooks already asked (Claude Code, Antigravity, OpenRouter `PermissionRequest`) or denied (Codex, DeepSeek, Pi, OpenRouter `PreToolUse`). The rollout stage gate and `jrx policy impact` count only unattended execution, so `review` → `enforce` is no longer reported as a relaxation.
- A bootstrap is a trust anchor only when the evaluating user can neither rewrite it nor replace it through its directories (ownership, mode bits, sticky directories, symlinks, POSIX ACLs via `access(2)`; never as root or with a Linux capability that overrides file permissions). An operator-controlled bootstrap's `public_key_path` and `rollout_state_path` must be operator-controlled too, and rollout state may replace a policy file only when it is at least as protected as that file. Previously, with no `/etc/jrx/bootstrap.yaml`, a `~/.jev-reflex/bootstrap.yaml` written by the agent's user could name unsigned rollout state and turn an operator-owned `enforce` policy into `advisory`. Bootstrap, key and state bytes are read through the checked location. See [Trust anchors](docs/security.md#trust-anchors-which-files-the-evaluating-user-must-not-control).
- `jrx policy status --config FILE [--json]` reports which policy inputs the evaluating user could change and every trust refusal evaluation would raise.
- Rollout state (schema 2) stores each revision's exact signed bytes, detached signature, and trust root (`bootstrap` or `policy_source`). Every read verifies all revisions again, so editing the state file can no longer replace a signed `reflex.yaml`.
- Relative bootstrap `public_key_path` and `rollout_state_path` resolve against the bootstrap file's directory, not the agent's working directory.
- Security YAML rejects tags outside the JSON-compatible core schema (`!!set`, `!!omap`, `!!pairs`, `!!binary`, `!!timestamp`, unquoted dates, custom tags). `jrx policy lint` now uses the runtime loader, so it reports aliases and merge keys as errors.
- With `require_signature: true`, `check`, `exec` and hooks trust rollout state only where the evaluating user can neither rewrite nor replace it (file, parent directories and symlinks not owned or writable by that user; never when evaluating as root). Signatures prove a revision's contents, not which revision is active, the canary percentage or a rollback, so state the agent could edit now fails closed.
- `jrx policy rollout stage` compares effective enforcement: it rejects a candidate whose mode runs a decision class the baseline blocked (for example `enforce` → `advisory`) even when every replayed label is unchanged, and `--max-new-allows` counts replayed decisions that become `ALLOW` or newly executable. `jrx policy impact` with a limit fails on the same mode relaxations.
- Commands run through `su -c`/`runuser`, `ssh` and `docker`/`podman exec` are unwrapped: local payloads get every local rule, remote and container payloads keep destructive, Git and supply-chain rules without being judged as local paths, and all of them need at least review (`PRIVILEGED_EXECUTION`, `REMOTE_EXECUTION`, `CONTAINER_EXECUTION`). `ssh -o ProxyCommand/LocalCommand` values are judged as local commands.
- `tar -C`/`--directory`, `unzip -d` and `git apply` write destinations are checked against workspace and protected-path rules (`git apply` targets are read from the patch file). Archive members are not read, so extraction inside the workspace needs review; extraction into `.git`, `.github` or another control directory is held.
- `find … | xargs rm` without a narrowing test is held like `find … -delete`.
- The DeepSeek adapter denies `REVIEW` in `review` and `enforce` mode, because its Codex-compatible bridge cannot ask; it used to return only `additionalContext`, which let the call run unattended.
- Tier-0 shell analysis follows bash quoting: comment line continuations, brace and `$"…"` expansion, `bash -o … -c`, here-strings, `time`/`builtin`/`function` and more wrappers, grouped interpreter flags (`python -Ic`, `node -pe`, `perl -le`) and `source <(curl …)` no longer hide commands. Unresolved expansions in arguments now need REVIEW (`UNRESOLVED_EXPANSION`).
- Git, destructive, tamper, repo-boundary and secret checks close bypasses through unknown git global options, abbreviated long options, `find -delete`, `git push --mirror`/`:ref`, git execution settings (`gpg.program`, `--upload-pack`, `GIT_EXTERNAL_DIFF`, …), `sed -i.bak`, directory copy targets, `env -C`, `key=value` paths, `printenv SECRET`, `cat < .env`, MultiEdit/NotebookEdit/Antigravity write tools, and large proposed diffs that used to be truncated before the deterministic checks.
- The MCP gateway re-serializes every message instead of forwarding client bytes (a bare CR could smuggle a second `tools/call`), drops upstream responses that match no outstanding request id, and rejects reused in-flight ids.
- Hooks run without `--config` find `reflex.yaml` between the event's working directory and the repository root and deny when there is none, instead of falling back to advisory defaults. `jrx setup` pins `--config` and names every edit tool in the Claude matcher.
- Redaction runs in linear time on adversarial input and also covers URL userinfo, `sshpass -p`, `mysql -pPW`, `PGPASSWORD`, unterminated PEM keys, JSON-in-string credentials and nested structured secrets. `jrx audit verify` and the dashboard enforce `signing.require_signature` with the configured public key, without loading the private key, and reject duplicate-key or non-canonical records. Policy reload records carry their own `event_type`.
- `jrx model pull` installs a pinned revision of the default model and checks every file against a pinned SHA-256 digest; other models must match the hub's published digests.

### Added

- `python -B -m benchmarks.workloads` scores labeled agent workloads by host outcome (proceed, ask, deny) per adapter, mode and backend, reporting risky actions allowed, flagged and prevented, benign actions denied and sent for review, and latency, with counts, denominators and Wilson intervals. Holdout scoring requires independently labeled, authorized records, pinned file hashes and acceptance thresholds registered before scoring (`eval/workloads/README.md`). No independent holdout exists yet.
- `docs/guarantees.md` states what each integration stops, asks about or cannot see, checked against the tested enforcement matrix.

### Fixed

- Canary cohorts are keyed on the repository root, so every subdirectory of a repository gets the same revision.
- `jrx policy test -c FILE` tests `FILE`, even when rollout state exists.
- `jrx policy status` no longer prints fetch and override fields for a central source the runtime never polls. The docs now describe staged rollout as the only path from a central policy to runtime.
- Stability threshold crossings also count the review boundary for hold signals. `PolicyReloader` keeps the previous policy when the local override is invalid.

### Breaking / Upgrade Notes

- Re-run `jrx setup --provider claude --apply` so the Claude Code hook blocks on failure; until then `jrx doctor` reports it as incomplete. Copy the updated `examples/openrouter/jev-reflex.ts` and `examples/pi/jev-reflex.ts` into existing integrations.
- **`enforce` mode and `REVIEW`.** Scripts that relied on `jrx exec` running `REVIEW` actions in `enforce` mode now get a confirmation prompt, and exit 2 without a terminal. Pass `--yes` where the invoker's confirmation is intended (refused under strict review), or set `rule_modes` so the rule behind the `REVIEW` is advisory. Wrappers that used `jrx check`'s exit status treat `REVIEW` as blocked; read `--json` `decision` to ask the user instead.
- **Trust anchors.** Three configurations that silently trusted inputs the agent's user could change now stop evaluation (hooks deny) with a message naming the path: (1) an operator-controlled bootstrap with `require_signature: true` whose `public_key_path` the evaluating user can write or replace: install the key root-owned, mode `0644`, for example in `/etc/jrx`; (2) an operator-controlled bootstrap naming `rollout_state_path` the evaluating user can change, with or without signatures: move the state to an operator directory such as `/var/lib/jrx` and run `jrx policy rollout stage --bootstrap /etc/jrx/bootstrap.yaml ...` there, or remove `rollout_state_path`; (3) a bootstrap the evaluating user can write naming user-writable rollout state over a `--config` policy the user cannot write: move the bootstrap and state under operator control, or remove `rollout_state_path`. Run `jrx policy status --config FILE` as the agent's user to check before upgrading. Same-user installations, where the agent's user owns the policy, bootstrap and state, behave as before.
- Bootstrap files must be readable by the evaluating user: use root-owned mode `0644`, not `0600` as earlier docs advised.
- With `require_signature: true`, rollout state written by earlier releases has no signature material and stops evaluation (fail-closed). Remove the state file and run `jrx policy rollout stage --bootstrap FILE --baseline reflex.yaml --audit LOG` again. Without `require_signature`, existing state keeps working and is upgraded on the next change.
- Hook commands installed by earlier releases are not pinned to a policy file. Re-run `jrx setup --provider NAME --apply` for each provider (`codex`, `claude` or `antigravity`) and confirm the change, so the hooks pass `--config`; without `--apply` setup only previews. Until then a hook that cannot find `reflex.yaml` denies.
- A default-model cache pulled from an unpinned revision fails `jrx model verify` until `jrx model pull` installs the pinned release.
- Audit logs that mix unsigned and signed records fail verification once `signing.public_key_path` is configured.
- **Staged rollout with `require_signature: true`:** keep the state in a directory only the operator can write, for example `sudo install -d -o root -g root -m 0755 /var/lib/jrx` with `rollout_state_path: /var/lib/jrx/policy-rollout.json` in `/etc/jrx/bootstrap.yaml`, and run `jrx policy rollout stage|promote|rollback --bootstrap /etc/jrx/bootstrap.yaml` as that operator. State in a directory the agent's user owns or can write (for example under `~/.jev-reflex`) now stops evaluation with a message naming the path; move it and stage again, or remove `rollout_state_path` to use the signed `reflex.yaml`. Evaluators running as root cannot use staged rollout with required signatures. Without `require_signature`, same-user state keeps working.
- Rollout state is now written `0644` by default so an evaluator running as another user can read it; an existing narrower mode is kept, so `chmod 0644` state written by earlier releases (`0600`) when the operator and the evaluating user differ. Group- or world-writable state is rejected.
- `jrx policy rollout stage` no longer stages mode downgrades such as `enforce` → `advisory`; deploy such a change deliberately as a signed `reflex.yaml` after removing the rollout state.
- New `REVIEW` results: `ssh` and `docker`/`podman exec` commands, `su`/`runuser`, archive extraction inside the workspace, and unreadable or stdin `git apply` patches. DeepSeek users see these and other `REVIEW` results as denials.

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
