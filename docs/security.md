# Security and threat model

JEV Reflex runs on an execution boundary. The design goal is probabilistic
semantic judgment wrapped in deterministic local policy, not a claim that JEV
or a coding agent is deterministic or that a model can make agents safe.

## Assets

- TypeSafe API keys and other credentials in command text, diffs, environment-derived output, or retrieved content.
- Repository source, paths, diffs, and persistent state.
- The integrity of the host agent’s permission and execution flow.
- User intent and the configured hard/review rules.

## Trust boundaries

1. The user and host agent provide the task and proposed action.
2. Repository files, diffs, tests, transcripts, and retrieved content are treated as untrusted data.
3. `redaction.py` and `context.py` deterministically bound and sanitize state before the TypeSafe gateway.
4. TypeSafe returns advisory structured judgments; repeated responses can vary.
5. Deterministic checks identify obvious local hazards without JEV.
6. `policy.py` is trusted local code and decides `ALLOW`, `REVIEW`, or `HOLD` from fixed configuration, structured findings, and normalized numbers.
7. The host agent or wrapper decides whether to execute after the policy result.

Configuration is loaded separately from evaluated state. Text inside a command, diff, or retrieved document cannot change `hold_on`, `review_on`, thresholds, or mode.

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Secret sent to TypeSafe | Redact before API calls, logs, hook output, and calibration; common credential flags, URL query keys, and secret-looking object fields are covered; only `TYPESAFE_API_KEY` is read for authentication. |
| Prompt injection in retrieved content | Supply it in an explicit untrusted field; every question says not to follow state instructions; policy is local and deterministic. |
| Destructive command | Obvious forms, including recursive `rm` through common wrappers and shell evaluation, produce a deterministic hard finding; semantic destructive signals also hold at the configured threshold. Native hooks or the enforce wrapper stop the resulting `HOLD`. |
| API/network failure | Advisory mode warns; review/enforce produce degraded `REVIEW`; non-advisory `exec` does not run degraded results. |
| Shell metacharacter injection | `exec` uses a preserved argv list and `shell=False`; `--command` is parsed once with `shlex`. |
| Malformed model response | Missing/wrong/out-of-range answers are rejected; no partial model output becomes policy approval. Non-advisory modes fail closed to `REVIEW`. |
| Wrong repository or symlink path | Working directories are canonicalized before Git inspection and execution; repository context is bounded. |
| Calibration data leakage | Events contain only timestamp, anonymous ID, probabilities, policy decision, risk choice, and feedback. |
| Hook bypass | Documented as a limitation; retain the host sandbox/permission system and use wrappers for surfaces without supported hooks. |

The wrapper canonicalizes the working directory for context collection and again uses that
canonical path for child execution. This reduces path ambiguity, but no user-space pre-check can
eliminate races if another process changes files or links between evaluation and execution.

## Redaction limits

Redaction detects common API keys, bearer headers, GitHub tokens, AWS access keys, private-key blocks, password/token/secret assignments, credential flags such as `--user` and `--secret-access-key`, URL query keys, and secret-looking object fields. It is heuristic. Do not use JEV Reflex as a guarantee that arbitrary high-entropy secrets or sensitive business data will be removed. Avoid putting secrets in command arguments in the first place.

`TYPESAFE_API_KEY` is passed to the official SDK only as the authentication credential. Its value is never placed in the model-facing state, result, logs, or events.

## Policy and stability limits

Probabilities are not proofs. Thresholds can be overridden, JEV can be wrong,
and a low score does not make an action safe. Identical policy inputs produce
identical policy outputs, but identical JEV requests may produce different
inputs. Stability reports measure observed final-decision consistency; they do
not establish model determinism or security. Hard rules are the deterministic
first layer, but users still need ordinary code review, tests, least
privilege, sandboxing, and backups.

Native hook coverage follows the host agent’s current interfaces. A specialized or hosted tool may bypass a local hook. Enforce mode should therefore be paired with the host’s own permission and sandbox controls.

## Reporting

If you find a secret-handling bug, do not include the secret in a public issue. Rotate the credential, describe the pattern generically, and report the problem through the project’s private security channel if one is configured.
