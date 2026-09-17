# Host broker protocol and operations

The broker implements `SemanticEvaluator`. Local deterministic checks run before
IPC, and the existing pure policy runs after validated probabilities return.
Neither the broker's response nor external context can supply the local policy.
The broker has no execution endpoint and never gathers files or runs commands
specified in a request. Standalone direct evaluation remains supported.

## Start and configure

In a trusted host terminal, supply `TYPESAFE_API_KEY` through your normal secret
manager or shell environment, then run:

```sh
jrx broker run
# Or detached, inheriting the host environment:
jrx broker start
jrx broker status --json
jrx broker stop
```

All commands also work with `jev-reflex`. `start` detaches a Python process with
closed inherited descriptors and stdio redirected to `/dev/null`. It checks
readiness for five seconds. It does not install a boot service or restart
automatically. Use `run` with `JRX_DEBUG=1` for safe diagnostic logs.
`stop` addresses the socket, not an untrusted PID file. A user-only lock file
remains after shutdown; the socket is removed. Startup recovers a stale socket
only after obtaining the lifecycle lock and checking that no listener exists.

Use a trusted configuration file for the hook:

```yaml
mode: enforce
jev:
  transport: broker
  socket: ~/.jev-reflex/reflex.sock
  connect_timeout: 1
  request_timeout: 25
  api_timeout: 20
```

Set the hook command to `jev-reflex codex-hook --config /absolute/path/reflex.yaml`.
An example is in `examples/reflex.broker.yaml`. The standalone default remains
`direct` for compatibility; configured hooks select `broker` with no direct
fallback. `--demo` and `--no-jev` continue to work without a broker.

```sh
env -u TYPESAFE_API_KEY jrx check --transport broker --command 'python migrate.py'
jrx check --transport direct --command 'python migrate.py'
```

Custom endpoints use `broker run --socket /absolute/private-directory/reflex.sock`
and the same `jev.socket` in client configuration. Only Unix sockets are supported;
the `BrokerClient` semantic interface is the extension point for future transports.

## Version 1 wire contract

One UTF-8 JSON object followed by a newline per connection. Requests and responses
are limited to 262,144 bytes including the newline. Request IDs contain 1–64 ASCII
letters, digits, underscores or hyphens. Unknown protocol versions are rejected.

```json
{"protocol_version":1,"request_id":"example-1","operation":"evaluate","action":{"type":"shell_command","argv":["pip","install","--upgrade","some-package"]},"context":{"user_task":"Upgrade a runtime dependency","repository":"example","working_directory":"/work/example","changed_files":[],"git_diff":"","test_results":""}}
```

`operation` defaults to `evaluate`. Context fields follow `EvaluationContext`
without `proposed_action`; the top-level `action` supplies it. Optional context
fields include `repository_root`, `recent_context` and `external_content`.

Successful evaluation returns primitive semantic data, not an enforcement decision:

```json
{"protocol_version":1,"request_id":"example-1","status":"ok","signals":{"dependency_risk":0.88},"risk":{"choice":"medium","score":1.0,"confidence":0.95},"degraded":false,"source":"live_jev","api_requests":1,"jev_latency_ms":350.0,"usage":{"input_tokens":1000,"output_tokens":100}}
```

The example abbreviates `signals`; the actual client requires all 18 known JEV
signals, validates finite probabilities in [0,1], and rejects unknown signal names.
Risk retains the existing structured choice/score/confidence contract. Local
evaluation output adds findings, triggered rules and ALLOW/REVIEW/HOLD using
existing deterministic policy. A successful broker-backed result is identified
as `semantic_source: "broker/live"`; human output says `LIVE JEV VIA BROKER`.

Errors contain only fixed codes, protocol version, validated request ID, request
count and `degraded: true`. Codes include `INVALID_REQUEST`, `REQUEST_TOO_LARGE`,
`UNSUPPORTED_PROTOCOL`, `TIMEOUT`, `BUSY`, and `JEV_UNAVAILABLE`. An invalid ID is
never reflected. `health` reports PID and whether a credential is configured;
it makes no paid API call and does not prove API connectivity. `stop` requests
service shutdown. Future versions can add authentication without changing the
semantic evaluator interface.

## Boundaries and failure behavior

The parent directory must be current-user-owned, non-symlinked and mode 0700.
The socket is created under a restrictive umask and set to 0600; both peers check
ownership and permissions. Existing unsafe directories/sockets are rejected,
not silently repaired. No TCP port is opened. Filesystem permissions authenticate
the current OS user, not individual processes belonging to that user.

Only the trusted host broker's direct evaluator needs the credential. The client
does not read it, transmit it, load `.env`, or fall back to a credential-dependent
backend. Start Codex with `env -u TYPESAFE_API_KEY codex`. Keep credential files
outside its readable filesystem, and keep host process environments inaccessible
from its sandbox. Same-user socket permissions alone cannot isolate a key from
an unsandboxed same-user attacker with access to `/proc`, a debugger, or secret
files. This service does not configure those OS boundaries for you.

Client redaction occurs before IPC, and broker redaction occurs again before JEV.
The existing context character limit also bounds API state. Pattern redaction is
best effort; avoid supplying arbitrary confidential material. Normal operation
does not persist requests. Debug logging uses IDs, numeric counts/timings,
probabilities and policy decisions; never commands, diffs, headers or environment
dumps. SDK exception details are discarded.

Defaults allow one second to connect, 25 seconds for a whole socket response,
and 20 seconds for the API worker. SDK HTTP operations also have a timeout and
automatic retries are disabled. Sixteen simultaneous IPC handlers and one API
worker are admitted. A timed-out worker retains its slot until it finishes;
subsequent evaluations return BUSY rather than accumulating workers. A daemon
thread cannot forcibly cancel a blocked SDK operation; process shutdown can.
Increase the host hook timeout when increasing samples or client timeouts.

Failures yield degraded REVIEW unless a local hard check already produces HOLD.
Advisory hooks attach a warning and continue; review hooks deny REVIEW/HOLD;
enforce hooks deny HOLD and every degraded result. Healthy semantic REVIEW in
enforce mode preserves existing behavior: the agent's normal permission system
still handles approval. Use review mode to deny every REVIEW at the hook.

The agent sandbox must permit connecting to the selected Unix socket. Some
sandboxes restrict Unix IPC as well as outbound networking. Verify from the actual
hook environment. A successful unsandboxed CLI call is not proof of nested Codex
connectivity. Use a narrowly scoped, host-supported socket allowance where
available; this project does not disable sandboxing or switch to public TCP.

## Acceptance smoke test

Terminal A: start `jrx broker run` with the host credential configured. Terminal B:

```sh
env -u TYPESAFE_API_KEY jrx broker status --json
env -u TYPESAFE_API_KEY jrx check --transport broker --command 'pip install --upgrade some-package' --json
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"pip install --upgrade some-package"}}' |
  env -u TYPESAFE_API_KEY jrx codex-hook --config examples/reflex.broker.yaml
```

Require REVIEW, `semantic_source: "broker/live"`, `degraded: false`, and a live
dependency-risk probability. The hook explanation must include `LIVE JEV VIA
BROKER`. Then repeat via an actual Codex PreToolUse invocation in the intended
sandbox; invoking the adapter manually alone does not establish that last step.
These commands analyze the proposed package installation and never execute it.

Host-side opt-in test (two paid requests, automatically skipped otherwise):

```sh
JEV_REFLEX_LIVE_TEST=1 pytest tests/integration/test_live_broker.py
```
