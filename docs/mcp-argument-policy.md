# MCP argument policies

An MCP rule may define the argument shape a tool is allowed to receive and limit
specific argument values. JRX checks both before building evaluation context, calling
the semantic evaluator, or forwarding a request to the upstream MCP server.

```yaml
mcp:
  tools:
    - server: cloud
      name: storage.list_objects
      effect: read
      expected_input_schema_sha256: 67159cb0f0f5c316ab5a757885a5be57a42340109a42e115419590eb4d3da2c5
      argument_schema:
        type: object
        required: [account, bucket, prefix]
        properties:
          account: {type: string}
          bucket: {type: string, minLength: 1, maxLength: 63}
          prefix: {type: string, maxLength: 512}
        additionalProperties: false
      argument_constraints:
        /account: [development]
        /bucket: [test-artifacts, build-cache]
```

`argument_schema` uses JSON Schema Draft 2020-12. JRX rejects invalid policy schemas
when it loads the configuration, and rejects tool calls that fail schema validation.
Set `additionalProperties: false` to ensure a caller cannot add unreviewed fields.
Schema formats such as `date-time` are checked. Local `$ref` references are supported;
remote references are rejected so tool calls cannot cause schema loading from the
network.

Each `argument_constraints` key is a JSON Pointer into the argument object. Its value
must be one of the listed JSON scalar values. Constraints reject missing paths and
compare booleans separately from numbers. Array positions can be addressed by their
numeric index, for example `/operations/0/account`. Keep the schema and constraints
aligned when a tool server changes its argument format.

For tools whose upstream schema must remain unchanged, set
`expected_input_schema_sha256` to the SHA-256 digest of the canonical JSON `inputSchema`
returned by `tools/list`. JRX blocks calls until it has observed a matching catalog
schema. A changed schema or missing pinned tool causes the catalog request to fail and
all pins from that catalog scan are revoked. Catalog-change notifications also revoke
trust until a new catalog is verified. Malformed catalog entries produce a protocol
error without stopping the gateway reader. Non-finite JSON numbers are rejected before
argument validation. Compute the digest with:

```bash
python -c 'import hashlib,json; schema={"type":"object","properties":{"account":{"type":"string"}}}; data=json.dumps(schema,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode(); print(hashlib.sha256(data).hexdigest())'
```

JRX checks the schema when the gateway receives `tools/list`; the upstream tool server
remains part of the operator's trust boundary.

Rules without these fields retain the existing allow-by-tool-name behavior. A tool
still needs an explicit `(server, name)` rule, and the existing `effect` checks,
deterministic checks, semantic evaluation, and session limits continue to apply.

## Human approval for write tools

With [enterprise access configured](../README.md#verified-identity-and-reviewed-execution),
set `require_approval: true` on the specific write rule.

```yaml
mcp:
  use_jev: true
  tools:
    - server: github-demo
      name: publish_release
      effect: write
      require_approval: true
      argument_constraints:
        /repository: [example/widgets]
```

Send a plain MCP `tools/call` with the tool name and arguments. Once all policy checks
pass, including a live semantic ALLOW, JRX returns
`structuredContent: {"status":"pending_approval","approval_id":"..."}`. At this point
JRX has sent zero calls to the server. Reviewers use their own host-provided OIDC
tokens to inspect the request and grant approval.

```bash
jrx approval pending --config reflex.yaml
jrx approval grant APPROVAL_ID --config reflex.yaml
```

The queue shows the requester, authorized local repository, environment, and a JSON
summary with the server, tool, and complete arguments. Approval uses the existing
expiry and review quorum, including two distinct reviewers in production. The
complete serialized summary must fit in the existing 1,000-character review limit
and pass secret redaction checks. JRX rejects secret-looking argument keys at any
depth before semantic evaluation, including keys that hold lists, objects, or numbers.

The trusted host starts a retry gateway with the original requester's OIDC identity
and passes `--approval-id APPROVAL_ID` before the upstream command separator.
Retry the same call on that gateway with a fresh string or integer request ID. JRX checks the
effective policy loaded at startup, reruns evaluation and authorization, and
consumes the matching approval before dispatch. JSON object member order is
irrelevant. Keep values, types, array order, and the spelling of numbers unchanged.
The reference is a gateway option. Approval-enabled calls accept `name` and optional
`arguments` as the MCP tool parameters.

For a changed request, start a gateway without the old reference to request fresh
approval. If a dispatched write has no upstream reply, JRX reports
`outcome_unknown` and the existing reference stays spent. Check the upstream state
before requesting approval for another attempt.

Run the offline release demo to see the policy, request, reviewer commands, and
recorded stdio call. The demo substitutes local identity and semantic stubs.

```bash
python examples/mcp_release_approval.py
```

The gateway tests exercise an allowed development database call, reject extra
arguments and a production database target, verify that schema changes block calls,
and check that the upstream server only receives allowed calls:

```bash
.venv/bin/python -m pytest tests/test_enterprise_approval.py tests/test_mcp_argument_policy.py tests/test_mcp_schema_pin.py tests/test_mcp_session.py
```

On POSIX, the gateway starts the upstream server in its own process group. Gateway
exit, interrupted input, a tool execution timeout, or session stop terminates that
group and kills remaining group
members, including children that ignore termination. A descendant that deliberately
creates a separate session or process group escapes this cleanup boundary; use an
OS sandbox when process isolation is required.
