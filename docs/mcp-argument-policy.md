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

The gateway tests exercise an allowed development database call, reject extra
arguments and a production database target, verify that schema changes block calls,
and check that the upstream server only receives allowed calls:

```bash
.venv/bin/python -m pytest tests/test_mcp_argument_policy.py tests/test_mcp_schema_pin.py tests/test_mcp_session.py
```
