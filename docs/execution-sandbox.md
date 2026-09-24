# Isolated command execution

`jrx exec` can run an approved command in a Docker container. The feature is opt-in;
without `sandbox.enabled`, command execution keeps its existing host behavior. When it
is enabled, Docker startup failures block the command and JRX never falls back to
running it on the host.

```yaml
mode: enforce
sandbox:
  enabled: true
  # Use trusted images pinned by digest for production deployments.
  image: "python:3.12-slim@sha256:REPLACE_WITH_VERIFIED_DIGEST"
  # Optional stronger OCI runtime, if installed in Docker (for example, runsc).
  # runtime: runsc
  memory_limit: 1g
  cpus: 2
  pids_limit: 256
  tmp_size: 256m
  max_execution_seconds: 300
  # Optional controlled outbound access through a short-lived proxy.
  # proxy_image: "python:3.12-slim@sha256:REPLACE_WITH_VERIFIED_DIGEST"
  # allowed_hosts: [pypi.org, files.pythonhosted.org]
  # allowed_ports: [443]
  # Permit private IP destinations only when a task needs them.
  # allowed_private_networks: [10.20.0.0/16]
```

Build or pull the image with the tools and dependencies required by the command before
starting JRX; JRX uses Docker's `--pull=never` option and will not contact a registry.
Then run
`jrx exec --config reflex.yaml --cwd /path/to/repository -- python -m pytest`. The
container receives the repository as its only host bind mount, at the same absolute
path, with write access so normal build and edit commands keep their path behavior.
The container runs as the invoking host UID and GID. It receives no host environment
variables, uses a read-only container root, drops Linux capabilities, enables
`no-new-privileges`, and has configured CPU, memory, PID, `/tmp`, and wall-clock limits.
Set `sandbox.runtime` to a trusted installed runtime such as gVisor when available.

By default, the sandbox has no network and external DNS lookup fails. To permit selected
outbound connections, set `proxy_image`, `allowed_hosts`, and `allowed_ports`. JRX starts
a short-lived CONNECT proxy for that command and places it on a private isolated network
with the sandbox. The proxy accepts only the exact configured hostnames and ports. Public
destinations are allowed; private destinations are denied unless their address is in an
explicit `allowed_private_networks` CIDR. The sandbox cannot connect to those targets
directly, and its DNS requests are not forwarded externally. `host.docker.internal` is
available inside the proxy for an explicitly configured host-gateway destination.
Allowlisting hostnames that use redirects or CDNs may require adding those hostnames too.
Use Docker Engine 28 or newer for the isolated gateway mode; JRX checks the daemon
version before creating egress resources. Explicit port lists replace the default port
443. Multicast, loopback, and link-local destinations remain blocked. Both configured images must
already be cached because JRX uses Docker's `--pull=never` option.

The repository mount is intentionally writable and includes files in the repository,
including ignored files; keep credentials outside the workspace. The container shares
the host kernel unless a stronger runtime is configured, and Docker daemon access and
kernel vulnerabilities remain in the trust boundary. This protects the host filesystem
outside the mounted workspace from ordinary container commands; it is not a substitute
for a VM or a hardened container runtime against kernel-level attacks.

JRX does not sandbox commands launched by agent hooks or upstream MCP servers in this
release. Configure those host integrations and their own isolation controls separately.

## End-to-end test

The integration test runs real Docker containers and checks workspace writes,
read-only root behavior, default network isolation, allowlisted proxy access, blocked
direct routes, and that host environment variables are not passed into the container.
Provide locally cached test images and a usable Docker Engine 28+ daemon:

```bash
JRX_TEST_DOCKER_IMAGE=python:3.12-slim .venv/bin/python -m pytest \
  tests/integration/test_docker_sandbox.py
```
