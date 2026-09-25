# Multi-stage Dockerfile for JEV Reflex (jrx) broker
# Stage 1: Build with full dependencies
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .

# Install the package with runtime dependencies only
RUN pip install --no-cache-dir --prefix /install .

# Bundle the optional deep secret scanner in the production image. Verify
# the upstream archive before placing the binary in the copied install tree.
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) asset=linux_x64; checksum=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;; \
      arm64) asset=linux_arm64; checksum=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;; \
      *) echo "unsupported gitleaks architecture" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_${asset}.tar.gz" -o /tmp/gitleaks.tar.gz; \
    echo "${checksum}  /tmp/gitleaks.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tar.gz -C /install/bin gitleaks

# Stage 2: Runtime image with minimal dependencies
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r jrx && useradd -r -g jrx jrx

# Install runtime dependencies only (cryptography may need system libs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed package from builder
COPY --from=builder /install /usr/local
RUN gitleaks version

# Create directory for broker socket and data
RUN mkdir -p /home/jrx/.jev-reflex && \
    chmod 700 /home/jrx/.jev-reflex && \
    chown -R jrx:jrx /home/jrx/.jev-reflex

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    JRX_DEBUG=0 \
    PATH="/usr/local/bin:$PATH"

# Switch to non-root user
USER jrx
WORKDIR /home/jrx

# Expose metrics port
EXPOSE 9090

# For TLS transport, expose broker port
EXPOSE 8443

# Health check using the broker CLI
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD jrx broker status --json || exit 1

# Default entrypoint: run the broker
ENTRYPOINT ["jrx", "broker", "run"]

# Allow configuration via environment variables
# TYPESAFE_API_KEY: Required for live JEV semantic evaluations
# JRX_DEBUG: Debug mode (1 to enable, 0 to disable)
# JRX_MODE: Execution mode (advisory, review, enforce)
# JRX_TRANSPORT: Transport type (direct, broker, broker-tls)
# JRX_SOCKET: Socket path for unix domain socket transport
# JRX_METRICS_HOST: Metrics HTTP server host (default: 127.0.0.1)
# JRX_METRICS_PORT: Metrics HTTP server port (default: 9090)
# JRX_BROKER_TLS_LISTEN_ADDR: Listen address for TLS transport (default: 0.0.0.0:8443)
# JRX_BROKER_TLS_CERT_PATH: Path to TLS certificate file
# JRX_BROKER_TLS_KEY_PATH: Path to TLS private key file
# JRX_BROKER_TLS_CLIENT_CA_PATH: Path to TLS client CA file
