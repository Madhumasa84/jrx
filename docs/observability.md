# Observability and Monitoring

JEV Reflex provides built-in observability through Prometheus metrics and structured JSON logging to help you monitor the health and performance of your policy enforcement in production.

## Metrics

The broker exposes a `/metrics` endpoint (Prometheus exposition format) on a lightweight HTTP server. By default, it binds to `127.0.0.1:9090` for security, but this can be configured.

### Starting the Broker with Metrics

```bash
# Default metrics endpoint (127.0.0.1:9090)
jrx broker run

# Custom metrics endpoint
jrx broker run --metrics-host 0.0.0.0 --metrics-port 9091

# For detached daemon
jrx broker start --metrics-host 0.0.0.0 --metrics-port 9091
```

### Available Metrics

#### Decision Metrics

**`jrx_decisions_total`** (Counter)
- Total number of policy decisions made
- Labels: `decision` (allow|review|hold)
- Use for: Overall decision rate, decision distribution

```promql
# Decision rate per second
rate(jrx_decisions_total[5m])

# Decision distribution
sum by (decision) (jrx_decisions_total)
```

**`jrx_hard_rule_triggers_total`** (Counter)
- Total number of hard rule triggers
- Labels: `rule_name` (e.g., destructive, secret_exposure)
- Use for: Hard rule frequency, security event tracking

```promql
# Hard rule trigger rate
rate(jrx_hard_rule_triggers_total[5m])

# Top triggered rules
topk(10, sum by (rule_name) (jrx_hard_rule_triggers_total))
```

#### Performance Metrics

**`jrx_jev_signal_latency_seconds`** (Histogram)
- Latency of JEV semantic signal requests in seconds
- Buckets: 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, +Inf
- Use for: JEV API performance, latency SLA monitoring

```promql
# P99 latency
histogram_quantile(0.99, sum(rate(jrx_jev_signal_latency_seconds_bucket[5m])) by (le))

# Average latency
rate(jrx_jev_signal_latency_seconds_sum[5m]) / rate(jrx_jev_signal_latency_seconds_count[5m])

# Latency rate over time
rate(jrx_jev_signal_latency_seconds_sum[5m])
```

#### Health Metrics

**`jrx_degraded_evaluations_total`** (Counter)
- Total number of degraded evaluations
- Labels: `reason` (jev_unavailable, gitleaks_failed)
- Use for: System health, fail-open detection

```promql
# Degraded evaluation rate
rate(jrx_degraded_evaluations_total[5m])

# Degraded evaluation by reason
sum by (reason) (jrx_degraded_evaluations_total)
```

**`jrx_policy_reload_total`** (Counter)
- Total number of policy reload attempts
- Labels: `result` (success|failure)
- Use for: Policy deployment tracking

```promql
# Policy reload success rate
sum by (result) (rate(jrx_policy_reload_total[5m]))
```

**`jrx_broker_uptime_seconds`** (Gauge)
- Broker uptime in seconds
- Use for: Broker availability, restart detection

```promql
# Broker uptime
jrx_broker_uptime_seconds

# Broker restart detection (uptime < 60 seconds)
jrx_broker_uptime_seconds < 60
```

## Structured Logging

JEV Reflex outputs structured JSON logs with automatic secret redaction. Logs include:

- `timestamp`: ISO 8601 timestamp in UTC
- `level`: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `event`: Event description
- `fields`: Additional structured context

### Configuration

Add to your `reflex.yaml`:

```yaml
logging:
  enabled: true
  sink: stdout  # stdout | syslog | webhook-url
  level: INFO  # DEBUG | INFO | WARNING | ERROR | CRITICAL
  webhook_url: null  # Required if sink=webhook-url
  syslog_ident: "jrx"  # Program identifier for syslog
```

### Log Sinks

#### Stdout (Default)
Logs to stdout in JSON lines format. Ideal for containerized environments with log aggregators.

```yaml
logging:
  sink: stdout
```

#### Syslog
Logs to syslog via Unix socket or UDP. Ideal for traditional infrastructure.

```yaml
logging:
  sink: syslog
  syslog_ident: "jrx"
```

#### Webhook URL
Logs to an HTTP webhook endpoint with fire-and-forget delivery, retry/backoff, and bounded queue. Ideal for SIEM integration.

```yaml
logging:
  sink: webhook-url
  webhook_url: "https://your-siem.example.com/logs/jrx"
```

**Webhook Features:**
- Fire-and-forget: Never blocks decision-making
- Bounded queue: Default 1000 entries, drops oldest when full
- Retry with exponential backoff: Up to 3 retries with 2^n second delays
- HTTP POST with JSON payload
- 5-second timeout per request

### Example Log Lines

**Policy Decision:**
```json
{
  "timestamp": "2024-01-15T10:30:45.123456Z",
  "level": "INFO",
  "event": "policy_decision",
  "fields": {
    "decision": "ALLOW",
    "action": "pytest tests/",
    "degraded": false,
    "semantic_source": "jev",
    "triggered_rules": []
  }
}
```

**Broker Started:**
```json
{
  "timestamp": "2024-01-15T10:30:00.000000Z",
  "level": "INFO",
  "event": "broker_started",
  "fields": {
    "pid": 12345,
    "jev_configured": true,
    "socket": "/home/user/.jev-reflex/reflex.sock",
    "metrics_endpoint": "http://127.0.0.1:9090/metrics"
  }
}
```

**Hard Rule Trigger:**
```json
{
  "timestamp": "2024-01-15T10:31:00.000000Z",
  "level": "WARNING",
  "event": "broker_request_timeout",
  "fields": {
    "request_id": "abc123def456"
  }
}
```

**Degraded Evaluation:**
```json
{
  "timestamp": "2024-01-15T10:32:00.000000Z",
  "level": "ERROR",
  "event": "broker_evaluation_error",
  "fields": {
    "request_id": "xyz789",
    "evaluating": true
  }
}
```

### Secret Redaction

All log entries are automatically redacted before output:
- API keys, tokens, and passwords
- Private keys and certificates
- Authorization headers
- Bearer tokens
- AWS/GitHub/other service tokens
- Shell secrets and environment variable references

**Example with secrets:**
```json
{
  "timestamp": "2024-01-15T10:30:45.123456Z",
  "level": "INFO",
  "event": "policy_decision",
  "fields": {
    "decision": "REVIEW",
    "action": "curl -H \"Authorization: Bearer <REDACTED_SECRET>\" https://api.example.com",
    "degraded": false,
    "semantic_source": "jev"
  }
}
```

## Grafana Dashboard Examples

### Panel 1: Decision Rate

**Title:** Decision Rate
**Query:**
```promql
sum(rate(jrx_decisions_total[5m]))
```
**Visualization:** Time series
**Unit:** reqps (requests per second)

### Panel 2: Decision Distribution

**Title:** Decision Distribution
**Query:**
```promql
sum by (decision) (rate(jrx_decisions_total[5m]))
```
**Visualization:** Time series with stacked bars
**Legend:** allow, review, hold

### Panel 3: HOLD Rate Trend

**Title:** HOLD Rate Trend
**Query:**
```promql
rate(jrx_decisions_total{decision="hold"}[5m]) / sum(rate(jrx_decisions_total[5m]))
```
**Visualization:** Time series
**Unit:** percent (0-100)
**Thresholds:** Warning at 5%, Critical at 10%

### Panel 4: P99 JEV Latency

**Title:** P99 JEV Latency
**Query:**
```promql
histogram_quantile(0.99, sum(rate(jrx_jev_signal_latency_seconds_bucket[5m])) by (le))
```
**Visualization:** Time series
**Unit:** seconds
**Thresholds:** Warning at 1s, Critical at 5s

### Panel 5: Degraded Evaluation Rate

**Title:** Degraded Evaluation Rate
**Query:**
```promql
sum by (reason) (rate(jrx_degraded_evaluations_total[5m]))
```
**Visualization:** Time series with stacked bars
**Legend:** jev_unavailable, gitleaks_failed

### Panel 6: Top Hard Rules

**Title:** Top Hard Rules (Last Hour)
**Query:**
```promql
topk(10, sum by (rule_name) (rate(jrx_hard_rule_triggers_total[1h])))
```
**Visualization:** Bar chart
**Legend:** rule names

### Panel 7: Broker Uptime

**Title:** Broker Uptime
**Query:**
```promql
jrx_broker_uptime_seconds
```
**Visualization:** Stat
**Unit:** seconds (or duration format)

### Panel 8: JEV Error Rate

**Title:** JEV Error Rate
**Query:**
```promql
rate(jrx_degraded_evaluations_total{reason="jev_unavailable"}[5m])
```
**Visualization:** Time series
**Unit:** reqps
**Thresholds:** Warning at 0.1 reqps, Critical at 1 reqps

## Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'jev-reflex-broker'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
    metrics_path: '/metrics'
```

For multiple brokers:
```yaml
scrape_configs:
  - job_name: 'jev-reflex-brokers'
    static_configs:
      - targets:
          - 'broker1.example.com:9090'
          - 'broker2.example.com:9090'
          - 'broker3.example.com:9090'
    scrape_interval: 15s
    metrics_path: '/metrics'
```

## Alerting Examples

### High HOLD Rate Alert

```promql
alert: HighHoldRate
expr: |
  rate(jrx_decisions_total{decision="hold"}[5m]) /
  sum(rate(jrx_decisions_total[5m])) > 0.10
for: 5m
labels:
  severity: warning
annotations:
  summary: "High HOLD rate detected"
  description: "HOLD rate is {{ $value | humanizePercentage }} for the last 5 minutes"
```

### High JEV Latency Alert

```promql
alert: HighJEVLatency
expr: |
  histogram_quantile(0.99, sum(rate(jrx_jev_signal_latency_seconds_bucket[5m])) by (le)) > 5
for: 5m
labels:
  severity: critical
annotations:
  summary: "JEV latency is too high"
  description: "P99 JEV latency is {{ $value }}s for the last 5 minutes"
```

### Degraded Evaluation Alert

```promql
alert: DegradedEvaluations
expr: |
  rate(jrx_degraded_evaluations_total[5m]) > 0.1
for: 5m
labels:
  severity: warning
annotations:
  summary: "High degraded evaluation rate"
  description: "Degraded evaluation rate is {{ $value }} req/s for the last 5 minutes"
```

### Broker Down Alert

```promql
alert: BrokerDown
expr: up{job="jev-reflex-broker"} == 0
for: 1m
labels:
  severity: critical
annotations:
  summary: "JEV Reflex broker is down"
  description: "Broker {{ $labels.instance }} has been down for more than 1 minute"
```

## Security Considerations

1. **Metrics Endpoint:** By default, the metrics endpoint binds to `127.0.0.1` for security. Only bind to `0.0.0.0` if you have network-level protections (firewall, VPC, etc.).

2. **Secret Redaction:** All log entries are automatically redacted before output. However, always test your redaction rules with your specific secret patterns.

3. **Webhook URLs:** When using webhook sinks, ensure HTTPS and proper authentication to protect log data in transit.

4. **Log Retention:** Configure appropriate log retention policies in your SIEM to comply with data retention requirements.

## Troubleshooting

### Metrics Not Available

1. Check if the broker is running: `jrx broker status`
2. Verify metrics endpoint is accessible: `curl http://127.0.0.1:9090/metrics`
3. Check broker logs for startup errors
4. Ensure no other process is using the metrics port

### Webhook Sink Not Delivering

1. Verify webhook URL is accessible from the broker host
2. Check webhook endpoint accepts POST requests with JSON payload
3. Review broker logs for delivery errors
4. Ensure webhook endpoint responds within 5 seconds

### High Degraded Evaluation Rate

1. Check TypeSafe API status and connectivity
2. Verify `TYPESAFE_API_KEY` is valid and not rate-limited
3. Review broker logs for specific error reasons
4. Check network connectivity to TypeSafe API

### High JEV Latency

1. Check TypeSafe API response times
2. Review network latency to TypeSafe API
3. Check broker resource utilization (CPU, memory)
4. Consider increasing JEV timeout in configuration
