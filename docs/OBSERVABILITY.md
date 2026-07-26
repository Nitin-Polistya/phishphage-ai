# Observability

The API writes timestamped, severity-tagged structured text logs to stdout.
Request IDs are attached to responses and included in error log context.
Raw email content, addresses, URLs, request bodies, credentials, and stack
traces are not emitted to client responses; model ID/version are safe release
metadata.

Configure `LOG_LEVEL` per environment. Health checks should be sampled or
filtered by the hosting platform so they do not dominate logs. A future
monitoring integration should track health/readiness status, 4xx/5xx rates,
429 rates, latency percentiles, startup failures, artifact hash failures, and
memory per worker without collecting request bodies.
