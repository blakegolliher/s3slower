# S3Slower Monitoring Stack

Prometheus + Grafana monitoring for s3slower stress tests.

## Quick Start

```bash
# From the project root:
make monitoring-up       # Start Prometheus + Grafana
make monitoring-down     # Stop everything
make monitoring-logs     # Tail container logs
```

Or directly:

```bash
cd monitoring
podman-compose up -d     # or docker-compose up -d
```

## Access

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin, anonymous viewer enabled)

## Prerequisites

- `podman-compose` or `docker-compose`
- s3slower running with `--prometheus --port 9000`

## Architecture

```
s3slower (:9000/metrics) --> Prometheus (:9090) --> Grafana (:3000)
```

All containers use `network_mode: host` to reach s3slower on localhost.

## Recording Rules

Pre-computed metrics for dashboard performance:

| Rule | Description |
|------|-------------|
| `s3slower:request_rate_5m` | Request rate per label set |
| `s3slower:error_rate_5m` | Error rate per label set |
| `s3slower:throughput_bytes_5m` | Combined upload+download throughput |
| `s3slower:request_duration_p50` | 50th percentile latency |
| `s3slower:request_duration_p95` | 95th percentile latency |
| `s3slower:request_duration_p99` | 99th percentile latency |

## Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| S3SlowerHighLatency | p95 > 1000ms for 5m | warning |
| S3SlowerHighErrorRate | errors > 0.1/sec for 2m | critical |
| S3SlowerExporterDown | target down for 1m | critical |
| S3SlowerVeryHighLatency | max > 5000ms for 1m | critical |

## Storage

- Prometheus retention: 120h (5 days), 10GB cap
- Data persisted in named volumes: `prometheus-data`, `grafana-data`

## Cleanup

```bash
make monitoring-down
podman volume rm monitoring_prometheus-data monitoring_grafana-data  # remove data
```
