# S3Slower

**See exactly how slow your S3 traffic is — from any client, without changing a single line of code.**

S3Slower is an eBPF-based tracer that measures the latency of every S3 request leaving a Linux host. It hooks into the kernel and TLS libraries to time HTTP request/response pairs as they happen, so you get accurate per-request timing whether the traffic comes from the AWS CLI, Boto3, `s3cmd`, `mc`, `elbencho`, Go clients, or any other tool that speaks S3 over HTTPS.

## Why S3Slower

- **Zero client instrumentation.** No SDK wrappers, no proxies, no code changes. Attach it to a host and it starts measuring.
- **Works with every S3 client.** OpenSSL, GnuTLS, NSS, s2n-tls, and Go's native `crypto/tls` are all supported. If the app makes an HTTPS S3 call, S3Slower sees it.
- **Real request latency, not synthetic probes.** You see what your actual workload experiences, bucket by bucket, operation by operation.
- **Low-cardinality Prometheus metrics by default.** Ships production-safe labels out of the box, with opt-in bucket/endpoint dimensions when you want them.
- **Runs as a systemd service.** Install the RPM, start the service, scrape the metrics endpoint. That's the whole deployment.

## Deploy

**1. Install the RPM.** It sets up the `s3slower` user, drops the config in `/etc/s3slower/`, and enables the systemd unit at boot.

```bash
sudo rpm -ivh s3slower-*.rpm
sudo systemctl start s3slower
```

**2. Verify it's running.**

```bash
sudo systemctl status s3slower
sudo journalctl -u s3slower -f
```

**3. Scrape the metrics endpoint.**

```bash
curl -s http://localhost:9000/metrics | grep s3slower
```

That's it. S3Slower is now tracing every S3 request on the host and exposing metrics on port 9000.

## Configure

Edit `/etc/s3slower/s3slower.yaml`. `min_latency_ms` and `debug` are hot-reloaded on save; everything else needs `sudo systemctl restart s3slower`.

```yaml
min_latency_ms: 0             # Only capture requests slower than this
prometheus:
  prom_exporter_host: "::"    # Listen on all interfaces
  prom_exporter_port: 9000
file:
  samples_path: /var/log/s3slower/s3slower.log
  max_backups: 5
  max_size_mb: 100
```

## Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `s3slower_requests_total` | Counter | Total S3 requests |
| `s3slower_request_errors_total` | Counter | HTTP 4xx/5xx errors |
| `s3slower_request_duration_ms` | Histogram | Latency distribution (ms) |
| `s3slower_request_bytes_total` | Counter | Upload bytes |
| `s3slower_response_bytes_total` | Counter | Download bytes |
| `s3slower_response_status_total` | Counter | Responses by HTTP status code |
| `s3slower_events_dropped_total` | Counter | Events dropped before export (`reason=perf_lost` for kernel-ring overflow, `channel_full` for userspace back-pressure) |

**Labels.** The always-on core is `comm` (process name) and `s3_operation`. The scrape-injected `instance` label identifies the host. Two more labels are opt-in because they can explode cardinality on multi-tenant workloads:

```yaml
metrics:
  labels:
    - bucket     # One series per (bucket × comm × operation)
    - endpoint   # One series per S3 endpoint address
```

Enable them only if your Prometheus can handle the cardinality of your bucket count. Dashboards that previously used a `hostname` label should switch to `instance`.

## Ad-hoc Usage

You can also run `s3slower` directly against a live workload without the service:

```bash
# Trace all S3 traffic, print a live table
sudo s3slower run

# Watch only specific process names, filter to slow requests
sudo s3slower run --watch elbencho,mc --min-latency 100

# Attach to a single running process
sudo s3slower attach --pid 12345
```

Sample output:

```
TIME         METHOD OP       BUCKET                     ENDPOINT          BYTES   LAT(ms) KEY
---------------------------------------------------------------------------------------------------------
14:30:15.123 GET    GET      my-bucket                  172.200.203.3   1048576    45.20 data/file1.json
14:30:16.456 PUT    PUT      backup-bucket              172.200.203.3         0   123.50 archive/backup.tar.gz
14:30:17.789 POST   MPU_INIT my-bucket                  172.200.203.3         0     8.30 large-upload.bin
```

Output formats: `--output table` (default), `simple`, `json`.

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-C, --config` | Config file path | - |
| `-T, --targets` | Targets file (hot-reloaded) | - |
| `--prometheus` | Enable Prometheus exporter | false |
| `-p, --port` | Prometheus port | 9000 |
| `--min-latency` | Min latency (ms) to report | 0 |
| `--watch` | Comma-separated process names to watch | - |
| `--mode` | Probe mode: auto, http, openssl, gnutls, nss, s2n, gotls | auto |
| `--output` | Output format: table, simple, json | table |
| `--log-dir` | Log directory | /var/log/s3slower |
| `--no-log` | Disable file logging | false |
| `--debug` | Debug output | false |

## Requirements

- Linux kernel 4.4+ with eBPF support
- Root privileges (eBPF and uprobe attachment)
