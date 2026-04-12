# S3Slower

eBPF-based S3 client latency tracer. Captures HTTP request/response timing from any S3 client without SDK instrumentation.

## Requirements

- Linux kernel 4.4+ with eBPF support
- Root privileges
- Go 1.24+ (build from source)

## Install

```bash
# Build from source
make build

# Or build and install RPM (auto-enables systemd service at boot)
make rpm
sudo rpm -ivh s3slower-*.rpm
```

## Run

```bash
# Basic — trace all S3 traffic, table output
sudo ./build/s3slower run

# With Prometheus exporter
sudo ./build/s3slower run --prometheus --port 9000

# Watch specific processes, set latency threshold
sudo ./build/s3slower run --watch elbencho,mc --min-latency 100

# Attach to a running process
sudo ./build/s3slower attach --pid 12345
```

## Output

```
TIME         METHOD OP       BUCKET                     ENDPOINT          BYTES   LAT(ms) KEY
---------------------------------------------------------------------------------------------------------
14:30:15.123 GET    GET      my-bucket                  172.200.203.3   1048576    45.20 data/file1.json
14:30:16.456 PUT    PUT      backup-bucket              172.200.203.3         0   123.50 archive/backup.tar.gz
14:30:17.789 POST   MPU_INIT my-bucket                  172.200.203.3         0     8.30 large-upload.bin
```

Output formats: `--output table` (default), `simple`, `json`

## Run as a System Service with Prometheus

After RPM install, s3slower runs as a systemd service with Prometheus metrics enabled by default:

```bash
# Start the service
sudo systemctl start s3slower

# Check status
sudo systemctl status s3slower

# View live logs
sudo journalctl -u s3slower -f

# Verify Prometheus endpoint
curl -s http://localhost:9000/metrics | grep s3slower
```

Edit `/etc/s3slower/s3slower.yaml` to configure (changes are hot-reloaded):

```yaml
min_latency_ms: 0
prometheus:
  prom_exporter_host: "::"
  prom_exporter_port: 9000
file:
  samples_path: /var/log/s3slower/s3slower.log
  max_backups: 5
  max_size_mb: 100
```

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `s3slower_requests_total` | Counter | Total S3 requests |
| `s3slower_request_errors_total` | Counter | HTTP 4xx/5xx errors |
| `s3slower_request_duration_ms` | Histogram | Latency distribution (ms) |
| `s3slower_request_bytes_total` | Counter | Upload bytes |
| `s3slower_response_bytes_total` | Counter | Download bytes |
| `s3slower_response_status_total` | Counter | Responses by bucket + HTTP status code |

Default labels: `hostname`, `comm`, `s3_operation`, `bucket`, `endpoint`

A local Grafana + Prometheus stack is included for development:
```bash
make monitoring-up    # Start Prometheus + Grafana on localhost
make monitoring-down  # Stop
```

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-C, --config` | Config file path | - |
| `-T, --targets` | Targets file (hot-reloaded) | - |
| `--prometheus` | Enable Prometheus exporter | false |
| `-p, --port` | Prometheus port | 9000 |
| `--min-latency` | Min latency (ms) to report | 0 |
| `--watch` | Process names to watch | - |
| `--mode` | Probe mode: auto, http, openssl, gnutls, nss | auto |
| `--output` | Output format: table, simple, json | table |
| `--log-dir` | Log directory | /var/log/s3slower |
| `--no-log` | Disable file logging | false |
| `--debug` | Debug output | false |

## Development

```bash
make build          # Build binary
make test           # Unit tests
make test-race      # Tests with race detection
make test-cover     # Coverage report
make test-validate  # E2E validation (requires root + S3 endpoint)
make lint           # Linter
make generate       # Regenerate BPF program (requires clang, bpftool)
make rpm            # Build RPM
make deb            # Build DEB
```
