# S3Slower

eBPF-based S3 client latency monitoring tool. Traces HTTP requests and responses from any S3 client without requiring SDK instrumentation.

## Features

- **Single static binary** - No runtime dependencies
- **eBPF-based monitoring** - Minimal performance overhead (<1% CPU)
- **No application changes required** - Works with any S3 client
- **Prometheus metrics export** - Integration with monitoring infrastructure
- **Multiple TLS library support** - OpenSSL, GnuTLS, NSS, and plain HTTP
- **Systemd integration** - Enabled at boot automatically on RPM install

## Requirements

- Linux kernel 4.4+ with eBPF support
- Root privileges (required for eBPF attachment)
- Go 1.24+ (for building from source)

## Installation

### Build from Source

```bash
make build
```

The binary is created at `build/s3slower`.

### RPM Package (RHEL/CentOS/Fedora)

```bash
make rpm
sudo rpm -ivh s3slower-*.rpm
```

The RPM installs the binary, systemd service, and default config. The service is **automatically enabled at boot**.

### DEB Package (Debian/Ubuntu)

```bash
make deb
sudo dpkg -i s3slower-*.deb
```

## Usage

```bash
# Run with terminal output (requires root)
sudo s3slower run

# Run with Prometheus exporter on port 9000
sudo s3slower run --prometheus --port 9000

# Watch specific processes
sudo s3slower run --watch elbencho,awscli

# Use a config file
sudo s3slower run -C /etc/s3slower/s3slower.yaml

# Attach to a specific process
sudo s3slower attach --pid 12345
```

After RPM installation:
```bash
sudo systemctl start s3slower
sudo journalctl -u s3slower -f
```

## CLI Reference

```
Usage:
  s3slower [command]

Commands:
  run         Run s3slower tracer
  attach      Attach to a specific process
  version     Print version information
  help        Help about any command
```

### Run Command Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-C, --config` | Path to config file | - |
| `-T, --targets` | Path to targets file (hot-reloaded) | - |
| `--prometheus` | Enable Prometheus exporter | false |
| `-p, --port` | Prometheus exporter port | 9000 |
| `--host` | Prometheus exporter host | "::" |
| `--min-latency` | Minimum latency in ms to report | 0 |
| `--watch` | Process names to watch (e.g., mc,warp) | - |
| `--mode` | Probe mode: auto, http, openssl, gnutls, nss | auto |
| `--debug` | Enable debug output | false |
| `--output` | Output format: table, simple, json | table |
| `--log-dir` | Log directory | /var/log/s3slower |
| `--log-max-size` | Max log size in MB before rotation | 100 |
| `--no-log` | Disable file logging | false |

### Attach Command Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--pid` | Process ID to attach to | - |
| `--mode` | Probe mode: auto, openssl, gnutls, nss, http | auto |
| `--min-latency` | Minimum latency in ms to report | 0 |
| `--log-dir` | Log directory | /var/log/s3slower |
| `--no-log` | Disable file logging | false |

## Configuration

### Main Configuration (`/etc/s3slower/s3slower.yaml`)

```yaml
# Minimum latency threshold (0 = capture all)
min_latency_ms: 0

# Enable debug logging
debug: false

# Prometheus exporter
prometheus:
  prom_exporter_host: "::"
  prom_exporter_port: 9000

# File driver — rotating log output
file:
  samples_path: /var/log/s3slower/s3slower.log
  max_backups: 5
  max_size_mb: 100

# Screen driver — console output (foreground mode)
screen:
  table_format: true
  max_url_length: 50
```

### Targets Configuration (`targets.yml`)

```yaml
targets:
  - id: aws-cli
    match:
      type: comm
      value: aws
    mode: openssl
    prom_labels:
      client: aws-cli
      env: production

  - id: mc
    match:
      type: exe_basename
      value: mc
    mode: openssl
    prom_labels:
      client: minio-client
```

Match types: `comm`, `exe_basename`, `cmdline_substring`

### Hot-Reload

Both configuration files support hot-reloading. Changes take effect immediately without restart.

## eBPF Tracing Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `auto` | Attach all available probes | Mixed traffic (recommended) |
| `http` | Kprobes on sys_read/sys_write/sendto/recvfrom | Plain HTTP traffic |
| `openssl` | Uprobes on SSL_read/SSL_write | HTTPS via OpenSSL |
| `gnutls` | Uprobes on gnutls_record_send/recv | HTTPS via GnuTLS |
| `nss` | Uprobes on PR_Read/PR_Write | HTTPS via NSS |

In `auto` mode, s3slower also detects statically-linked binaries (e.g., elbencho, awcli) that embed OpenSSL.

## Terminal Output

```
TIME         METHOD OP       BUCKET         ENDPOINT          BYTES   LAT(ms) KEY
---------------------------------------------------------------------------------------------------------
14:30:15.123 GET    GET      my-bucket      172.200.203.3      1048576    45.20 data/file1.json
14:30:16.456 PUT    PUT      backup-bucket  172.200.203.3            0   123.50 archive/backup.tar.gz
14:30:17.789 POST   MPU_INIT my-bucket      172.200.203.3            0     8.30 large-upload.bin
```

Output formats: `table` (default), `simple`, `json`

## Prometheus Metrics

When running with `--prometheus`, the following metrics are exported on `/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `s3slower_requests_total` | Counter | Total S3 requests |
| `s3slower_request_errors_total` | Counter | Total request errors (HTTP 4xx/5xx) |
| `s3slower_request_duration_ms` | Histogram | Request latency distribution |
| `s3slower_request_bytes_total` | Counter | Total request (upload) bytes |
| `s3slower_response_bytes_total` | Counter | Total response (download) bytes |

Labels: `hostname`, `comm`, `s3_operation`, `bucket`, `endpoint`

Histogram buckets: 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000 ms

## S3 Operation Detection

| Operation | HTTP Method | Description |
|-----------|------------|-------------|
| `GET_OBJECT` | GET | Download an object |
| `PUT_OBJECT` | PUT | Upload an object |
| `HEAD_OBJECT` | HEAD | Get object metadata |
| `DELETE_OBJECT` | DELETE | Delete an object |
| `LIST_OBJECTS` | GET | List bucket contents |
| `LIST_PREFIX` | GET | List with prefix filter |
| `CREATE_BUCKET` | PUT | Create a bucket |
| `DELETE_BUCKET` | DELETE | Delete a bucket |
| `HEAD_BUCKET` | HEAD | Check bucket existence |
| `MPU_CREATE` | POST | Initiate multipart upload |
| `MPU_PART` | PUT | Upload a part |
| `MPU_COMPLETE` | POST | Complete multipart upload |
| `MPU_ABORT` | DELETE | Abort multipart upload |

## Deployment

### Systemd Service

After RPM installation, the service is enabled at boot automatically:

```bash
# Start now
sudo systemctl start s3slower

# Check status
sudo systemctl status s3slower

# View logs
sudo journalctl -u s3slower -f
```

Configuration: `/etc/s3slower/s3slower.yaml`
Log files: `/var/log/s3slower/`

## Development

```bash
make build          # Build binary
make test           # Run unit tests
make test-race      # Run tests with race detection
make test-cover     # Run tests with coverage report
make test-validate  # Run E2E validation (requires root + S3 endpoint)
make test-stress    # Run stress test (requires root + S3 endpoint)
make rpm            # Build RPM package
make deb            # Build DEB package
make lint           # Run linter
make fmt            # Format code
make generate       # Regenerate BPF program (requires clang, bpftool)
make clean          # Clean build artifacts
```

### Monitoring Stack

```bash
make monitoring-up    # Start Prometheus + Grafana (podman-compose)
make monitoring-down  # Stop monitoring stack
make monitoring-logs  # Tail container logs
```

Grafana dashboard is provisioned automatically from `monitoring/grafana/dashboards/`.

### Project Structure

```
.
├── cmd/s3slower/           # Main entry point
├── internal/
│   ├── cmd/                # CLI commands (cobra)
│   ├── config/             # YAML configuration + hot-reload
│   ├── ebpf/               # eBPF program loader (cilium/ebpf)
│   ├── event/              # Event processing pipeline
│   ├── http/               # HTTP request/response parsing
│   ├── logger/             # Rotating file logger
│   ├── metrics/            # Prometheus exporter
│   ├── runner/             # Main execution loop
│   ├── terminal/           # Console output (table/simple/json)
│   └── watcher/            # Process watching (/proc scanner)
├── packaging/              # RPM/DEB install scripts
├── systemd/                # Systemd service file
├── k8s/                    # Kubernetes manifests
├── monitoring/             # Prometheus + Grafana stack
│   ├── grafana/            # Dashboard JSON + provisioning
│   └── prometheus/         # Scrape config + alert rules
├── validation_test/        # E2E validation tests
├── s3slower.yaml           # Default configuration
├── nfpm.yaml               # Package build configuration
└── Makefile
```

## Performance

- **CPU impact**: <1% under normal load
- **Memory usage**: 10-50MB depending on traffic
- **Network overhead**: None (passive monitoring)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied | Run as root (eBPF requires root privileges) |
| BPF program load failed | Check kernel version (4.4+ required) |
| No events captured | Verify S3 traffic exists; use `--debug` to inspect |
| Missing TLS traffic | Check that OpenSSL/GnuTLS is detected (`--debug`) |

```bash
# Debug mode shows probe attachment and event filtering details
sudo s3slower run --debug
```
