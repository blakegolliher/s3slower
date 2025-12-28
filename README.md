# S3Slower

eBPF-based S3 client latency monitoring tool. Traces HTTP requests and responses from any S3 client without requiring SDK instrumentation.

## Features

- **Single static binary** - No runtime dependencies
- **eBPF-based monitoring** - Minimal performance overhead (<1% CPU)
- **No application changes required** - Works with any S3 client
- **Prometheus metrics export** - Integration with monitoring infrastructure
- **S3 operation detection** - GetObject, PutObject, multipart uploads, etc.
- **Multiple TLS library support** - OpenSSL, GnuTLS, NSS, and plain HTTP
- **Process watching** - Auto-attach to mc, warp, aws-cli, and other S3 clients
- **RPM/DEB packaging** - Easy installation via package managers
- **Systemd integration** - Run as a background service
- **Hot-reload configuration** - Update settings without restart

## Requirements

- Linux kernel 4.4+ with eBPF support
- Root privileges (required for eBPF attachment)
- Go 1.21+ (for building from source)

## Installation

### Build from Source

```bash
make build
```

The binary is created at `build/s3slower`.

### Install System-Wide

```bash
# Install to /usr/local/bin
sudo make install

# Or build and install RPM (RHEL/CentOS/Fedora)
make rpm
sudo rpm -i dist/s3slower-*.rpm

# Or build and install DEB (Debian/Ubuntu)
make deb
sudo dpkg -i dist/s3slower-*.deb
```

## Usage

```bash
# Run with terminal output (requires root)
sudo ./build/s3slower run

# Run with Prometheus exporter on port 9000
sudo ./build/s3slower run --prometheus --port 9000

# Watch specific processes
sudo ./build/s3slower run --watch mc,warp

# Use a config file
sudo ./build/s3slower run -C s3slower.yaml

# Attach to a specific process
sudo ./build/s3slower attach --pid 12345
```

After system installation:
```bash
sudo s3slower run
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
| `-T, --targets` | Path to targets file | - |
| `--prometheus` | Enable Prometheus exporter | false |
| `-p, --port` | Prometheus exporter port | 9000 |
| `--host` | Prometheus exporter host | "::" |
| `--min-latency` | Minimum latency in ms to report | 0 |
| `--watch` | Process names to watch (e.g., mc,warp) | - |
| `--mode` | Probe mode: auto, http, openssl, gnutls, nss | auto |
| `--debug` | Enable debug output | false |
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

### Main Configuration (`s3slower.yaml`)

```yaml
interval: 5                    # Collection interval (seconds)
min_latency_ms: 0             # Minimum latency to report
debug: false                  # Debug logging

prometheus:
  prom_exporter_host: "::"    # Listen address
  prom_exporter_port: 9000    # Listen port
  buffer_size: 1000           # Sample buffer size

screen:
  table_format: true          # Use table format
  max_url_length: 50          # URL truncation length
```

### Targets Configuration (`targets.yml`)

```yaml
targets:
  - id: aws-cli
    match:
      type: comm              # Match by process name
      value: aws
    mode: openssl
    prom_labels:
      client: aws-cli
      env: production

  - id: mc
    match:
      type: exe_basename      # Match by executable name
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
| `http` | Kprobes on sys_read/sys_write | Plain HTTP traffic |
| `openssl` | Uprobes on SSL_read/SSL_write | HTTPS via OpenSSL |
| `gnutls` | Uprobes on gnutls_record_* | HTTPS via GnuTLS |
| `nss` | Uprobes on PR_Read/PR_Write | HTTPS via NSS |

## Terminal Output

```
TIME         METHOD BUCKET           ENDPOINT                      BYTES    LAT(ms) KEY
---------------------------------------------------------------------------------------------------------------
14:30:15.123 GET    my-bucket        s3.amazonaws.com            1048576      45.20 data/file1.json
14:30:16.456 PUT    backup-bucket    s3.us-west-2.amazonaws.com        0     123.50 archive/backup.tar.gz
14:30:17.789 GET    logs             minio.local:9000              4096      12.30 app/2024-01-15/app.log
```

## Prometheus Metrics

When running with `--prometheus`, the following metrics are exported:

| Metric | Type | Description |
|--------|------|-------------|
| `s3slower_requests_total` | Counter | Total S3 requests |
| `s3slower_request_errors_total` | Counter | Total request errors |
| `s3slower_request_duration_ms` | Histogram | Request latency |
| `s3slower_request_duration_min_ms` | Gauge | Minimum latency |
| `s3slower_request_duration_max_ms` | Gauge | Maximum latency |
| `s3slower_request_bytes_total` | Counter | Total request bytes |
| `s3slower_response_bytes_total` | Counter | Total response bytes |
| `s3slower_partial_requests_total` | Counter | Multipart requests |

Labels: `hostname`, `comm`, `s3_operation`, `method`, `pid`

## S3 Operation Detection

Automatically detected operations:

- GetObject, PutObject, HeadObject, DeleteObject
- InitMultipart, UploadPart(N), CompleteMultipart, AbortMultipart
- ListParts, ListMultiparts, DeleteMultiple

## Deployment

### Systemd Service

After package installation:

```bash
sudo systemctl start s3slower
sudo systemctl enable s3slower
sudo journalctl -u s3slower -f
```

### Docker

```dockerfile
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN make build

FROM debian:bookworm-slim
COPY --from=builder /app/build/s3slower /usr/local/bin/
CMD ["s3slower", "run", "--prometheus"]
```

Run with required privileges:
```bash
docker run --privileged \
  -v /lib/modules:/lib/modules:ro \
  -v /sys/kernel:/sys/kernel:ro \
  -v /proc:/proc:rw \
  s3slower:latest
```

### Kubernetes

See `k8s/` directory for DaemonSet and Prometheus configurations.

## Development

```bash
make build        # Build binary
make test         # Run tests
make test-cover   # Run tests with coverage
make lint         # Run linter
make fmt          # Format code
make clean        # Clean build artifacts
make dev          # Full development workflow
make ci           # CI pipeline
```

### Project Structure

```
.
├── cmd/s3slower/           # Main entry point
├── internal/
│   ├── cmd/                # CLI commands (cobra)
│   ├── config/             # YAML configuration
│   ├── ebpf/               # eBPF loader (cilium/ebpf)
│   ├── event/              # Event processing
│   ├── http/               # HTTP parsing
│   ├── logger/             # Rotating file logger
│   ├── metrics/            # Prometheus exporter
│   ├── runner/             # Main execution loop
│   ├── terminal/           # Console output
│   ├── utils/              # Utilities
│   └── watcher/            # Process watching
├── k8s/                    # Kubernetes manifests
├── systemd/                # Systemd service file
├── s3slower.yaml           # Example configuration
├── nfpm.yaml               # Package configuration
├── Makefile
└── LICENSE
```

## Performance

- **CPU impact**: <1% under normal load
- **Memory usage**: 10-50MB depending on traffic
- **Network overhead**: None (passive monitoring)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied | Run as root or with CAP_BPF capability |
| BPF program load failed | Check kernel version (4.4+ required) |
| No events captured | Verify S3 traffic exists and TLS library is detected |
| High CPU usage | Increase `--min-latency` to filter noise |

Enable debug logging:
```bash
sudo s3slower run --debug
```

## License

Apache License 2.0
