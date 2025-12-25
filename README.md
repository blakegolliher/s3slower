# S3Slower - S3 Client Latency Monitor

S3Slower is a production-ready tool for monitoring S3 client-side latency using eBPF. It traces HTTP requests and responses from S3 clients without requiring SDK instrumentation, providing detailed metrics via Prometheus and terminal output.

## Features

- **Single static binary** - No dependencies, no runtime required
- **eBPF-based monitoring** with minimal performance overhead
- **No application instrumentation** required - works with any S3 client
- **Prometheus metrics export** for integration with monitoring infrastructure
- **S3 operation detection** - identifies GetObject, PutObject, multipart uploads, etc.
- **Multiple TLS library support** - OpenSSL, GnuTLS, NSS, and plain HTTP
- **Process watching** - Auto-attach to mc, warp, and other S3 clients
- **RPM/DEB packaging** - Easy installation via package managers
- **Systemd integration** - Run as a background service

## Quick Start

### Prerequisites

- **Linux kernel**: 4.4+ with eBPF support
- **Go**: 1.24+ (for building from source)
- **Root privileges**: Required for eBPF attachment

### Build from Source

```bash
cd go
make build
```

The binary will be created at `go/build/s3slower`.

### Run

```bash
# Run with terminal output (requires root)
sudo ./go/build/s3slower run

# Run with Prometheus exporter on port 9000
sudo ./go/build/s3slower run --prometheus --port 9000

# Watch specific processes
sudo ./go/build/s3slower run --watch mc,warp

# Use a config file
sudo ./go/build/s3slower run -C s3slower.yaml

# Attach to a specific process
sudo ./go/build/s3slower attach --pid 12345
```

### Install System-Wide

```bash
cd go

# Install to /usr/local/bin
sudo make install

# Or build and install RPM (RHEL/CentOS/Fedora)
make rpm
sudo rpm -i dist/s3slower-*.rpm

# Or build and install DEB (Debian/Ubuntu)
make deb
sudo dpkg -i dist/s3slower-*.deb
```

After installation, run from anywhere:
```bash
sudo s3slower run
```

## CLI Reference

```
Usage:
  s3slower [command]

Available Commands:
  run         Run s3slower tracer
  attach      Attach to a specific process
  demo        Run demo mode with sample events
  version     Print version information
  help        Help about any command

Global Flags:
  -h, --help      help for s3slower
  -v, --version   version for s3slower
```

### Run Command

```bash
s3slower run [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-C, --config` | Path to config file | - |
| `--prometheus` | Enable Prometheus exporter | false |
| `-p, --port` | Prometheus exporter port | 9000 |
| `--host` | Prometheus exporter host | "::" |
| `--min-latency` | Minimum latency in ms to report | 0 |
| `--watch` | Process names to watch (e.g., mc,warp) | - |
| `--mode` | Probe mode: auto, http, openssl, gnutls, nss | auto |
| `--debug` | Enable debug output | false |
| `--log-dir` | Log directory | /opt/s3slower |
| `--no-log` | Disable file logging | false |

### Attach Command

```bash
s3slower attach [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--pid` | Process ID to attach to | - |
| `--mode` | Probe mode: auto, openssl, gnutls, nss, http | auto |
| `-f, --follow` | Follow child processes | false |

## eBPF Tracing Modes

S3Slower supports multiple tracing modes for different TLS libraries:

| Mode | Description | Use Case |
|------|-------------|----------|
| `auto` | Attach all available probes | Mixed traffic (recommended) |
| `http` | Kprobes on sys_read/sys_write | Plain HTTP traffic |
| `openssl` | Uprobes on SSL_read/SSL_write | HTTPS via OpenSSL |
| `gnutls` | Uprobes on gnutls_record_* | HTTPS via GnuTLS |
| `nss` | Uprobes on PR_Read/PR_Write | HTTPS via NSS |

## Configuration

### Configuration File (`s3slower.yaml`)

```yaml
# Collection settings
interval: 5                    # Collection interval (seconds)
min_latency_ms: 0             # Minimum latency to report
debug: false                  # Debug logging

# Prometheus exporter
prometheus:
  prom_exporter_host: "::"    # Listen address
  prom_exporter_port: 9000    # Listen port
  buffer_size: 1000           # Sample buffer size

# Terminal output
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

## Terminal Output

```
TIME     COMM         PID    S3_OPERATION     COUNT  AVG_MS   MIN_MS   MAX_MS   REQ_BYTES  RESP_BYTES
14:30:15 aws-cli      1234   GetObject        3      125.3    45.2     234.1    512        1048576
14:30:15 boto3-app    5678   PutObject        1      89.7     89.7     89.7     1024       0
14:30:15 s3cmd        9012   UploadPart(1)    1      456.2    456.2    456.2    5242880    0
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

All metrics include labels:
- `hostname` - System hostname
- `comm` - Process command name
- `s3_operation` - Detected S3 operation
- `method` - HTTP method
- `pid` - Process ID

## S3 Operation Detection

S3Slower automatically detects the following S3 operations:

- **GetObject** - Object retrieval
- **PutObject** - Object upload
- **HeadObject** - Object metadata retrieval
- **DeleteObject** - Object deletion
- **InitMultipart** - Multipart upload initiation
- **UploadPart(N)** - Multipart upload part (with part number)
- **CompleteMultipart** - Multipart upload completion
- **AbortMultipart** - Multipart upload cancellation
- **ListParts** - List multipart upload parts
- **ListMultiparts** - List multipart uploads
- **DeleteMultiple** - Batch object deletion

## Deployment

### Systemd Service

After package installation, manage with systemd:

```bash
# Start service
sudo systemctl start s3slower

# Enable at boot
sudo systemctl enable s3slower

# View logs
sudo journalctl -u s3slower -f

# Check status
sudo systemctl status s3slower
```

### Docker

```dockerfile
FROM golang:1.24 AS builder
WORKDIR /app
COPY go/ .
RUN make build

FROM debian:bookworm-slim
COPY --from=builder /app/build/s3slower /usr/local/bin/
CMD ["s3slower", "run", "--prometheus"]
```

Run with required privileges:
```bash
docker run --privileged \
  --volume /lib/modules:/lib/modules:ro \
  --volume /usr/src:/usr/src:ro \
  --volume /sys/kernel:/sys/kernel:ro \
  --volume /proc:/proc:rw \
  --name s3slower \
  s3slower:latest
```

### Kubernetes

Deploy as a DaemonSet to monitor S3 operations across all nodes:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: s3slower
spec:
  selector:
    matchLabels:
      name: s3slower
  template:
    metadata:
      labels:
        name: s3slower
    spec:
      hostPID: true
      hostIPC: true
      securityContext:
        runAsUser: 0
      containers:
      - name: s3slower
        image: s3slower:latest
        args: ["run", "--prometheus", "--port", "9000"]
        securityContext:
          privileged: true
        volumeMounts:
        - name: lib-modules
          mountPath: /lib/modules
          readOnly: true
        - name: sys-kernel
          mountPath: /sys/kernel
          readOnly: true
        - name: proc
          mountPath: /proc
        ports:
        - containerPort: 9000
          name: metrics
      volumes:
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: sys-kernel
        hostPath:
          path: /sys/kernel
      - name: proc
        hostPath:
          path: /proc
```

## Monitoring and Alerting

### Grafana Dashboard

Example PromQL queries for Grafana:

```promql
# Request rate
rate(s3slower_requests_total[5m])

# Average latency by operation
s3slower_request_duration_ms

# High latency operations
s3slower_request_duration_max_ms > 1000

# Error rate
rate(s3slower_request_errors_total[5m])

# Throughput
rate(s3slower_request_bytes_total[5m]) + rate(s3slower_response_bytes_total[5m])
```

### Alerting Rules

```yaml
groups:
- name: s3slower.rules
  rules:
  - alert: S3HighLatency
    expr: s3slower_request_duration_ms > 1000
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High S3 latency detected"

  - alert: S3HighErrorRate
    expr: rate(s3slower_request_errors_total[5m]) > 0.1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High S3 error rate detected"
```

## Development

### Build Commands

```bash
cd go

# Build binary
make build

# Run tests
make test

# Run tests with coverage
make test-cover

# Format code
make fmt

# Run linter
make lint

# Full development workflow
make dev

# CI pipeline
make ci

# Clean build artifacts
make clean
```

### Project Structure

```
go/
├── cmd/s3slower/          # Main entry point
├── internal/
│   ├── cmd/               # CLI commands (cobra)
│   ├── config/            # YAML configuration
│   ├── ebpf/              # eBPF loader (cilium/ebpf)
│   │   ├── bpf/           # BPF C source code
│   │   ├── tracer.go      # BPF program management
│   │   ├── library.go     # TLS library detection
│   │   └── pipeline.go    # Event processing pipeline
│   ├── event/             # Event processing
│   ├── http/              # HTTP parsing
│   ├── metrics/           # Prometheus exporter
│   ├── terminal/          # Console output
│   ├── utils/             # Utilities
│   └── watcher/           # Process watching
├── Makefile               # Build system
├── nfpm.yaml              # Package configuration
└── README.md              # Go-specific docs
```

## Performance Impact

S3Slower is designed for production use with minimal overhead:

- **CPU impact**: <1% additional CPU usage under normal load
- **Memory usage**: ~10-50MB depending on traffic volume
- **Network overhead**: None (passive monitoring)
- **Storage overhead**: Configurable buffer sizes

## Troubleshooting

### Common Issues

1. **Permission denied**: Ensure running as root or with `CAP_BPF` capability
2. **BPF program load failed**: Check kernel version (4.4+ required)
3. **No events captured**: Verify S3 traffic exists and TLS library is detected
4. **High CPU usage**: Increase `--min-latency` to filter noise

### Debug Mode

Enable debug logging:
```bash
sudo s3slower run --debug
```

See [LINUX_TROUBLESHOOTING.md](LINUX_TROUBLESHOOTING.md) for detailed troubleshooting.

## Legacy Python Version

The original Python implementation is still available but no longer maintained. See [LEGACY_README.md](LEGACY_README.md) for Python-specific documentation.

## License

Apache License 2.0 - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run `make ci` to verify
5. Submit a pull request
