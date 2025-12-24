# S3Slower - S3 Client Latency Monitor

> **⚠️ Refactoring in Progress**: This project is being refactored from Python to Go. See the [Go Implementation](#go-implementation-in-progress) section below for details.

S3Slower is a production-ready tool for monitoring S3 client-side latency using eBPF. It traces HTTP requests and responses from S3 clients without requiring SDK instrumentation, providing detailed metrics via Prometheus and other exporters.

## Features

- **eBPF-based monitoring** with minimal performance overhead
- **No application instrumentation** required - works with any S3 client
- **Prometheus metrics export** for integration with monitoring infrastructure
- **S3 operation detection** - identifies GetObject, PutObject, multipart uploads, etc.
- **Process-level monitoring** with optional PID filtering
- **Configurable latency thresholds** to focus on slow operations
- **Multiple output formats** (console, Prometheus)
- **Production-ready** with proper packaging and deployment options

## Quick Start

### Installation

```bash
# Install from source
git clone https://github.com/yourusername/s3slower.git
cd s3slower
pip install .

# Or install in development mode
pip install -e .
```

### Basic Usage

Monitor all S3 operations with console output:
```bash
sudo s3slower -d screen
```

Monitor with Prometheus export:
```bash
sudo s3slower -d prometheus
```

Monitor specific process with latency threshold:
```bash
sudo s3slower -d screen --pid 1234 --min-latency-ms 100
```

Use configuration file:
```bash
sudo s3slower -C s3slower.yaml
```

## Configuration

### Command Line Options

```bash
s3slower --help
```

Key options:
- `-d, --driver`: Output driver (screen, prometheus)
- `-p, --pid`: Monitor specific process ID
- `--min-latency-ms`: Minimum latency threshold (default: 0)
- `-i, --interval`: Collection interval in seconds (default: 5)
- `-C, --cfg`: Configuration file path
- `--debug`: Enable debug logging

### Configuration File

Example `s3slower.yaml`:

```yaml
# Collection settings
interval: 5
min_latency_ms: 0
debug: false

# Optional process filtering
# pid: 1234

# Prometheus exporter
prometheus:
  prom_exporter_host: "::"
  prom_exporter_port: 9000
  buffer_size: 1000

# Optional console output
# screen:
#   table_format: true
```

## Output Formats

### Console Output

```
TIME     COMM         PID    S3_OPERATION     COUNT  AVG_MS   MIN_MS   MAX_MS   REQ_BYTES  RESP_BYTES
14:30:15 aws-cli      1234   GetObject        3      125.3    45.2     234.1    512        1048576
14:30:15 boto3-app    5678   PutObject        1      89.7     89.7     89.7     1024       0
14:30:15 s3cmd        9012   UploadPart(1)    1      456.2    456.2    456.2    5242880    0
```

### Prometheus Metrics

The Prometheus driver exports the following metrics:

- `s3slower_requests_total` - Total number of S3 requests
- `s3slower_request_errors_total` - Total number of S3 request errors
- `s3slower_request_duration_ms` - Average S3 request duration in milliseconds
- `s3slower_request_duration_min_ms` - Minimum S3 request duration
- `s3slower_request_duration_max_ms` - Maximum S3 request duration
- `s3slower_request_bytes_total` - Total S3 request bytes
- `s3slower_response_bytes_total` - Total S3 response bytes
- `s3slower_partial_requests_total` - Total number of multi-part requests

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

## System Requirements

- **Linux kernel** 4.4+ with eBPF support
- **Python** 3.9+
- **BCC** (BPF Compiler Collection) 0.25.0+
- **Root privileges** (required for eBPF programs)

### Installing BCC

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
```

#### CentOS/RHEL/Fedora
```bash
sudo yum install bcc-tools kernel-devel
# or
sudo dnf install bcc-tools kernel-devel
```

## Deployment

### Systemd Service

Create `/etc/systemd/system/s3slower.service`:

```ini
[Unit]
Description=S3Slower - S3 Latency Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/s3slower -C /etc/s3slower/s3slower.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo mkdir -p /etc/s3slower
sudo cp s3slower.yaml /etc/s3slower/
sudo systemctl enable s3slower
sudo systemctl start s3slower
```

### Docker

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    bpfcc-tools linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

COPY . /app
WORKDIR /app
RUN pip3 install .

CMD ["s3slower", "-C", "s3slower.yaml"]
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
        securityContext:
          privileged: true
        volumeMounts:
        - name: lib-modules
          mountPath: /lib/modules
          readOnly: true
        - name: usr-src
          mountPath: /usr/src
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
      - name: usr-src
        hostPath:
          path: /usr/src
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
      description: "{{ $labels.comm }} on {{ $labels.hostname }} has S3 {{ $labels.s3_operation }} latency of {{ $value }}ms"

  - alert: S3HighErrorRate
    expr: rate(s3slower_request_errors_total[5m]) > 0.1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High S3 error rate detected"
      description: "{{ $labels.comm }} on {{ $labels.hostname }} has S3 error rate of {{ $value }}/sec"
```

## Troubleshooting

### Common Issues

1. **Permission denied**: Ensure running as root or with proper capabilities
2. **BPF program load failed**: Check kernel version and BCC installation
3. **No events captured**: Verify S3 traffic is using HTTP (not just HTTPS headers)
4. **High CPU usage**: Increase `--min-latency-ms` to filter noise

### Debug Mode

Enable debug logging:
```bash
sudo s3slower -d screen --debug
```

View eBPF program:
```bash
s3slower --ebpf
```

## Performance Impact

S3Slower is designed for production use with minimal overhead:

- **CPU impact**: <1% additional CPU usage under normal load
- **Memory usage**: ~10-50MB depending on traffic volume
- **Network overhead**: None (passive monitoring)
- **Storage overhead**: Configurable buffer sizes

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   S3 Client     │    │    eBPF         │    │   S3Slower      │
│   Application   │────│   Kernel        │────│   Userspace     │
│                 │    │   Probes        │    │   Aggregator    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                              ┌────────────────────────┼────────────────────────┐
                              │                        │                        │
                    ┌─────────▼─────────┐    ┌─────────▼─────────┐    ┌─────────▼─────────┐
                    │   Screen Driver   │    │ Prometheus Driver │    │  Future Drivers   │
                    │   (Console)       │    │   (HTTP Server)   │    │  (Kafka, etc.)    │
                    └───────────────────┘    └───────────────────┘    └───────────────────┘
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

### Development Setup

```bash
git clone https://github.com/yourusername/s3slower.git
cd s3slower
pip install -e .[test]
pytest
```

## License

Apache License 2.0 - see LICENSE file for details.

## Support

- GitHub Issues: Report bugs and feature requests
- Documentation: See docs/ directory for detailed guides
- Examples: Check examples/ directory for usage patterns

## Comparison with Other Tools

| Tool | Approach | Pros | Cons |
|------|----------|------|------|
| S3Slower | eBPF | No instrumentation, minimal overhead | Requires root, Linux only |
| AWS X-Ray | SDK tracing | Rich details, cloud integration | Requires code changes |
| tcpdump | Packet capture | Universal | Manual analysis needed |
| Application logs | Custom logging | Application context | Requires code changes |

## Go Implementation (In Progress)

We are actively refactoring S3Slower from Python to Go to provide:

- **Single static binary** - No Python runtime or dependencies needed
- **Easy RPM/DEB packaging** - Simple installation via package managers
- **Lower memory footprint** - Reduced resource consumption
- **Faster startup** - No interpreter overhead
- **Native eBPF support** - Using cilium/ebpf library

### Current Status

| Component | Python | Go | Status |
|-----------|--------|-----|--------|
| Config loading | ✅ | ✅ | Complete |
| HTTP parsing | ✅ | ✅ | Complete |
| Process watcher | ✅ | ✅ | Complete |
| Event processing | ✅ | ✅ | Complete |
| Prometheus metrics | ✅ | ✅ | Complete |
| Terminal output | ✅ | ✅ | Complete |
| eBPF loader | ✅ (BCC) | ✅ (cilium/ebpf) | Complete |
| CLI commands | ✅ | ✅ | Complete |
| RPM packaging | ❌ | ✅ | Complete |

### eBPF Tracing Modes

The Go implementation supports multiple tracing modes:

| Mode | Description | Use Case |
|------|-------------|----------|
| `http` | Kprobes on sys_read/sys_write | Plain HTTP traffic |
| `openssl` | Uprobes on SSL_read/SSL_write | HTTPS via OpenSSL |
| `gnutls` | Uprobes on gnutls_record_* | HTTPS via GnuTLS |
| `nss` | Uprobes on PR_Read/PR_Write | HTTPS via NSS |
| `auto` | Attach all available probes | Mixed traffic |

### Test Coverage

- **Python tests**: 340 passing tests
- **Go tests**: 441 passing tests

### Try the Go Version

```bash
# Build from source
cd go
make build

# Run tests
make test

# Generate BPF program (requires clang, bpftool)
make generate

# Build RPM package
make rpm
```

### Go Project Structure

```
go/
├── cmd/s3slower/          # Main entry point
├── internal/
│   ├── cmd/               # CLI commands
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

For more details, see [go/README.md](go/README.md). 