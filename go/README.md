# S3Slower Go Implementation

A complete rewrite of S3Slower in Go, providing a single static binary for easy deployment.

## Overview

S3Slower is an eBPF-based monitoring tool that traces S3 client-side latency without requiring SDK instrumentation. This Go implementation provides:

- **Single binary deployment** - No dependencies, no Python runtime
- **RPM/DEB packaging** - Easy installation via package managers
- **Systemd integration** - Run as a background service
- **Prometheus metrics** - Export metrics for monitoring
- **Terminal display** - Real-time operation display
- **Process watching** - Auto-attach to mc, warp, and other S3 clients

## Quick Start

### Build from Source

```bash
# Build the binary
make build

# Run tests
make test

# Build with coverage
make test-cover
```

### Install

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

### Run

```bash
# Run with terminal output
s3slower run

# Run with Prometheus exporter
s3slower run --prometheus --port 9000

# Attach to specific process
s3slower attach --pid 12345

# Run as systemd service
sudo systemctl start s3slower
sudo systemctl enable s3slower
```

## Project Structure

```
go/
├── cmd/
│   └── s3slower/          # Main application entry point
│       └── main.go
├── internal/
│   ├── cmd/               # CLI commands (cobra)
│   │   └── root.go
│   ├── config/            # Configuration loading
│   │   ├── config.go
│   │   └── config_test.go
│   ├── ebpf/              # eBPF loader (cilium/ebpf)
│   │   ├── bpf/           # BPF C source code
│   │   ├── tracer.go      # BPF program management
│   │   ├── library.go     # TLS library detection
│   │   ├── pipeline.go    # Event processing pipeline
│   │   └── *_test.go
│   ├── event/             # Event processing
│   │   ├── event.go
│   │   └── event_test.go
│   ├── http/              # HTTP parsing
│   │   ├── parser.go
│   │   └── parser_test.go
│   ├── logger/            # Rotating file logger
│   │   ├── logger.go
│   │   └── logger_test.go
│   ├── metrics/           # Prometheus metrics
│   │   ├── metrics.go
│   │   └── metrics_test.go
│   ├── runner/            # Main execution loop
│   │   ├── runner.go
│   │   └── runner_test.go
│   ├── terminal/          # Terminal output
│   │   ├── terminal.go
│   │   └── terminal_test.go
│   ├── utils/             # Utility functions
│   │   ├── utils.go
│   │   └── utils_test.go
│   └── watcher/           # Process watching
│       ├── watcher.go
│       └── watcher_test.go
├── go.mod
├── go.sum
├── Makefile
├── nfpm.yaml              # Package configuration
└── README.md
```

## Test Coverage

The Go implementation includes comprehensive tests (498 total):

| Package | Tests | Coverage | Description |
|---------|-------|----------|-------------|
| config | 37 | 92% | YAML loading, validation, target matching |
| ebpf | 116 | 52% | eBPF loader, tracer, pipeline, library detection |
| event | 38 | 94% | Event processing, request correlation |
| http | 78 | 91% | HTTP parsing, bucket/endpoint extraction |
| logger | 27 | 87% | Rotating file logger, size-based rotation |
| metrics | 20 | 86% | Prometheus metrics, sample buffering |
| runner | 30 | 44% | Main execution loop, event handling |
| terminal | 59 | 95% | Output formatting, color codes |
| utils | 42 | 92% | Utility functions, file operations |
| watcher | 51 | 95% | Process classification, PID watching |

Run tests:

```bash
# Run all tests
make test

# Run with verbose output
go test -v ./...

# Run with coverage
make test-cover
# Coverage report: build/coverage.html

# Run specific package tests
go test -v ./internal/config/...

# Run with race detection
make test-race
```

## Configuration

### Main Configuration (`/etc/s3slower/s3slower.yaml`)

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

  - id: boto3
    match:
      type: cmdline_substring # Match by command line
      value: boto3
    mode: openssl

  - id: mc
    match:
      type: exe_basename      # Match by executable name
      value: mc
    mode: openssl
    prom_labels:
      client: minio-client
```

## CLI Reference

```
Usage:
  s3slower [command]

Available Commands:
  run         Run s3slower tracer
  attach      Attach to a specific process
  version     Print version information
  help        Help about any command

Flags:
  -h, --help      help for s3slower
  -v, --version   version for s3slower

Run Flags:
  -C, --config string      Path to config file
      --prometheus         Enable Prometheus exporter
  -p, --port int           Prometheus exporter port (default 9000)
      --host string        Prometheus exporter host (default "::")
      --min-latency uint   Minimum latency in ms to report (default 0)
      --watch strings      Process names to watch (e.g., mc,warp)
      --mode string        Probe mode: auto, http, openssl, gnutls, nss (default "auto")
      --debug              Enable debug output
      --log-dir string     Log directory (default "/var/log/s3slower")
      --log-max-size int   Max log size in MB before rotation (default 100)
      --no-log             Disable file logging

Attach Flags:
      --pid int            Process ID to attach to
      --mode string        Probe mode: auto, openssl, gnutls, nss, http (default "auto")
      --min-latency uint   Minimum latency in ms to report (default 0)
      --log-dir string     Log directory (default "/var/log/s3slower")
      --no-log             Disable file logging
```

## Building Packages

### RPM (RHEL/CentOS/Fedora)

```bash
make rpm
# Output: dist/s3slower-<version>-1.x86_64.rpm
```

### DEB (Debian/Ubuntu)

```bash
make deb
# Output: dist/s3slower_<version>_amd64.deb
```

### Multiple Architectures

```bash
make build-all
# Output:
#   build/s3slower-linux-amd64
#   build/s3slower-linux-arm64
```

## Systemd Service

After installation, manage with systemd:

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

## Prometheus Metrics

When running with `--prometheus`, the following metrics are exported:

| Metric | Type | Description |
|--------|------|-------------|
| s3slower_requests_total | Counter | Total S3 requests |
| s3slower_request_errors_total | Counter | Total request errors |
| s3slower_request_duration_ms | Histogram | Request latency |
| s3slower_request_duration_min_ms | Gauge | Minimum latency |
| s3slower_request_duration_max_ms | Gauge | Maximum latency |
| s3slower_request_bytes_total | Counter | Total request bytes |
| s3slower_response_bytes_total | Counter | Total response bytes |
| s3slower_partial_requests_total | Counter | Multipart requests |

## Development

### Prerequisites

- Go 1.24+
- Linux kernel 4.4+ with eBPF support
- Root access (for eBPF attachment)

### Useful Commands

```bash
# Format code
make fmt

# Run linter
make lint

# Tidy dependencies
make tidy

# Full development workflow
make dev

# CI pipeline
make ci

# Clean build artifacts
make clean
```

## Migration from Python

This Go implementation is designed to be a drop-in replacement for the Python version:

- Same configuration file format
- Same Prometheus metrics names and labels
- Same CLI options
- Same systemd service integration

The main differences are:
1. Single static binary (no Python runtime required)
2. Faster startup time
3. Lower memory footprint
4. No BCC/bpfcc dependency at runtime (uses cilium/ebpf)

## License

Apache-2.0
