# S3Slower - Python Version (Legacy)

> **Note**: This documents the legacy Python implementation. For the current Go implementation, see [README.md](README.md).

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

## Prerequisites

S3Slower requires BCC (BPF Compiler Collection) to be installed on your system:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

# CentOS/RHEL/Fedora
sudo yum install bcc-tools python3-bcc kernel-devel
# or
sudo dnf install bcc-tools python3-bcc kernel-devel
```

## Installation

**You must install the package before using the `s3slower` command:**

```bash
# Clone and install from source
git clone https://github.com/yourusername/s3slower.git
cd s3slower
sudo pip install .

# Or install in development mode
sudo pip install -e .
```

## Basic Usage

After installation, monitor all S3 operations with console output:
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

### Running Without Installation (Development)

If you want to run directly from the source directory without installing:
```bash
cd s3slower
sudo python -m s3slower.main -d screen
```

## Command Line Options

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

## Configuration File

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

## System Requirements

- **Linux kernel** 4.4+ with eBPF support
- **Python** 3.9+
- **BCC** (BPF Compiler Collection) 0.25.0+
- **Root privileges** (required for eBPF programs)

## Development Setup

```bash
git clone https://github.com/yourusername/s3slower.git
cd s3slower
pip install -e .[test]
pytest
```

### Install Dependencies

```bash
# Install runtime dependencies
pip install -r requirements.txt

# Install development/test dependencies
pip install -r requirements-dev.txt
```

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=s3slower --cov-report=html

# Run specific test file
pytest tests/test_config.py
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

## License

Apache License 2.0 - see LICENSE file for details.
