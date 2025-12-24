# s3slower

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-green.svg)](https://kernel.org)
[![eBPF](https://img.shields.io/badge/eBPF-powered-orange.svg)](https://ebpf.io)

**Trace S3 request latency without changing your code.**

> Ever wondered why your S3 requests are slow? s3slower uses eBPF to trace every S3 API call at the TLS layer—no code changes, no proxies, no sampling. See exactly which requests are slow, to which bucket, with what latency.

## Why s3slower?

- **Zero instrumentation** — Works with any S3 client (AWS CLI, boto3, SDKs, curl) without modification
- **TLS visibility** — Traces encrypted HTTPS traffic by hooking TLS libraries, not network packets
- **Production-ready** — Prometheus metrics, log rotation, auto-attach to new processes
- **Universal** — Works with AWS S3, MinIO, Ceph, and any S3-compatible storage

## Quick Demo

```
TIME     PID    COMM             TARGET     OP           LAT(ms) STATUS BUCKET               ENDPOINT
14:23:01 1234   aws              aws        GET             12.34 200    mybucket             s3.amazonaws.com
14:23:02 1234   aws              aws        PUT            145.67 200    mybucket             s3.amazonaws.com
14:23:03 5678   python3          boto3      LIST             8.21 200    data-lake            s3.us-west-2.amazonaws.com
```

## Overview

`s3slower` uses eBPF (extended Berkeley Packet Filter) to instrument TLS libraries at the user-space level and HTTP traffic at the syscall layer, capturing the complete lifecycle of S3 HTTP/HTTPS requests from write to first read. It provides real-time latency metrics and statistics for S3 API operations.

### Key Features

- **TLS-level tracing**: Captures latency between SSL_write and SSL_read operations
- **Plain HTTP tracing**: Captures latency for unencrypted HTTP S3 traffic via send/recv syscalls
- **HTTP/S3 parsing**: Extracts HTTP method, host, path, and S3-specific metadata from traffic
- **Multiple TLS libraries**: Supports OpenSSL, GnuTLS, and NSS/NSPR
- **Auto-TLS mode**: Automatically detects and attaches to available TLS libraries
- **Latency statistics**: Per-operation p50, p90, p99 percentiles
- **Prometheus integration**: Optional metrics export for monitoring systems
- **Configurable logging**: YAML-driven settings for Prometheus listener, metrics refresh, and rotated transaction logs
- **Packaging helpers**: Makefile targets for RPM/DEB builds installing binaries, config, and log directory
- **Filtering capabilities**: Filter by PID, host, HTTP method, or minimum latency
- **Auto-attach watch mode**: Optional exec tracepoint watcher that auto-attaches to PIDs whose command matches a YAML target config

## Requirements

- Linux kernel 4.4+ with BPF support
- Python 3.6+
- BCC (BPF Compiler Collection) tools
- Root privileges (required for eBPF)

## Installation

1. Install BCC tools for your distribution:

   **Ubuntu/Debian:**
   ```bash
   sudo apt-get install bpfcc-tools python3-bpfcc
   ```

   **RHEL/CentOS/Fedora:**
   ```bash
   sudo yum install bcc-tools python3-bcc
   ```

   **Arch Linux:**
   ```bash
   sudo pacman -S bcc bcc-tools python-bcc
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Make the script executable:
   ```bash
   chmod +x s3slower.py
   ```

## Configuration

- Default config path: `/etc/s3slower/config.yaml` (override with `--config`).
- Precedence: built-in defaults → config file → CLI flags.
- Transaction logging is enabled by default and writes TSV entries to `/opt/s3slower/s3slower.log` with size-based rotation (100 MB, 5 backups). Use `logging.enabled: false` or `--no-log-file` to disable; `max_size_mb <= 0` disables rotation.
- PyYAML is required when a config file is present (see `requirements.txt`).

Example config:

```yaml
logging:
  enabled: true
  path: /opt/s3slower/s3slower.log
  max_size_mb: 100
  max_backups: 5
prometheus:
  host: 0.0.0.0
  port: 9102
metrics:
  refresh_interval_seconds: 5
```

## Usage

### Basic Usage

Trace all S3 HTTP/HTTPS traffic system-wide:
```bash
sudo ./s3slower.py
```

### Common Examples

**Trace specific process:**
```bash
sudo ./s3slower.py --pid 12345
```

**Filter by S3 endpoint:**
```bash
sudo ./s3slower.py --host-substr "s3.amazonaws.com"
```

**Show only slow requests (>100ms):**
```bash
sudo ./s3slower.py --min-lat-ms 100
```

**Filter by HTTP method:**
```bash
sudo ./s3slower.py --method GET
```

**Export Prometheus metrics:**
```bash
sudo ./s3slower.py --prometheus-port 8080
```

**Bind Prometheus + tune refresh interval:**
```bash
sudo ./s3slower.py --prometheus-host 127.0.0.1 --prometheus-port 8080 --metrics-refresh-interval 2
```

**Auto-attach matching PIDs (watch mode):**
```bash
sudo ./s3slower.py --watch-config                 # uses /etc/s3slower/targets.yml
sudo ./s3slower.py --watch-config ./targets.yml   # custom path
```

Create `/etc/s3slower/targets.yml` to describe which commands to trace:
```yaml
targets:
  - id: "mc"
    match:
      type: "exe_basename"   # also checks comm for safety
      value: "mc"
    mode: "go_tls"           # or "openssl"/"http"/"gnutls"/"nss"
    prom_labels:
      app: "minio-client"
  - id: "aws"
    match:
      type: "comm"
      value: "aws"
    mode: "openssl"
    prom_labels:
      app: "aws-cli"
```
The watcher hooks `sched:sched_process_exec`, conservatively matches against `comm`, `/proc/<pid>/exe` basename, and optional cmdline substrings, then attaches s3slower to the PID. Duplicate attaches are avoided.
Prometheus label set is fixed at startup; restart the tool if you add new `prom_labels` keys to the targets file.

**Use specific TLS library:**
```bash
sudo ./s3slower.py --openssl
sudo ./s3slower.py --gnutls --libgnutls /usr/lib/x86_64-linux-gnu/libgnutls.so.30
```

**Trace only plain HTTP (no TLS libraries):**
```bash
sudo ./s3slower.py --http-only
```

**Disable plain HTTP tracing (TLS libraries only):**
```bash
sudo ./s3slower.py --no-http
```

**Override or disable transaction log file:**
```bash
sudo ./s3slower.py --log-file /var/log/s3slower.tsv --log-max-size-mb 200 --log-max-backups 10
sudo ./s3slower.py --no-log-file
```

### Example Output

```
TIME     PID    COMM             TARGET     OP           LAT(ms) STATUS BUCKET               ENDPOINT             PATH
14:23:01 1234   aws              aws        GET             12.34 200    mybucket             s3.amazonaws.com     /mybucket/object.txt
14:23:02 1234   aws              aws        PUT             45.67 200    mybucket             s3.amazonaws.com     /mybucket/large-file.zip
14:23:03 4242   minio-mc         mc         MPU_CREATE      78.90 200    demo-bucket          play.min.io          /demo-bucket/foo?uploads
```
Prometheus metrics expose `bucket`, `endpoint`, `method`, `pid`, and `target` labels by default, plus any extra labels set in `prom_labels` entries in the targets YAML.

## Command Line Options

| Option | Description |
|--------|-------------|
| `--config PATH` | YAML config path (default: `/etc/s3slower/config.yaml`) |
| `--pid PID` | Trace only this process ID |
| `--openssl` | Explicitly attach to OpenSSL |
| `--gnutls` | Explicitly attach to GnuTLS |
| `--nss` | Explicitly attach to NSS/NSPR |
| `--libssl PATH` | Path to OpenSSL library |
| `--libgnutls PATH` | Path to GnuTLS library |
| `--libnss PATH` | Path to NSS library |
| `--http-only` | Trace only plain HTTP over TCP (disable TLS library probes) |
| `--no-http` | Disable plain HTTP tracing; only trace TLS libraries |
| `--host-substr STR` | Filter by Host header substring |
| `--method METHOD` | Filter by HTTP method (GET, PUT, POST, DELETE, HEAD) |
| `--min-lat-ms MS` | Only show requests >= this latency (ms) |
| `--include-unknown` | Include non-HTTP TLS traffic |
| `--prometheus-host HOST` | Bind address for Prometheus `/metrics` listener (overrides config) |
| `--prometheus-port PORT` | Expose Prometheus metrics on this port (overrides config; 0 disables) |
| `--metrics-refresh-interval SECONDS` | Interval between Prometheus metric flushes |
| `--log-file PATH` | TSV transaction log path (overrides config; rotation still applies) |
| `--log-max-size-mb MB` | Max log size before rotation (<=0 disables rotation) |
| `--log-max-backups COUNT` | How many rotated logs to keep |
| `--watch-config [PATH]` | Enable PID auto-attach using a target YAML file (default: `/etc/s3slower/targets.yml`) |
| `--no-log-file` | Disable transaction logging |

## Architecture

`s3slower` consists of two main components:

1. **BPF Program (Kernel Space)**:
   - Attaches uprobes to TLS library functions
   - Attaches kprobes to sendto/recvfrom syscalls for plain HTTP
   - Captures function arguments and return values
   - Tracks per-connection state and timing
   - Sends events to user space via perf buffer

2. **Python Program (User Space)**:
   - Loads and manages BPF program
   - Processes kernel events
   - Parses HTTP headers from TLS payloads
   - Calculates statistics and displays results
   - Auto-attaches to new PIDs that match the targets config (watch mode)
   - Exposes console output and Prometheus metrics with PID/target labels
   - Optionally exports Prometheus metrics

The tool works by:
1. Attaching probes to TLS write functions (SSL_write, gnutls_record_send, PR_Write) and HTTP send syscalls (sendto)
2. Parsing HTTP request headers from the write buffer
3. Recording timestamp and connection metadata
4. Attaching probes to TLS read functions (SSL_read, gnutls_record_recv, PR_Read) and HTTP recv syscalls (recvfrom)
5. Matching read events with pending write events
6. Calculating latency and updating statistics

## Packaging

`Makefile` targets build RPM (rpmbuild) and DEB (fpm) packages:

```bash
make rpm        # build RHEL/Fedora RPM using rpmbuild (outputs to dist/rpmbuild/RPMS/)
make rpm_fpm    # alternative RPM build using fpm (requires Ruby fpm gem)
make deb        # build Debian/Ubuntu package with fpm
```

Install layout:
- Binary: `/usr/bin/s3slower`
- Config: `/etc/s3slower/config.yaml` (marked as a config file and not overwritten on upgrade)
- Log dir: `/opt/s3slower/` (created by post-install script)

Prereqs:
- RPM: `rpm-build`, `tar`, `python3`, `bcc` (runtime deps are declared in the spec; Prometheus client can be installed via pip if not packaged).
- DEB: `fpm` gem or package, plus `python3`, `bcc` runtime deps.

Defaults:
- `VERSION` defaults to `0.2.0`; override with `make VERSION=0.3.0 rpm`.
- `ITERATION` auto-uses a timestamp so each build revs uniquely; override if needed (`make ITERATION=2 rpm`).

## Testing

Test scripts are included to generate S3 traffic for validation:

```bash
# Set up environment
export S3_ENDPOINT="https://s3.amazonaws.com"
export S3_BUCKET="your-test-bucket"
export AWS_PROFILE="your-profile"

# Run test traffic generator (in one terminal)
./scripts/aws-s3-test.sh

# Trace the traffic (in another terminal)
sudo ./s3slower.py --host-substr "s3.amazonaws.com"
```

Available test scripts:
- `scripts/aws-s3-test.sh` — AWS CLI traffic generator with per-operation logging
- `scripts/curl-s3-test.sh` — curl with SigV4 signing for HTTP/1.1 traffic
- `scripts/boto3-s3-test.py` — Python boto3 traffic over HTTP/HTTPS
- `scripts/s3slower_correlate.py` — correlate test logs with s3slower output for validation

## Limitations

- Requires root privileges for eBPF
- Supports HTTP/1.x traffic over TLS and plain TCP; HTTP/2 is experimental
- Limited to user-space TLS libraries (OpenSSL, GnuTLS, NSS)
- Known issue: Some boto3 HTTPS PUT operations with "HTTP 100 Continue" may not be captured correctly
- Maximum buffer sizes for request/response parsing (256 bytes for headers)

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Setting up a development environment
- Running tests
- Submitting pull requests

## Acknowledgments

This tool is built on top of the BCC (BPF Compiler Collection) framework and inspired by various eBPF tracing tools in the BCC toolkit.
