# Changelog

All notable changes to s3slower will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-01-01

### Added
- Modular package structure (`s3slower/` directory)
- curl and boto3 test scripts for traffic generation
- Log correlation tool (`scripts/s3slower_correlate.py`)
- Plain HTTP tracing via sendto/recvfrom syscalls
- Auto-attach watch mode for dynamic process tracing
- Prometheus metrics with customizable labels
- Transaction logging with size-based rotation
- RPM and DEB packaging support

### Changed
- Refactored from single file to module structure
- Improved HTTP request/response matching with sequence numbers

## [0.1.0] - 2024-12-01

### Added
- Initial release
- eBPF-based TLS tracing for S3 requests
- Support for OpenSSL, GnuTLS, and NSS/NSPR
- Per-operation latency statistics (p50, p90, p99)
- Filtering by PID, host, method, and minimum latency
- Basic Prometheus metrics export
