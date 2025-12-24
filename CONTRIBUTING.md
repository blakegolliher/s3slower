# Contributing to s3slower

Thank you for your interest in contributing to s3slower! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/s3slower.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`

## Development Setup

```bash
# Install BCC tools (required)
sudo apt-get install bpfcc-tools python3-bpfcc  # Debian/Ubuntu
sudo yum install bcc-tools python3-bcc          # RHEL/CentOS

# Install Python dependencies
pip install -r requirements.txt

# Run the tool (requires root)
sudo ./s3slower.py
```

## Testing Changes

Use the test scripts in `scripts/` to generate S3 traffic:

```bash
# Terminal 1: Run s3slower
sudo ./s3slower.py --host-substr "your-endpoint"

# Terminal 2: Generate traffic
./scripts/aws-s3-test.sh
# or
./scripts/boto3-s3-test.py --iterations 10

# Correlate results
./scripts/s3slower_correlate.py --ops-log /tmp/... --trace-log /opt/s3slower/...
```

## Code Style

- Use Python type hints
- Follow PEP 8 guidelines
- Add docstrings to public functions
- Keep BPF code within verifier limits

## Submitting Changes

1. Ensure your code works with the test scripts
2. Update documentation if needed
3. Commit with a clear message describing the change
4. Push to your fork and open a Pull Request

## Reporting Issues

When reporting bugs, please include:
- Linux distribution and kernel version
- BCC version (`dpkg -l bpfcc-tools` or `rpm -q bcc-tools`)
- Steps to reproduce the issue
- Relevant output or error messages

## Areas for Contribution

- Bug fixes (especially the HTTP 100 Continue handling for boto3)
- Additional TLS library support
- HTTP/2 improvements
- Documentation and examples
- Performance optimizations
