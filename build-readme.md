# Build Guide for S3Slower

This document provides build instructions for S3Slower, an eBPF-based S3 client-side latency monitoring tool.

## Prerequisites

### System Requirements

- **Linux kernel**: 4.4+ with eBPF support
- **Root privileges**: Required for eBPF attachment
- **Architecture**: x86_64 or arm64

### Python Version Requirements

- Python 3.9+
- pip
- BCC/eBPF tools installed on the system

### Go Version Requirements

- Go 1.24.0+
- GNU Make
- nfpm (for package building, optional)

## Building the Python Version

### Install Dependencies

```bash
# Install runtime dependencies
pip install -r requirements.txt

# Install development/test dependencies
pip install -r requirements-dev.txt
```

### Install the Package

```bash
# Standard installation
pip install .

# Development mode (editable install)
pip install -e .

# With test dependencies
pip install -e .[test]
```

### Run Tests (Python)

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=s3slower --cov-report=html

# Run specific test file
pytest tests/test_config.py

# Quick run without coverage/headers
pytest --no-cov --no-header -q

# Run only unit tests
pytest -m unit
```

## Building the Go Version

All Go build commands should be run from the `go/` directory:

```bash
cd go
```

### Quick Build

```bash
# Build binary to go/build/s3slower
make build
```

### Full Development Workflow

```bash
# Run full dev workflow: deps, fmt, lint, test, build
make dev
```

### Build Commands

| Command | Description |
|---------|-------------|
| `make build` | Build binary for current platform |
| `make build-all` | Build for linux/amd64 and linux/arm64 |
| `make clean` | Clean build artifacts |

### Run Tests (Go)

```bash
# Run all tests
make test

# Run with race detection
make test-race

# Run with coverage report
make test-cover

# View test summary
make test-summary
```

Coverage report is generated at `go/build/coverage.html`.

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint

# Check dependencies
make deps
```

### Installation

```bash
# Install to /usr/local/bin (requires sudo)
sudo make install

# Uninstall
make uninstall
```

## Building Packages

The Go version supports building RPM and DEB packages using nfpm.

```bash
cd go

# Build RPM package
make rpm

# Build DEB package
make deb

# Build both packages
make packages
```

Packages are output to `go/dist/`.

## CI Pipeline

For continuous integration environments:

```bash
cd go
make ci
```

This runs: `deps` → `fmt` → `lint` → `test-race` → `test-cover` → `build`

## Running S3Slower

### Python Version

```bash
# Console output
sudo s3slower -d screen

# Prometheus metrics
sudo s3slower -d prometheus

# With config file
sudo s3slower -C s3slower.yaml
```

### Go Version

```bash
# Terminal output
./go/build/s3slower run

# Prometheus metrics on port 9000
./go/build/s3slower run --prometheus --port 9000

# Attach to specific process
./go/build/s3slower attach --pid 12345

# As systemd service (after package install)
sudo systemctl start s3slower
```

## Project Structure

```
s3slower/
├── go/                     # Go implementation
│   ├── cmd/s3slower/       # CLI entry point
│   ├── internal/           # Internal packages
│   ├── Makefile            # Build system
│   └── nfpm.yaml           # Package configuration
├── s3slower/               # Python implementation
│   ├── main.py             # CLI entry point
│   ├── core.py             # Core tracing logic
│   └── drivers/            # Output drivers
├── tests/                  # Python test suite
├── requirements.txt        # Python runtime dependencies
├── requirements-dev.txt    # Python dev dependencies
├── setup.py                # Python package setup
└── s3slower.yaml           # Configuration file
```

## Troubleshooting

### Build Issues

- Ensure Go 1.24+ is installed: `go version`
- Ensure Python 3.9+ is installed: `python3 --version`
- For Go builds, run from the `go/` directory

### Runtime Issues

- eBPF requires root privileges
- Check kernel version: `uname -r` (4.4+ required)
- See `LINUX_TROUBLESHOOTING.md` for detailed troubleshooting
