# Build Guide for S3Slower

This document provides build instructions for S3Slower, an eBPF-based S3 client-side latency monitoring tool.

## Prerequisites

### System Requirements

- **Linux kernel**: 4.4+ with eBPF support
- **Root privileges**: Required for eBPF attachment
- **Architecture**: x86_64 or arm64

### Go Requirements

- Go 1.24.0+
- GNU Make
- nfpm (for package building, optional)

## Building from Source

All build commands should be run from the `go/` directory:

```bash
cd go
```

### Quick Build

```bash
# Build binary to go/build/s3slower
make build
```

The binary will be created at `go/build/s3slower`.

### Full Development Workflow

```bash
# Run full dev workflow: deps, fmt, lint, test, build
make dev
```

## Build Commands

| Command | Description |
|---------|-------------|
| `make build` | Build binary for current platform |
| `make build-all` | Build for linux/amd64 and linux/arm64 |
| `make clean` | Clean build artifacts |
| `make test` | Run all tests |
| `make test-race` | Run tests with race detection |
| `make test-cover` | Run tests with coverage report |
| `make fmt` | Format code |
| `make lint` | Run linter |
| `make deps` | Download dependencies |
| `make dev` | Development workflow (deps, fmt, lint, test, build) |
| `make ci` | CI pipeline (deps, fmt, lint, test-race, test-cover, build) |

## Installation

```bash
cd go

# Install to /usr/local/bin (requires sudo)
sudo make install

# Uninstall
sudo make uninstall
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

### Installing Packages

```bash
# RPM (RHEL/CentOS/Fedora)
sudo rpm -i dist/s3slower-*.rpm

# DEB (Debian/Ubuntu)
sudo dpkg -i dist/s3slower-*.deb
```

## Running S3Slower

```bash
# Terminal output (run from go/ directory after build)
sudo ./build/s3slower run

# With Prometheus metrics on port 9000
sudo ./build/s3slower run --prometheus --port 9000

# With config file
sudo ./build/s3slower run -C ../s3slower.yaml

# Attach to specific process
sudo ./build/s3slower attach --pid 12345

# After system-wide installation
sudo s3slower run
```

## Project Structure

```
s3slower/
├── go/                     # Go implementation (primary)
│   ├── cmd/s3slower/       # CLI entry point
│   ├── internal/           # Internal packages
│   ├── Makefile            # Build system
│   └── nfpm.yaml           # Package configuration
├── s3slower/               # Python implementation (legacy)
├── tests/                  # Python test suite (legacy)
├── s3slower.yaml           # Configuration file
├── README.md               # Main documentation
├── LEGACY_README.md        # Python documentation
└── build-readme.md         # This file
```

## Troubleshooting

### Build Issues

- Ensure Go 1.24+ is installed: `go version`
- Run build commands from the `go/` directory
- If `make build` says "Nothing to be done", you may be in the wrong directory

### "Nothing to be done for 'build'" Error

This happens when running `make build` from the root directory instead of `go/`:

```bash
# Wrong (from root directory - no Makefile here)
make build
# Output: make: Nothing to be done for 'build'.

# Correct (from go/ directory)
cd go
make build
```

### Runtime Issues

- eBPF requires root privileges
- Check kernel version: `uname -r` (4.4+ required)
- See `LINUX_TROUBLESHOOTING.md` for detailed troubleshooting

## Legacy Python Version

The Python version is deprecated. For Python documentation, see [LEGACY_README.md](LEGACY_README.md).
