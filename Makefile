# S3Slower - eBPF-based S3 Client Latency Tracer
#
# Build targets:
#   make build       - Build the binary
#   make test        - Run all tests
#   make rpm         - Build RPM package
#   make deb         - Build DEB package
#   make install     - Install to system
#   make clean       - Clean build artifacts
#
# Requirements:
#   - Go 1.21+
#   - For packaging: nfpm (auto-installed if missing)
#   - For BPF generation: clang, bpftool

BINARY_NAME := s3slower
VERSION := $(shell cat version.txt 2>/dev/null || echo "0.1.0")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_TS := $(shell date -u +"%Y%m%d%H%M%S")
GOBIN := $(shell go env GOPATH)/bin
NFPM := $(GOBIN)/nfpm

# Go build flags
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE) -s -w"
GOFLAGS := -trimpath

# Directories
BUILD_DIR := build
DIST_DIR := dist

.PHONY: all build test test-race test-cover test-validate test-stress lint fmt tidy deps \
        rpm deb packages install uninstall clean generate version dev ci help \
        monitoring-up monitoring-down monitoring-logs

# Default target
all: build

# BPF source and generated output
BPF_SRC := internal/ebpf/bpf/s3slower.c
BPF_OBJ := internal/ebpf/bpf_x86_bpfel.o

# Build the binary
build: $(BUILD_DIR)/$(BINARY_NAME)

$(BPF_OBJ): $(BPF_SRC)
	$(MAKE) generate

$(BUILD_DIR)/$(BINARY_NAME): $(BPF_OBJ) $(shell find . -name '*.go' -not -path './.git/*')
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(GOFLAGS) $(LDFLAGS) -o $@ ./cmd/s3slower

# Run tests
test:
	go test -v ./...

# Run tests with race detection
test-race:
	go test -race -v ./...

# Run E2E validation tests (requires root, S3 endpoint, AWS credentials)
test-validate: build
	@echo "Running validation tests (requires root, S3 endpoint, AWS credentials)..."
	sudo -E S3SLOWER_BIN=$(BUILD_DIR)/$(BINARY_NAME) validation_test/run_validation.sh

# Run long-running stress test (requires root, S3 endpoint, AWS credentials)
test-stress: build
	@echo "Running stress test (requires root, S3 endpoint, AWS credentials)..."
	sudo -E S3SLOWER_BIN=$(BUILD_DIR)/$(BINARY_NAME) validation_test/stress/run_stress_test.sh

# Start Prometheus + Grafana monitoring stack
monitoring-up:
	cd monitoring && podman-compose up -d

# Stop Prometheus + Grafana monitoring stack
monitoring-down:
	cd monitoring && podman-compose down

# Tail monitoring container logs
monitoring-logs:
	cd monitoring && podman-compose logs -f

# Run tests with coverage
test-cover:
	@mkdir -p $(BUILD_DIR)
	go test -coverprofile=$(BUILD_DIR)/coverage.out ./...
	go tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "Coverage report: $(BUILD_DIR)/coverage.html"
	@go tool cover -func=$(BUILD_DIR)/coverage.out | tail -1

# Run linter
lint:
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

# Format code
fmt:
	go fmt ./...
	gofmt -s -w .

# Tidy dependencies
tidy:
	go mod tidy

# Download dependencies
deps:
	go mod download

# Generate BPF program (requires clang, bpftool)
KERNEL_VERSION := $(shell uname -r)
KERNEL_SRC := $(shell if [ -d /usr/src/kernels/$(KERNEL_VERSION) ]; then echo /usr/src/kernels/$(KERNEL_VERSION); else ls -d /usr/src/kernels/* 2>/dev/null | head -1; fi)
LIBBPF_INCLUDE := -I$(KERNEL_SRC)/tools/lib/bpf -I$(KERNEL_SRC)/tools/bpf/resolve_btfids/libbpf/include

generate:
	@echo "Generating BPF program..."
	@which bpftool > /dev/null || (echo "bpftool required for vmlinux.h generation" && exit 1)
	@which clang > /dev/null || (echo "clang required for BPF compilation" && exit 1)
	@[ -f internal/ebpf/bpf/vmlinux.h ] || bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/bpf/vmlinux.h
	@echo "Using libbpf headers from: $(KERNEL_SRC)"
	cd internal/ebpf && GOPACKAGE=ebpf go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -target amd64 bpf bpf/s3slower.c -- $(LIBBPF_INCLUDE) -Ibpf

# Build RPM package (timestamped to the second)
rpm: build $(NFPM)
	VERSION=$(VERSION) RELEASE=$(BUILD_TS) $(NFPM) package --config nfpm.yaml --packager rpm --target .

# Build DEB package (timestamped to the second)
deb: build $(NFPM)
	VERSION=$(VERSION) RELEASE=$(BUILD_TS) $(NFPM) package --config nfpm.yaml --packager deb --target .

$(NFPM):
	go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.1

# Build all packages
packages: rpm deb

# Install binary
install: build
	install -Dm755 $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	install -Dm644 systemd/s3slower.service /usr/lib/systemd/system/s3slower.service
	install -Dm644 s3slower.yaml /etc/s3slower/s3slower.yaml

# Uninstall binary
uninstall:
	rm -f /usr/local/bin/$(BINARY_NAME)
	rm -f /usr/lib/systemd/system/s3slower.service
	rm -rf /etc/s3slower

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -f *.rpm *.deb
	go clean

# Show version
version:
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Date:    $(BUILD_DATE)"

# Development workflow
dev: deps fmt lint test build

# CI pipeline
ci: deps fmt lint test-race test-cover build

# Help
help:
	@echo "S3Slower Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build:"
	@echo "  build        Build the binary"
	@echo "  clean        Clean build artifacts"
	@echo ""
	@echo "Test:"
	@echo "  test          Run all tests"
	@echo "  test-race     Run tests with race detection"
	@echo "  test-cover    Run tests with coverage report"
	@echo "  test-validate Run E2E validation (requires root + S3)"
	@echo "  test-stress   Run long-running stress test (requires root + S3)"
	@echo ""
	@echo "Package:"
	@echo "  rpm          Build RPM package"
	@echo "  deb          Build DEB package"
	@echo "  packages     Build all packages (RPM and DEB)"
	@echo ""
	@echo "Install:"
	@echo "  install      Install to /usr/local/bin"
	@echo "  uninstall    Uninstall from system"
	@echo ""
	@echo ""
	@echo "Monitoring:"
	@echo "  monitoring-up   Start Prometheus + Grafana"
	@echo "  monitoring-down Stop Prometheus + Grafana"
	@echo "  monitoring-logs Tail monitoring container logs"
	@echo ""
	@echo "Development:"
	@echo "  fmt          Format code"
	@echo "  lint         Run linter"
	@echo "  deps         Download dependencies"
	@echo "  tidy         Tidy go.mod"
	@echo "  generate     Generate BPF program (requires clang, bpftool)"
	@echo "  dev          Development workflow (deps, fmt, lint, test, build)"
	@echo "  ci           CI pipeline (deps, fmt, lint, test-race, test-cover, build)"
	@echo ""
	@echo "Info:"
	@echo "  version      Show version info"
	@echo "  help         Show this help"
