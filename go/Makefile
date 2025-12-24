# S3Slower Go Build Configuration
#
# Build targets:
#   make build       - Build the binary
#   make test        - Run all tests
#   make test-cover  - Run tests with coverage
#   make rpm         - Build RPM package
#   make clean       - Clean build artifacts
#   make install     - Install to /usr/local/bin

BINARY_NAME := s3slower
VERSION := $(shell cat ../version.txt 2>/dev/null || echo "0.1.0")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go build flags
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE) -s -w"
GOFLAGS := -trimpath

# Directories
BUILD_DIR := build
DIST_DIR := dist

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build: $(BUILD_DIR)/$(BINARY_NAME)

$(BUILD_DIR)/$(BINARY_NAME): $(shell find . -name '*.go')
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(GOFLAGS) $(LDFLAGS) -o $@ ./cmd/s3slower

# Build for multiple architectures
.PHONY: build-all
build-all:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/s3slower
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/s3slower

# Run tests
.PHONY: test
test:
	go test -v ./...

# Run tests with race detection
.PHONY: test-race
test-race:
	go test -race -v ./...

# Run tests with coverage
.PHONY: test-cover
test-cover:
	@mkdir -p $(BUILD_DIR)
	go test -coverprofile=$(BUILD_DIR)/coverage.out ./...
	go tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "Coverage report: $(BUILD_DIR)/coverage.html"
	@go tool cover -func=$(BUILD_DIR)/coverage.out | tail -1

# Run tests with coverage and show summary
.PHONY: test-summary
test-summary:
	@echo "Running tests..."
	@go test -count=1 ./... 2>&1 | grep -E '^(ok|FAIL|---|\?)'
	@echo ""
	@echo "Test summary complete"

# Generate test report
.PHONY: test-report
test-report:
	@mkdir -p $(BUILD_DIR)
	go test -json ./... > $(BUILD_DIR)/test-results.json 2>&1 || true
	@echo "Test results: $(BUILD_DIR)/test-results.json"

# Lint the code
.PHONY: lint
lint:
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

# Format the code
.PHONY: fmt
fmt:
	go fmt ./...
	gofmt -s -w .

# Tidy dependencies
.PHONY: tidy
tidy:
	go mod tidy

# Download dependencies
.PHONY: deps
deps:
	go mod download

# Generate BPF program (requires clang, libbpf-dev)
.PHONY: generate
generate:
	@echo "Generating BPF program..."
	@which bpftool > /dev/null || (echo "bpftool required for vmlinux.h generation" && exit 1)
	@which clang > /dev/null || (echo "clang required for BPF compilation" && exit 1)
	@[ -f internal/ebpf/bpf/vmlinux.h ] || bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/bpf/vmlinux.h
	go generate ./internal/ebpf/...

# Build RPM package using nfpm
.PHONY: rpm
rpm: build
	@mkdir -p $(DIST_DIR)
	@which nfpm > /dev/null || go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
	nfpm package --config nfpm.yaml --packager rpm --target $(DIST_DIR)/

# Build DEB package using nfpm
.PHONY: deb
deb: build
	@mkdir -p $(DIST_DIR)
	@which nfpm > /dev/null || go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
	nfpm package --config nfpm.yaml --packager deb --target $(DIST_DIR)/

# Build all packages
.PHONY: packages
packages: rpm deb

# Install binary
.PHONY: install
install: build
	install -Dm755 $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	install -Dm644 ../systemd/s3slower.service /usr/lib/systemd/system/s3slower.service
	install -Dm644 ../s3slower.yaml /etc/s3slower/s3slower.yaml

# Uninstall binary
.PHONY: uninstall
uninstall:
	rm -f /usr/local/bin/$(BINARY_NAME)
	rm -f /usr/lib/systemd/system/s3slower.service
	rm -rf /etc/s3slower

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	go clean

# Show version
.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Date:    $(BUILD_DATE)"

# Development helpers
.PHONY: dev
dev: deps fmt lint test build

# CI pipeline
.PHONY: ci
ci: deps fmt lint test-race test-cover build

# Help
.PHONY: help
help:
	@echo "S3Slower Go Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build        Build the binary"
	@echo "  build-all    Build for linux/amd64 and linux/arm64"
	@echo "  test         Run all tests"
	@echo "  test-race    Run tests with race detection"
	@echo "  test-cover   Run tests with coverage report"
	@echo "  test-summary Show test summary"
	@echo "  lint         Run linter"
	@echo "  fmt          Format code"
	@echo "  rpm          Build RPM package"
	@echo "  deb          Build DEB package"
	@echo "  packages     Build all packages"
	@echo "  generate     Generate BPF program (requires clang, bpftool)"
	@echo "  install      Install to /usr/local/bin"
	@echo "  uninstall    Uninstall"
	@echo "  clean        Clean build artifacts"
	@echo "  deps         Download dependencies"
	@echo "  tidy         Tidy go.mod"
	@echo "  version      Show version info"
	@echo "  dev          Development workflow (deps, fmt, lint, test, build)"
	@echo "  ci           CI pipeline (deps, fmt, lint, test-race, test-cover, build)"
	@echo "  help         Show this help"
