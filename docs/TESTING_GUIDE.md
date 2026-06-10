# S3Slower: Testing & Quality Assurance Guide

This document outlines the strategy for improving test coverage and ensuring the
long-term stability of s3slower. It serves as a roadmap for fixing broken tests,
improving portability, and implementing comprehensive integration testing.

---

## Table of Contents

1. [Fix Existing Broken Tests](#1-fix-existing-broken-tests)
2. [Portability & Platform Independence](#2-portability--platform-independence)
3. [Full Integration Testing](#3-full-integration-testing)
4. [Mocking Infrastructure Improvements](#4-mocking-infrastructure-improvements)
5. [Performance & Race Detection](#5-performance--race-detection)
6. [Coverage Targets](#6-coverage-targets)

---

## 1. Fix Existing Broken Tests

### Problem: Terminal Truncation
`TestWriteEvent/table_mode` in `internal/terminal/terminal_test.go` fails because
the endpoint "s3.amazonaws.com" (16 chars) is truncated to "s3.amazonaws..." (15 chars).

**Solution**:
- Update the `ENDPOINT` column width in `internal/terminal/terminal.go` from 15 to 20.
- Update the test expectation to match the full string or a larger truncation.

### Problem: Watcher /proc Dependency
`TestReadExeBasename` and `TestReadCmdline` in `internal/watcher/watcher_test.go`
fail on non-Linux systems because they rely on the `/proc` filesystem.

**Solution**:
- Use build tags (`//go:build linux`) for tests that strictly require Linux.
- Implement more robust mocking for the process filesystem in `watcher_test.go`.

---

## 2. Portability & Platform Independence

### Problem: BPF Build Failures
The `internal/ebpf` package fails to compile on non-x86/non-Linux platforms (like
Apple Silicon) because the generated BPF code is missing or build-tagged for specific
architectures.

**Solution**:
- Provide stub implementations of `loadBpf` and other generated functions for
  non-Linux platforms.
- Ensure the `ebpf` package can be imported and compiled anywhere, even if the
  real tracer only works on Linux. This allows running unit tests on development
  machines.

### Implementation:
Create a file `internal/ebpf/bpf_stub.go`:
```go
//go:build !linux || (!amd64 && !386)

package ebpf

import "github.com/cilium/ebpf"

func loadBpf() (*ebpf.CollectionSpec, error) {
    return nil, fmt.Errorf("BPF not supported on this platform")
}
```

---

## 3. Full Integration Testing

### Problem
Current tests are unit-heavy but lack an end-to-end flow check. We need to verify
that a `Runner` correctly connects the `Pipeline`, `EventProcessor`, and `Exporter`.

**Solution**:
Create a new test file `internal/runner/integration_test.go`:
- Use `NewPipelineWithMock` to avoid root/BPF requirements.
- Use a `bytes.Buffer` for terminal output.
- Inject raw events into the `MockTracer`.
- Verify that metrics are recorded and terminal output contains expected strings.

---

## 4. Mocking Infrastructure Improvements

### Problem
The `MockTracer` is relatively simple. It could be improved to simulate more
complex scenarios like lost events, high-frequency bursts, or specific S3
client types.

**Solution**:
- Enhance `internal/ebpf/mock.go` with a way to simulate event drops.
- Add helper methods to inject pre-baked S3 events (GET, PUT, Multipart).

---

## 5. Performance & Race Detection

### Problem
S3Slower handles high-volume traffic. We must ensure no race conditions exist in
the pipeline or metrics collection.

**Solution**:
- Add more benchmarks to `internal/runner/runner_test.go` for concurrent event
  handling.
- Always run tests with the race detector in CI: `go test -race ./...`.

---

## 6. Coverage Targets

We aim for the following statement coverage across packages:

| Package | Current | Target |
|---------|---------|--------|
| `internal/config` | 88.2% | 90% |
| `internal/ebpf` | Build Fail | 80% (via Mocks) |
| `internal/event` | 93.8% | 95% |
| `internal/http` | 89.3% | 95% |
| `internal/logger` | 88.2% | 90% |
| `internal/metrics` | 85.7% | 90% |
| `internal/runner` | Build Fail | 85% |
| `internal/terminal` | 78.2% | 85% |
| `internal/watcher` | 69.7% | 80% |

---

## Implementation Order

1. **Fix Portability**: Add BPF stubs and skip Linux-specific tests on Darwin.
2. **Fix Truncation**: Correct the terminal writer and its tests.
3. **Integration Test**: Implement the first end-to-end mock-based test.
4. **Coverage Boost**: Add missing unit tests for `internal/watcher` and `internal/terminal`.
5. **Race/Perf**: Add concurrency benchmarks.
