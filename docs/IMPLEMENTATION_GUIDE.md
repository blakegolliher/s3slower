# S3Slower: Implementation Guide for Production Readiness

This document is an exhaustive, step-by-step guide for completing the partially-built
features in s3slower. It is written so that a fresh engineering session on a Linux
host can read this guide and implement every change correctly.

**Principles**: DRY, clean code, clear not clever. No over-engineering. Every change
must have tests. Preserve existing architecture and naming conventions.

---

## Table of Contents

1. [Stale PID and Request Cleanup Loop](#1-stale-pid-and-request-cleanup-loop)
2. [Wire Up Config Fields or Remove Them](#2-wire-up-config-fields-or-remove-them)
3. [Proper JSON Output Mode](#3-proper-json-output-mode)
4. [Wire Up --watch Flag to Auto-Generate Targets](#4-wire-up---watch-flag-to-auto-generate-targets)
5. [Debug Output Mode](#5-debug-output-mode)
6. [Per-Process Probe Attachment](#6-per-process-probe-attachment)
7. [Dead Code Cleanup](#7-dead-code-cleanup)
8. [Test Coverage](#8-test-coverage)
9. [Build Verification](#9-build-verification)
10. [BPF Enhancements: HTTP Tracing, Response Capture, and Scaled Data Buffers](#10-bpf-enhancements-http-tracing-response-capture-and-scaled-data-buffers)

---

## 1. Stale PID and Request Cleanup Loop

### Problem

The `TargetWatcher.CleanupExited()` method exists at `internal/watcher/watcher.go:244`
but is never called. The `EventProcessor.Cleanup()` method exists at
`internal/event/event.go:246` but is also never called. When s3slower runs as a
24/7 daemon, `watcher.attached` map and `correlator.requests` map grow unbounded
as processes start and exit.

### Solution

Add a periodic cleanup goroutine to the Runner's main loop.

### Files to Modify

- `internal/runner/runner.go`

### Implementation

In the `Run()` method of Runner (around line 306, before the main event loop), add a
cleanup ticker goroutine. The cleanup should:

1. Run every 30 seconds (hardcode this; it's not user-configurable complexity we need).
2. Call `r.targetWatcher.CleanupExited()` if targetWatcher is non-nil.
3. Call `r.pipeline.CleanupStaleRequests(30 * time.Second)` — this requires adding
   a pass-through method on Pipeline.

#### Step 1: Add CleanupStaleRequests to Pipeline

In `internal/ebpf/pipeline.go`, add this method:

```go
// CleanupStaleRequests removes in-flight requests older than maxAge.
func (p *Pipeline) CleanupStaleRequests(maxAge time.Duration) int {
    return p.processor.Cleanup(maxAge)
}
```

#### Step 2: Add cleanup goroutine in Runner.Run()

In `internal/runner/runner.go`, inside the `Run()` method, after starting the pipeline
and before the main event loop (`for { select { ... } }`), add:

```go
// Start periodic cleanup of stale PIDs and in-flight requests
cleanupTicker := time.NewTicker(30 * time.Second)
defer cleanupTicker.Stop()
```

Then add a case to the existing select statement in the main loop:

```go
case <-cleanupTicker.C:
    if r.targetWatcher != nil {
        r.targetWatcher.CleanupExited()
    }
    if r.pipeline != nil {
        r.pipeline.CleanupStaleRequests(30 * time.Second)
    }
```

You will need to add `"time"` to the imports in runner.go.

#### Step 3: Add the detach callback

In `internal/watcher/watcher.go`, implement `SetDetachCallback` properly:

```go
func (w *TargetWatcher) SetDetachCallback(callback DetachCallback) {
    w.mu.Lock()
    defer w.mu.Unlock()
    w.detachCallback = callback
}
```

Add a `detachCallback` field to the `TargetWatcher` struct:

```go
type TargetWatcher struct {
    targets        []config.TargetConfig
    attachCallback AttachCallback
    detachCallback DetachCallback  // <-- add this
    attached       map[int]bool
    mu             sync.RWMutex
    running        bool
    stopCh         chan struct{}
}
```

Update `CleanupExited()` to call the detach callback when removing a PID:

```go
func (w *TargetWatcher) CleanupExited() {
    w.mu.Lock()
    defer w.mu.Unlock()

    for pid := range w.attached {
        if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
            delete(w.attached, pid)
            if w.detachCallback != nil {
                w.detachCallback(pid)
            }
        }
    }
}
```

### Tests

Add to `internal/watcher/watcher_test.go`:

```go
func TestCleanupExited(t *testing.T) {
    // Create a watcher with a fake PID that doesn't exist
    targets := []config.TargetConfig{{
        ID: "test", MatchType: config.MatchTypeComm, MatchValue: "nonexistent", Mode: "auto",
    }}

    attached := false
    detached := false
    var detachedPID int

    w := NewTargetWatcher(targets, func(pid int, comm string, target *config.TargetConfig) {
        attached = true
    })
    w.SetDetachCallback(func(pid int) {
        detached = true
        detachedPID = pid
    })

    // Manually add a PID that doesn't exist
    w.mu.Lock()
    w.attached[999999] = true
    w.mu.Unlock()

    // Run cleanup
    w.CleanupExited()

    assert.False(t, w.IsAttached(999999))
    assert.True(t, detached)
    assert.Equal(t, 999999, detachedPID)
}
```

Add to `internal/ebpf/pipeline_test.go` (or create if needed):

```go
func TestCleanupStaleRequests(t *testing.T) {
    cfg := PipelineConfig{Mode: ProbeModeAuto, BufferSize: 100}
    p, err := NewPipelineWithMock(cfg)
    require.NoError(t, err)

    // CleanupStaleRequests should not panic on empty pipeline
    removed := p.CleanupStaleRequests(30 * time.Second)
    assert.Equal(t, 0, removed)
}
```

---

## 2. Wire Up Config Fields or Remove Them

### Problem

These config fields are loaded from YAML but never applied:

| Field | Location | Issue |
|-------|----------|-------|
| `interval` | AppConfig.Interval | Loaded, never used |
| `screen.table_format` | ScreenConfig.TableFormat | Loaded, not passed to terminal.Writer |
| `screen.max_url_length` | ScreenConfig.MaxURLLength | Loaded, hardcoded as 50 in runner.go |
| `prometheus.buffer_size` | PrometheusConfig.BufferSize | Loaded, never used |

### Decision: What to Wire vs. What to Remove

- **`screen.table_format`**: Wire it. Controls terminal output mode (table vs simple).
- **`screen.max_url_length`**: Wire it. Already supported by terminal.Writer constructor.
- **`interval`**: Remove it. There is no interval-based collection cycle and adding one
  would be over-engineering. The tool is event-driven, not polling-based.
- **`prometheus.buffer_size`**: Remove it. The SampleBuffer is unused dead code (see
  section 7). Pipeline buffer size is set at construction time.

### Files to Modify

- `internal/config/config.go` — Remove `Interval` field and `BufferSize` field
- `internal/runner/runner.go` — Wire screen config to terminal.Writer
- `internal/cmd/root.go` — Pass screen config from AppConfig to runner.Config
- `s3slower.yaml` — Remove `interval` line, remove `buffer_size` line
- `README.md` — Remove `interval` and `buffer_size` from config docs

### Implementation

#### Step 1: Update AppConfig (internal/config/config.go)

Remove the `Interval` field from `AppConfig`:

```go
type AppConfig struct {
    MinLatencyMs int              `yaml:"min_latency_ms"`
    PID          int              `yaml:"pid,omitempty"`
    Debug        bool             `yaml:"debug"`
    Prometheus   PrometheusConfig `yaml:"prometheus"`
    Screen       ScreenConfig     `yaml:"screen"`
}
```

Remove `BufferSize` from `PrometheusConfig`:

```go
type PrometheusConfig struct {
    Host string `yaml:"prom_exporter_host"`
    Port int    `yaml:"prom_exporter_port"`
}
```

Update `DefaultConfig()` to match:

```go
func DefaultConfig() *AppConfig {
    return &AppConfig{
        MinLatencyMs: 0,
        Debug:        false,
        Prometheus: PrometheusConfig{
            Host: "::",
            Port: 9000,
        },
        Screen: ScreenConfig{
            TableFormat:  true,
            MaxURLLength: 50,
        },
    }
}
```

#### Step 2: Add screen config fields to runner.Config

In `internal/runner/runner.go`, add to the Config struct:

```go
type Config struct {
    // ... existing fields ...

    // Screen settings
    TableFormat  bool
    MaxURLLength int

    // ... rest of existing fields ...
}
```

Update `DefaultConfig()` :

```go
func DefaultConfig() Config {
    return Config{
        Mode:           "auto",
        EnableTerminal: true,
        EnableLogging:  true,
        LogDir:         "/var/log/s3slower",
        LogMaxSizeMB:   100,
        LogMaxBackups:  5,
        PrometheusPort: 9000,
        PrometheusHost: "::",
        TableFormat:    true,
        MaxURLLength:   50,
    }
}
```

#### Step 3: Use screen config when creating terminal.Writer

In the `New()` method of Runner (runner.go ~line 89), change:

```go
// Before:
r.terminal = terminal.NewWriter(os.Stdout, terminal.OutputModeTable, 50)

// After:
outputMode := terminal.OutputModeTable
if !cfg.TableFormat {
    outputMode = terminal.OutputModeSimple
}
r.terminal = terminal.NewWriter(os.Stdout, outputMode, cfg.MaxURLLength)
```

#### Step 4: Pass screen config from CLI (internal/cmd/root.go)

In the `newRunCommand()` RunE function, after loading the app config (~line 102),
add screen config propagation:

```go
// Apply screen settings from config file
cfg.TableFormat = appCfg.Screen.TableFormat
cfg.MaxURLLength = appCfg.Screen.MaxURLLength
```

#### Step 5: Update s3slower.yaml

Remove the `interval` and `buffer_size` lines:

```yaml
# S3Slower Configuration File

# Minimum latency threshold in milliseconds
# Only capture operations slower than this threshold (0 = capture all)
min_latency_ms: 0

# Enable debug logging
debug: false

# Prometheus exporter
prometheus:
  prom_exporter_host: "::"
  prom_exporter_port: 9000

# Console output settings
screen:
  table_format: true
  max_url_length: 50
```

#### Step 6: Update README.md

Update the configuration section to remove `interval` and `buffer_size` from the
example YAML block.

### Tests

Add to `internal/runner/runner_test.go`:

```go
func TestNewRunnerWithScreenConfig(t *testing.T) {
    cfg := DefaultConfig()
    cfg.EnableLogging = false
    cfg.TableFormat = false
    cfg.MaxURLLength = 100

    r, err := New(cfg)
    require.NoError(t, err)
    defer r.Close()

    // Verify terminal writer was created with correct settings
    assert.NotNil(t, r.terminal)
}
```

---

## 3. Proper JSON Output Mode

### Problem

The current `writeJSONEvent` in `internal/terminal/terminal.go:124` uses manual
`Fprintf` with string interpolation. It:
- Misses many fields (bucket, endpoint, operation, request_size, response_size, etc.)
- Doesn't use `encoding/json` (risks broken JSON from special characters in paths)
- Doesn't include a `--json` or `--output` CLI flag to activate it

### Solution

Replace the manual formatter with `encoding/json`, add all fields, and add a
`--output` CLI flag.

### Files to Modify

- `internal/terminal/terminal.go` — Replace writeJSONEvent
- `internal/cmd/root.go` — Add `--output` flag
- `internal/runner/runner.go` — Accept output format setting

### Implementation

#### Step 1: Replace writeJSONEvent in terminal.go

Add `"encoding/json"` to imports. Replace the `writeJSONEvent` method:

```go
// jsonEvent is the JSON representation of an S3 event.
type jsonEvent struct {
    Timestamp    string  `json:"timestamp"`
    PID          uint32  `json:"pid"`
    TID          uint32  `json:"tid"`
    Comm         string  `json:"comm"`
    Method       string  `json:"method"`
    Operation    string  `json:"operation,omitempty"`
    Bucket       string  `json:"bucket,omitempty"`
    Endpoint     string  `json:"endpoint,omitempty"`
    Path         string  `json:"path"`
    LatencyMs    float64 `json:"latency_ms"`
    RequestSize  uint32  `json:"request_size"`
    ResponseSize uint32  `json:"response_size"`
    StatusCode   int     `json:"status_code,omitempty"`
    IsError      bool    `json:"is_error,omitempty"`
    ClientType   string  `json:"client_type,omitempty"`
}

func (w *Writer) writeJSONEvent(e *event.S3Event) {
    je := jsonEvent{
        Timestamp:    e.Timestamp.Format(time.RFC3339Nano),
        PID:          e.PID,
        TID:          e.TID,
        Comm:         e.Comm,
        Method:       e.Method,
        Operation:    string(e.Operation),
        Bucket:       e.Bucket,
        Endpoint:     e.Endpoint,
        Path:         e.Path,
        LatencyMs:    e.LatencyMs,
        RequestSize:  e.RequestSize,
        ResponseSize: e.ResponseSize,
        StatusCode:   e.StatusCode,
        IsError:      e.IsError,
        ClientType:   e.ClientType,
    }

    data, err := json.Marshal(je)
    if err != nil {
        return
    }
    w.out.Write(data)
    w.out.Write([]byte("\n"))
}
```

Note: The `w.out.Write()` calls require that `io.Writer` is used. Since `io.Writer`
only has `Write`, this is fine. The newline-delimited JSON (NDJSON) format is standard
for log pipelines.

#### Step 2: Add --output flag to CLI

In `internal/cmd/root.go`, add to the `newRunCommand()` variable declarations:

```go
var (
    // ... existing vars ...
    outputFormat string
)
```

Add the flag registration (after existing flags):

```go
cmd.Flags().StringVar(&outputFormat, "output", "table", "Output format: table, simple, json")
```

In the RunE function, pass it to the runner config. First, add an `OutputFormat` field
to runner.Config:

```go
// In runner.go Config struct:
OutputFormat string // "table", "simple", "json"
```

Then in root.go's RunE:

```go
if cmd.Flags().Changed("output") {
    cfg.OutputFormat = outputFormat
}
```

#### Step 3: Use OutputFormat in Runner.New()

In `internal/runner/runner.go`, update the terminal creation logic in `New()` :

```go
if cfg.EnableTerminal {
    outputMode := terminal.OutputModeTable
    switch cfg.OutputFormat {
    case "json":
        outputMode = terminal.OutputModeJSON
    case "simple":
        outputMode = terminal.OutputModeSimple
    default:
        if !cfg.TableFormat {
            outputMode = terminal.OutputModeSimple
        }
    }
    r.terminal = terminal.NewWriter(os.Stdout, outputMode, cfg.MaxURLLength)
}
```

Also update the DefaultConfig:

```go
func DefaultConfig() Config {
    return Config{
        // ... existing defaults ...
        OutputFormat: "table",
    }
}
```

### Tests

Add to `internal/terminal/terminal_test.go`:

```go
func TestWriteJSONEvent(t *testing.T) {
    var buf bytes.Buffer
    w := NewWriter(&buf, OutputModeJSON, 50)

    evt := &event.S3Event{
        Timestamp:    time.Date(2024, 1, 15, 14, 30, 0, 0, time.UTC),
        PID:          1234,
        TID:          1234,
        Comm:         "aws",
        Method:       "GET",
        Operation:    "GET_OBJECT",
        Bucket:       "my-bucket",
        Endpoint:     "s3.amazonaws.com",
        Path:         "/my-bucket/path/to/file.json",
        LatencyMs:    45.2,
        RequestSize:  0,
        ResponseSize: 1048576,
        StatusCode:   200,
    }

    w.WriteEvent(evt)
    output := buf.String()

    // Verify it's valid JSON
    var parsed map[string]interface{}
    err := json.Unmarshal([]byte(output), &parsed)
    require.NoError(t, err)

    assert.Equal(t, "GET", parsed["method"])
    assert.Equal(t, "GET_OBJECT", parsed["operation"])
    assert.Equal(t, "my-bucket", parsed["bucket"])
    assert.Equal(t, float64(1234), parsed["pid"])
    assert.Equal(t, 45.2, parsed["latency_ms"])
}

func TestWriteJSONEventSpecialChars(t *testing.T) {
    var buf bytes.Buffer
    w := NewWriter(&buf, OutputModeJSON, 50)

    evt := &event.S3Event{
        Timestamp: time.Now(),
        Method:    "GET",
        Path:      `/bucket/path with "quotes" & <angles>`,
    }

    w.WriteEvent(evt)

    // Must be valid JSON even with special characters
    var parsed map[string]interface{}
    err := json.Unmarshal([]byte(buf.String()), &parsed)
    require.NoError(t, err)
}
```

---

## 4. Wire Up --watch Flag to Auto-Generate Targets

### Problem

The `--watch mc,warp` flag is accepted by the CLI and stored in
`runner.Config.WatchProcesses`, but `runner.New()` never converts these process
names into TargetConfig entries. The README documents this feature.

### Solution

In `runner.New()`, convert `WatchProcesses` entries into TargetConfig entries using
`comm` match type and `auto` probe mode. Merge them with any file-based targets.

### Files to Modify

- `internal/runner/runner.go`

### Implementation

In `runner.New()`, after loading file-based targets (~line 133) and before creating
the target watcher (~line 138), add:

```go
// Convert --watch process names into target configs
if len(cfg.WatchProcesses) > 0 {
    for _, proc := range cfg.WatchProcesses {
        proc = strings.TrimSpace(proc)
        if proc == "" {
            continue
        }
        r.targets = append(r.targets, config.TargetConfig{
            ID:         "watch-" + proc,
            MatchType:  config.MatchTypeComm,
            MatchValue: proc,
            Mode:       config.ProbeModeAuto,
        })
    }
}
```

Add `"strings"` to the imports.

### Tests

Add to `internal/runner/runner_test.go`:

```go
func TestNewRunnerWithWatchProcesses(t *testing.T) {
    cfg := DefaultConfig()
    cfg.EnableLogging = false
    cfg.WatchProcesses = []string{"mc", "warp", "aws"}

    r, err := New(cfg)
    require.NoError(t, err)
    defer r.Close()

    targets := r.Targets()
    require.Len(t, targets, 3)
    assert.Equal(t, "watch-mc", targets[0].ID)
    assert.Equal(t, config.MatchTypeComm, targets[0].MatchType)
    assert.Equal(t, "mc", targets[0].MatchValue)
    assert.Equal(t, config.ProbeModeAuto, targets[0].Mode)
}

func TestWatchProcessesEmptyStringsIgnored(t *testing.T) {
    cfg := DefaultConfig()
    cfg.EnableLogging = false
    cfg.WatchProcesses = []string{"mc", "", "  ", "warp"}

    r, err := New(cfg)
    require.NoError(t, err)
    defer r.Close()

    targets := r.Targets()
    assert.Len(t, targets, 2)
}
```

---

## 5. Debug Output Mode

### Problem

The `--debug` flag and `debug: true` config field exist but barely do anything.
Only one place checks it: the fallback to mock tracer in Runner.Run() prints a
message when debug is true. For a production tool, `--debug` should provide
meaningful diagnostic output.

### Solution

Add a simple debug logger that writes to stderr when debug mode is enabled. Use it
in key locations throughout the codebase. Keep it simple — just a function that
conditionally prints.

### Files to Modify

- `internal/runner/runner.go` — Add debug logging throughout
- `internal/ebpf/pipeline.go` — Log probe attachment details

### Implementation

#### Step 1: Add a debugf helper to Runner

In `internal/runner/runner.go`, add:

```go
// debugf prints a debug message if debug mode is enabled.
func (r *Runner) debugf(format string, args ...interface{}) {
    if r.config.Debug {
        fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
    }
}
```

#### Step 2: Add debug logging at key points in Runner.Run()

Add debug calls at these locations in `runner.go`:

After pipeline creation (~line 266):
```go
r.debugf("Pipeline created with mode=%s targetPID=%d minLatencyMs=%d",
    mode, r.config.TargetPID, r.config.MinLatencyMs)
```

After pipeline start (~line 272):
```go
r.debugf("Pipeline started, reading events from perf buffer")
```

In the cleanup ticker case:
```go
case <-cleanupTicker.C:
    if r.targetWatcher != nil {
        r.targetWatcher.CleanupExited()
        r.debugf("Cleanup: %d attached PIDs", len(r.targetWatcher.GetAttached()))
    }
    if r.pipeline != nil {
        removed := r.pipeline.CleanupStaleRequests(30 * time.Second)
        if removed > 0 {
            r.debugf("Cleaned up %d stale requests", removed)
        }
    }
```

In handleEvent:
```go
func (r *Runner) handleEvent(evt *event.S3Event) {
    r.debugf("Event: pid=%d method=%s op=%s bucket=%s latency=%.2fms",
        evt.PID, evt.Method, evt.Operation, evt.Bucket, evt.LatencyMs)
    // ... rest of method
}
```

In onProcessAttach:
```go
func (r *Runner) onProcessAttach(pid int, comm string, target *config.TargetConfig) {
    r.debugf("Process attached: pid=%d comm=%s target=%s mode=%s",
        pid, comm, target.ID, target.Mode)
    // ... rest of method
}
```

#### Step 3: Add debug logging to Pipeline

Add a `Debug` field to `PipelineConfig`:

```go
type PipelineConfig struct {
    Mode         ProbeMode
    TargetPID    uint32
    MinLatencyMs uint64
    LibraryPath  string
    BufferSize   int
    Debug        bool
}
```

Add a `debug` field and `debugf` method to `Pipeline`:

```go
type Pipeline struct {
    // ... existing fields ...
    debug bool
}

func (p *Pipeline) debugf(format string, args ...interface{}) {
    if p.debug {
        fmt.Fprintf(os.Stderr, "[DEBUG] [pipeline] "+format+"\n", args...)
    }
}
```

Set it in `NewPipeline` and `NewPipelineWithMock`:

```go
return &Pipeline{
    // ... existing fields ...
    debug: config.Debug,
}, nil
```

Add debug logging in `attachProbes()` :

```go
func (p *Pipeline) attachProbes() error {
    p.debugf("Attaching probes in mode: %s", p.mode)
    // ... existing code, adding p.debugf calls at each attachment point
}
```

In `Runner.Run()`, set the debug flag on PipelineConfig:

```go
pipelineCfg := ebpf.PipelineConfig{
    // ... existing fields ...
    Debug: r.config.Debug,
}
```

#### Step 4: Print startup diagnostics

In `Runner.Run()`, after the existing startup message block, add when debug is on:

```go
if r.config.Debug {
    stats := r.pipeline.Stats()
    r.debugf("Active probes: %d", stats.TracerStats.ActiveProbes)
    r.debugf("Target watcher: %v (%d targets)", r.targetWatcher != nil, len(r.targets))
    r.debugf("Terminal: %v, Logger: %v, Prometheus: %v",
        r.terminal != nil, r.logger != nil, r.exporter != nil)
}
```

### Tests

Add to `internal/runner/runner_test.go`:

```go
func TestDebugfNoOutput(t *testing.T) {
    cfg := DefaultConfig()
    cfg.EnableLogging = false
    cfg.Debug = false

    r, err := New(cfg)
    require.NoError(t, err)
    defer r.Close()

    // Capture stderr
    old := os.Stderr
    _, w, _ := os.Pipe()
    os.Stderr = w

    r.debugf("should not appear")

    w.Close()
    os.Stderr = old
}
```

---

## 6. Per-Process Probe Attachment

### Problem

The `onProcessAttach` callback in `runner.go:146` has an explicit TODO:
```go
// TODO: Attach eBPF probes to this process
```

The current architecture attaches probes globally in Pipeline.Start(). The watcher
finds matching processes but doesn't actually do anything with them beyond printing
a message.

### Decision

**Do NOT implement full per-process probe attachment in this pass.** Per-process
uprobe attachment requires significant BPF program changes (attaching uprobes to
specific process binaries rather than shared libraries). This is a v2 feature.

Instead:
1. Remove the misleading TODO comment.
2. Use the watcher to set PID filters on the BPF config map when a process is found.
3. Add the matched process's prom_labels to metrics output.
4. Document clearly in code comments that probes are attached globally and the watcher
   provides process filtering and label enrichment.

### Files to Modify

- `internal/runner/runner.go`

### Implementation

Replace the `onProcessAttach` method:

```go
// onProcessAttach is called when a matching process is found by the target watcher.
// Probes are attached globally (not per-process). The watcher provides process
// identification for Prometheus label enrichment and PID-based filtering.
func (r *Runner) onProcessAttach(pid int, comm string, target *config.TargetConfig) {
    r.debugf("Matched process: pid=%d comm=%s target=%s mode=%s",
        pid, comm, target.ID, target.Mode)

    fmt.Printf("Detected S3 client: %s (PID %d, target: %s)\n",
        comm, pid, target.ID)

    // If targeting a single PID, update the BPF filter
    if r.config.TargetPID == 0 && r.pipeline != nil {
        // Store the target association for label enrichment
        r.mu.Lock()
        if r.targetLabels == nil {
            r.targetLabels = make(map[uint32]map[string]string)
        }
        r.targetLabels[uint32(pid)] = target.PromLabels
        r.mu.Unlock()
    }
}
```

Add a `targetLabels` field to the Runner struct:

```go
type Runner struct {
    // ... existing fields ...

    // targetLabels maps PIDs to their target's Prometheus labels
    targetLabels map[uint32]map[string]string
}
```

Update `handleEvent` to merge target labels into metrics:

```go
func (r *Runner) handleEvent(evt *event.S3Event) {
    // ... existing min latency check ...

    // ... terminal and logger output (unchanged) ...

    // Record metrics with label enrichment from target watcher
    if r.metrics != nil {
        hostname, _ := os.Hostname()
        labels := map[string]string{
            "hostname":     hostname,
            "comm":         evt.Comm,
            "s3_operation": string(evt.Operation),
            "method":       evt.Method,
            "pid":          fmt.Sprintf("%d", evt.PID),
        }

        // Merge target-specific labels if this PID has been matched
        r.mu.RLock()
        if extraLabels, ok := r.targetLabels[evt.PID]; ok {
            for k, v := range extraLabels {
                labels[k] = v
            }
        }
        r.mu.RUnlock()

        r.metrics.RecordRequest(
            labels,
            evt.LatencyMs,
            int64(evt.RequestSize),
            int64(evt.ResponseSize),
            evt.IsError,
            evt.IsPartial,
        )
    }
}
```

**Important note about Prometheus label cardinality:** When extra labels from targets
are merged into metrics, the Prometheus CounterVec/HistogramVec must have been created
with those label names. This is already handled — `metrics.New(extraLabels)` accepts
extra label names. But the Runner needs to collect the extra label keys from targets
and pass them when creating the exporter.

Update the exporter creation in `runner.New()` :

```go
if cfg.EnablePrometheus {
    addr := fmt.Sprintf("%s:%d", cfg.PrometheusHost, cfg.PrometheusPort)
    extraLabels := config.CollectExtraLabelKeys(r.targets)
    r.exporter = metrics.NewExporter(addr, extraLabels)
    r.metrics = r.exporter.Metrics()
}
```

Note: Move the Prometheus setup AFTER the targets are loaded (after both file-based
and watch-based targets are processed).

### Tests

Test that target labels are properly merged:

```go
func TestHandleEventWithTargetLabels(t *testing.T) {
    cfg := DefaultConfig()
    cfg.EnableLogging = false
    cfg.EnableTerminal = false
    cfg.EnablePrometheus = false

    r, err := New(cfg)
    require.NoError(t, err)
    defer r.Close()

    // Add target labels for a PID
    r.mu.Lock()
    r.targetLabels = map[uint32]map[string]string{
        1234: {"client": "aws-cli", "env": "production"},
    }
    r.mu.Unlock()

    // Verify labels are accessible
    r.mu.RLock()
    labels, ok := r.targetLabels[1234]
    r.mu.RUnlock()

    assert.True(t, ok)
    assert.Equal(t, "aws-cli", labels["client"])
}
```

---

## 7. Dead Code Cleanup

### Problem

Several types, fields, and methods exist but are never used:

1. `SampleBuffer` type in `internal/metrics/metrics.go` — Never instantiated
2. `EventProcessor.ProcessWrite()` and `EventProcessor.ProcessRead()` — Never called
   (Pipeline.handleEvent bypasses them)
3. `event.S3Event.ActualBytes` field — Never populated
4. `event.S3Event.IsPartial` — Never set to true
5. `Probe` interface in `internal/ebpf/types.go` — Never implemented
6. Duplicate `ClientType` definitions — defined as constants in both
   `internal/ebpf/types.go` (uint8) and `internal/watcher/watcher.go` (int type)

### Solution

Remove dead code. For fields that represent future functionality, add clear TODO
comments or remove them.

### Files to Modify

- `internal/metrics/metrics.go`
- `internal/event/event.go`
- `internal/ebpf/types.go`
- `internal/watcher/watcher.go`

### Implementation

#### Step 1: Remove SampleBuffer from metrics.go

Delete the entire `SampleBuffer`, `Sample`, `NewSampleBuffer`, `Add`, `Flush`,
and `Len` sections (lines 239-293 of metrics.go). These types are unused.

#### Step 2: Clean up EventProcessor

The `ProcessWrite` and `ProcessRead` methods in event.go represent a different
architecture (separate write/read events). The current BPF program sends combined
events. These methods are dead code.

However, the `RequestCorrelator` might be useful if the BPF architecture changes.
Keep the correlator but remove `ProcessWrite` and `ProcessRead` from EventProcessor.
The EventProcessor then becomes a thin wrapper around the event channel.

Delete `ProcessWrite` (lines 198-214) and `ProcessRead` (lines 217-238) from
event.go.

The `correlator` field on EventProcessor is now unused. Keep `Cleanup()` since we
use it from the runner, but note that it now operates on an empty correlator.

Actually, on second thought: since `Cleanup()` is called from the runner and we want
to keep the correlator for the stale cleanup, but nothing adds to it... this is a
contradiction. The clean approach:

**Option A (recommended):** Remove ProcessWrite, ProcessRead, the correlator, and
the Cleanup method from EventProcessor. Remove the cleanup call from Runner. The
current architecture doesn't need request correlation because the BPF program
handles it.

**Option B:** Keep everything for future use.

**Go with Option A.** Clean code now, add it back if the BPF architecture changes.

If you go with Option A, also update the runner's cleanup ticker to only clean up
the target watcher:

```go
case <-cleanupTicker.C:
    if r.targetWatcher != nil {
        r.targetWatcher.CleanupExited()
    }
```

And remove `CleanupStaleRequests` from Pipeline.

Keep the `RequestCorrelator` type and its methods in event.go — they're a clean,
self-contained data structure that may be useful. Just remove the integration with
EventProcessor.

EventProcessor becomes:

```go
type EventProcessor struct {
    minLatency time.Duration
    eventChan  chan *event.S3Event
}

func NewEventProcessor(minLatency time.Duration, bufferSize int) *EventProcessor {
    return &EventProcessor{
        minLatency: minLatency,
        eventChan:  make(chan *S3Event, bufferSize),
    }
}
```

#### Step 3: Remove ActualBytes from S3Event

In `internal/event/event.go`, remove the `ActualBytes` field from S3Event struct.
It is never set.

#### Step 4: Clean up duplicate ClientType

The `watcher` package has `ClientType int` with constants and detection functions.
The `ebpf/types.go` has `ClientType uint8` constants. These serve different purposes:
- `ebpf/types.go` constants match the BPF program's C enum values
- `watcher` constants are for userspace detection

Keep both but rename the watcher ones to avoid confusion:

In `internal/watcher/watcher.go`, rename `ClientType` to `KnownClient` and its
constants to `KnownClientWarp`, etc. Or simply leave them as-is since they're in
different packages and don't conflict at the Go level. **Leave as-is** — they're
in separate packages and serve separate purposes.

#### Step 5: Remove unused Probe interface

In `internal/ebpf/types.go`, remove the `Probe` interface (lines 88-104). It is
never implemented by any type in the codebase.

### Tests

After each removal, run `go build ./...` and `go test ./...` to verify nothing
breaks. Remove any tests that test deleted functionality.

---

## 8. Test Coverage

After all changes, ensure comprehensive tests exist for the new code:

### New Tests Needed

1. **Cleanup lifecycle test** — Verify CleanupExited removes dead PIDs
2. **JSON output test** — Verify valid JSON with all fields
3. **JSON special characters test** — Verify encoding safety
4. **Watch flag test** — Verify auto-generated targets
5. **Config wiring test** — Verify screen config reaches terminal Writer
6. **Debug mode test** — Verify debug output appears/doesn't appear

### Run All Tests

```bash
make test-race
make test-cover
```

Target: maintain or improve the current 64% test coverage.

---

## 9. Build Verification

After all changes, verify the full build pipeline:

```bash
# Clean build
make clean

# Full CI pipeline
make ci

# Verify binary runs
./build/s3slower version
./build/s3slower run --help

# Verify JSON output flag appears in help
./build/s3slower run --help | grep output

# Verify config file loads without errors
./build/s3slower run --config s3slower.yaml --debug --no-log 2>&1 | head -20
```

---

## Implementation Order

Execute these changes in this order to minimize conflicts:

1. **Dead code cleanup** (Section 7) — Remove dead code first so subsequent changes
   are against a clean codebase.
2. **Config wiring** (Section 2) — Wire screen config, remove dead config fields.
3. **Stale cleanup loop** (Section 1) — Add the cleanup lifecycle.
4. **Watch flag** (Section 4) — Small, self-contained change.
5. **JSON output** (Section 3) — New feature, independent of other changes.
6. **Debug output** (Section 5) — Adds logging throughout, easier to do last.
7. **Per-process attachment** (Section 6) — Most complex change, depends on targets
   being fully wired.

After each section, run `go build ./...` and `go test ./...` to verify.

---

## Summary of Files Modified

| File | Changes |
|------|---------|
| `internal/runner/runner.go` | Cleanup loop, watch targets, debug logging, screen config, target labels |
| `internal/ebpf/pipeline.go` | Debug logging, debug config field |
| `internal/watcher/watcher.go` | Implement SetDetachCallback, add detachCallback field |
| `internal/terminal/terminal.go` | Proper JSON output with encoding/json |
| `internal/event/event.go` | Remove ProcessWrite/ProcessRead, remove ActualBytes |
| `internal/metrics/metrics.go` | Remove SampleBuffer |
| `internal/ebpf/types.go` | Remove Probe interface |
| `internal/config/config.go` | Remove Interval, remove BufferSize |
| `internal/cmd/root.go` | Add --output flag, pass screen config |
| `s3slower.yaml` | Remove interval, buffer_size |
| `README.md` | Update config docs, add --output flag |

## New Files

None. All changes are to existing files.

---

## 10. BPF Enhancements: HTTP Tracing, Response Capture, and Scaled Data Buffers

This section combines three interdependent BPF changes into one coordinated pass.
They all modify `s3slower.c`, change struct layouts, and require `make generate`.
Doing them together avoids 3 separate struct migrations and BPF recompilations.

**What this delivers:**
- Complete kprobe-based plain HTTP tracing (currently stubs that do nothing)
- Response status code capture (currently impossible — no response data reaches Go)
- Larger data capture buffer (96→256 bytes) for better S3 operation detection
- Per-CPU heap maps to avoid BPF stack overflow with larger structs

**Minimum kernel version:** 5.5+ (required for `bpf_probe_read_user`)

### Problem

Three related gaps in the BPF program:

1. **Plain HTTP is broken.** `kprobe_sys_read` (line 193) and `kretprobe_sys_read`
   (line 209) in `s3slower.c` are stubs that return 0. No latency can be measured
   for plain HTTP traffic.

2. **Response status codes are never captured.** The `event_t` struct has only one
   `data` field, populated with request headers in write/send entry probes. The
   return probes (`uretprobe_ssl_read`, etc.) can only access `PT_REGS_RC(ctx)`
   (the return value = bytes read), NOT the buffer pointer where SSL_read wrote
   the response data. The Go parser's `ParseStatusCode` method has no response
   data to work with, so all events show status code 0.

3. **96-byte data buffer is too small.** A typical S3 request like
   `PUT /bucket/path/to/deeply/nested/object?partNumber=1&uploadId=abc HTTP/1.1\r\nHost: s3.us-west-2.amazonaws.com\r\n`
   is ~150 bytes. The 96-byte limit truncates paths and query params, causing
   `DetectS3Operation` to return UNKNOWN for multipart and list operations.
   But naively increasing `MAX_DATA_SIZE` causes BPF stack overflow (512-byte limit).

### Solution

**Key architectural insight:** Return probes (uretprobe, kretprobe) can only access
the return value via `PT_REGS_RC(ctx)`, NOT the original function arguments. To read
the response buffer that `SSL_read`/`sys_read` wrote into, we must:

1. Add **entry probes** for all read functions that save the buffer pointer to a map
2. In the **return probes**, look up the saved buffer pointer and `bpf_probe_read_user` from it

This is the standard BPF pattern for correlating entry/return probe data.

For the stack overflow, use **per-CPU array maps** as heap-like scratch space. This is
the standard BPF pattern for large struct construction.

### Files to Modify

| File | Changes |
|------|---------|
| `internal/ebpf/bpf/s3slower.c` | Full rewrite of most BPF functions |
| `internal/ebpf/types.go` | Update `RawEvent` struct |
| `internal/ebpf/tracer.go` | Attach new read entry probes |
| `internal/ebpf/pipeline.go` | Pass resp_data to status parser |
| `internal/ebpf/bpf_x86_bpfel.go` | Auto-generated — DO NOT hand-edit |
| `internal/ebpf/bpf_x86_bpfel.o` | Auto-generated — DO NOT hand-edit |

### Implementation

#### Step 1: Update Constants in `s3slower.c`

Replace the existing `MAX_DATA_SIZE` definition:

```c
// Old:
#define MAX_DATA_SIZE 96

// New:
#define MAX_DATA_SIZE 256
#define MAX_RESP_SIZE 128
#define HTTP_CHECK_SIZE 8
```

#### Step 2: Add `resp_data` Field to `event_t` in `s3slower.c`

Add the `resp_data` field as the LAST data field (before any trailing padding):

```c
struct event_t {
    __u64 timestamp_us;
    __u64 latency_us;
    __u32 pid;
    __u32 tid;
    __u32 fd;
    char comm[TASK_COMM_LEN];
    __u32 req_size;
    __u32 resp_size;
    __u32 actual_resp_bytes;
    __u8 is_partial;
    __u8 client_type;
    __u8 _pad[2];
    char data[MAX_DATA_SIZE];       // request headers (256 bytes)
    char resp_data[MAX_RESP_SIZE];  // response headers (128 bytes) — NEW
};
```

**Struct alignment analysis (CRITICAL — C and Go must match byte-for-byte):**
- Fields through `_pad[2]`: 60 bytes (offset 0-59)
- `data[256]`: offset 60, ends at offset 316
- `resp_data[128]`: offset 316, ends at offset 444
- C compiler pads to 448 (next multiple of 8, due to `__u64` alignment)
- Go `unsafe.Sizeof(RawEvent{})` also produces 448 — they match

Do NOT change `req_info_t`. Its `data[MAX_DATA_SIZE]` field will automatically
grow to 256 bytes because it references the `MAX_DATA_SIZE` constant.

#### Step 3: Add `read_args_t` Struct to `s3slower.c`

Add this new struct after `req_info_t`:

```c
// Saves read() arguments from entry probe for use in return probe.
// Return probes can only access the return value (PT_REGS_RC), NOT the
// original function arguments. This map bridges that gap.
struct read_args_t {
    __u64 buf_ptr;  // userspace buffer pointer (cast from char*)
    __u32 fd;       // file descriptor (only used by kprobes)
    __u32 _pad;     // alignment padding
};
```

#### Step 4: Add 3 New BPF Maps to `s3slower.c`

Add these after the existing `events` map definition:

```c
// Per-CPU scratch space for event_t construction.
// With MAX_DATA_SIZE=256 and MAX_RESP_SIZE=128, event_t is ~444 bytes,
// which exceeds the 512-byte BPF stack limit when combined with local vars.
// Using a per-CPU array as a "heap" avoids this.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event_t);
} event_heap SEC(".maps");

// Per-CPU scratch space for req_info_t construction.
// With MAX_DATA_SIZE=256, req_info_t is ~289 bytes — also too large for stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct req_info_t);
} req_heap SEC(".maps");

// Saves buffer pointers from read entry probes for return probes.
// Key: raw pid_tgid value from bpf_get_current_pid_tgid()
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct read_args_t);
} read_args_map SEC(".maps");
```

#### Step 5: Rewrite ALL Write/Send Entry Probes in `s3slower.c`

All 4 write/send probes must be rewritten to use `req_heap` instead of stack
allocation. They all follow the same pattern:

1. Read `HTTP_CHECK_SIZE` (8) bytes onto the stack for the quick HTTP check
2. If HTTP, get `req_info_t` pointer from `req_heap` per-CPU array
3. `bpf_probe_read_user` the full `MAX_DATA_SIZE` directly into `req->data`
4. Copy from heap scratch to `req_map` via `bpf_map_update_elem` (value copy)

**IMPORTANT BPF verifier rules:**
- Every `bpf_map_lookup_elem` return MUST be NULL-checked before dereferencing
- `bpf_probe_read_user` size must be a compile-time constant (use `MAX_DATA_SIZE`)
- Per-CPU array values persist between calls — set every field explicitly

**Replace `kprobe_sys_write` with:**

```c
SEC("kprobe/sys_write")
int kprobe_sys_write(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (should_filter_pid(pid))
        return 0;

    int fd = (int)PT_REGS_PARM1(ctx);
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    __u32 count = (size_t)PT_REGS_PARM3(ctx);

    if (fd < 3 || count == 0)
        return 0;

    // Quick HTTP check on the stack (8 bytes, well within 512-byte limit)
    char check[HTTP_CHECK_SIZE] = {};
    if (bpf_probe_read_user(check, sizeof(check), buf) < 0)
        return 0;
    if (!is_http_data(check, HTTP_CHECK_SIZE))
        return 0;

    // Build req_info in per-CPU scratch space (too large for stack)
    __u32 zero = 0;
    struct req_info_t *req = bpf_map_lookup_elem(&req_heap, &zero);
    if (!req)
        return 0;

    req->start_time = bpf_ktime_get_ns() / 1000;
    req->req_size = count;
    req->fd = fd;
    bpf_get_current_comm(&req->comm, sizeof(req->comm));
    req->client_type = detect_client_type(req->comm);
    // Read full request data directly into scratch space
    bpf_probe_read_user(req->data, MAX_DATA_SIZE, buf);

    // bpf_map_update_elem copies the value, so scratch space is safe to reuse
    __u64 key = ((__u64)pid << 32) | (__u32)fd;
    bpf_map_update_elem(&req_map, &key, req, BPF_ANY);

    return 0;
}
```

**Replace `uprobe_ssl_write` with:**

```c
SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    // SSL_write(SSL *ssl, const void *buf, int num)
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    if (num <= 0)
        return 0;

    char check[HTTP_CHECK_SIZE] = {};
    if (bpf_probe_read_user(check, sizeof(check), buf) < 0)
        return 0;
    if (!is_http_data(check, HTTP_CHECK_SIZE))
        return 0;

    __u32 zero = 0;
    struct req_info_t *req = bpf_map_lookup_elem(&req_heap, &zero);
    if (!req)
        return 0;

    req->start_time = bpf_ktime_get_ns() / 1000;
    req->req_size = num;
    req->fd = tid;  // uprobes use TID as pseudo-FD
    bpf_get_current_comm(&req->comm, sizeof(req->comm));
    req->client_type = detect_client_type(req->comm);
    bpf_probe_read_user(req->data, MAX_DATA_SIZE, buf);

    __u64 key = ((__u64)pid << 32) | tid;
    bpf_map_update_elem(&req_map, &key, req, BPF_ANY);

    return 0;
}
```

**Replace `uprobe_gnutls_send` with:** Same pattern as `uprobe_ssl_write`.
`gnutls_record_send(session, data, data_size)` — buffer is `PT_REGS_PARM2`,
size is `PT_REGS_PARM3`. Use `size_t` cast for the size. Check `data_size == 0`.

**Replace `uprobe_pr_write` with:** Same pattern as `uprobe_ssl_write`.
`PR_Write(fd, buf, amount)` — buffer is `PT_REGS_PARM2`, size is `PT_REGS_PARM3`.
Use `int` cast for amount. Check `amount <= 0`.

#### Step 6: Add 3 New Read Entry Probes to `s3slower.c`

These probes fire when the application calls a read/recv function. They save the
userspace buffer pointer into `read_args_map` so the return probe can read response
data from that buffer after the function completes.

**CRITICAL: Why this is needed.** A return probe (uretprobe/kretprobe) can ONLY
access `PT_REGS_RC(ctx)` — the function's return value. The original arguments
(including the buffer pointer) are NOT available. Without saving the buffer pointer
in the entry probe, the return probe cannot read the response data.

Each entry probe checks `req_map` first. This is essential for performance:
`sys_read` fires for EVERY read syscall on the system (files, pipes, sockets).
We only store args when there's a pending HTTP request for that PID+FD.

**Add `uprobe_ssl_read` (NEW function):**

```c
SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    // Only save args if there's a pending request for this thread
    __u64 req_key = ((__u64)pid << 32) | tid;
    if (!bpf_map_lookup_elem(&req_map, &req_key))
        return 0;

    // SSL_read(SSL *ssl, void *buf, int num) — buf is PARM2
    const char *buf = (const char *)PT_REGS_PARM2(ctx);

    struct read_args_t args = {};
    args.buf_ptr = (__u64)buf;
    bpf_map_update_elem(&read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}
```

**Add `uprobe_gnutls_recv` (NEW function):**

```c
SEC("uprobe/gnutls_record_recv")
int uprobe_gnutls_recv(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    __u64 req_key = ((__u64)pid << 32) | tid;
    if (!bpf_map_lookup_elem(&req_map, &req_key))
        return 0;

    // gnutls_record_recv(session, void *data, size_t sizeofdata) — data is PARM2
    const char *buf = (const char *)PT_REGS_PARM2(ctx);

    struct read_args_t args = {};
    args.buf_ptr = (__u64)buf;
    bpf_map_update_elem(&read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}
```

**Add `uprobe_pr_read` (NEW function):**

```c
SEC("uprobe/PR_Read")
int uprobe_pr_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    __u64 req_key = ((__u64)pid << 32) | tid;
    if (!bpf_map_lookup_elem(&req_map, &req_key))
        return 0;

    // PR_Read(PRFileDesc *fd, void *buf, PRInt32 amount) — buf is PARM2
    const char *buf = (const char *)PT_REGS_PARM2(ctx);

    struct read_args_t args = {};
    args.buf_ptr = (__u64)buf;
    bpf_map_update_elem(&read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}
```

**Rewrite `kprobe_sys_read` (complete replacement):**

```c
SEC("kprobe/sys_read")
int kprobe_sys_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_filter_pid(pid))
        return 0;

    // ssize_t read(int fd, void *buf, size_t count)
    int fd = (int)PT_REGS_PARM1(ctx);
    if (fd < 3)
        return 0;

    // Only save args if there's a pending HTTP request for this PID+FD
    __u64 req_key = ((__u64)pid << 32) | (__u32)fd;
    if (!bpf_map_lookup_elem(&req_map, &req_key))
        return 0;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);

    struct read_args_t args = {};
    args.buf_ptr = (__u64)buf;
    args.fd = (__u32)fd;  // kprobes need to save FD (uprobes use TID instead)
    bpf_map_update_elem(&read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}
```

#### Step 7: Rewrite ALL Return Probes in `s3slower.c`

All 4 return probes follow this new pattern:

1. Look up saved buffer pointer from `read_args_map` (saved by entry probe)
2. Delete `read_args_map` entry immediately (prevent stale entries)
3. Look up pending request from `req_map`
4. Calculate latency, check threshold
5. Get `event_t` pointer from `event_heap` per-CPU scratch space
6. Fill all event fields from `req` and return value
7. `__builtin_memset` resp_data to zero, then `bpf_probe_read_user` response data
8. Emit via `bpf_perf_event_output`
9. Delete `req_map` entry (one event per request-response pair)

**IMPORTANT BPF verifier rules for return probes:**
- `bpf_map_delete_elem` on `read_args_map` BEFORE checking `req_map` — prevents leaks
  even if the request lookup fails
- `__builtin_memset(event->resp_data, 0, MAX_RESP_SIZE)` BEFORE `bpf_probe_read_user`
  — if the read fails, resp_data stays zeroed instead of containing stale heap data
- Use `MAX_RESP_SIZE` as the constant size for `bpf_probe_read_user` — the verifier
  needs a compile-time constant or verifier-bounded value
- If `req_map` lookup fails after `read_args_map` was found, still return cleanly
  (the read_args entry was already deleted)

**Replace `uretprobe_ssl_read` with:**

```c
SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    // Look up saved buffer pointer from entry probe
    struct read_args_t *args = bpf_map_lookup_elem(&read_args_map, &pid_tgid);
    if (!args)
        return 0;
    __u64 buf_ptr = args->buf_ptr;
    bpf_map_delete_elem(&read_args_map, &pid_tgid);

    __u64 now = bpf_ktime_get_ns() / 1000;

    // Look up the pending request
    __u64 req_key = ((__u64)pid << 32) | tid;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &req_key);
    if (!req)
        return 0;

    __u64 latency_us = now - req->start_time;
    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    // Build event in per-CPU scratch space (too large for stack)
    __u32 zero = 0;
    struct event_t *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    event->timestamp_us = now;
    event->latency_us = latency_us;
    event->pid = pid;
    event->tid = tid;
    event->fd = req->fd;
    __builtin_memcpy(event->comm, req->comm, TASK_COMM_LEN);
    event->req_size = req->req_size;
    event->resp_size = (__u32)ret;
    event->actual_resp_bytes = (__u32)ret;
    event->is_partial = 0;
    event->client_type = req->client_type;
    __builtin_memcpy(event->data, req->data, MAX_DATA_SIZE);

    // Read response data from saved userspace buffer.
    // Zero first so failed reads leave clean data for the Go parser.
    __builtin_memset(event->resp_data, 0, MAX_RESP_SIZE);
    bpf_probe_read_user(event->resp_data, MAX_RESP_SIZE, (const char *)buf_ptr);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&req_map, &req_key);

    return 0;
}
```

**Replace `uretprobe_gnutls_recv` with:** Same as `uretprobe_ssl_read` above.
Copy the entire function and change only the SEC name and function name:
- SEC: `"uretprobe/gnutls_record_recv"`
- Function name: `uretprobe_gnutls_recv`
- Use `ssize_t ret = (ssize_t)PT_REGS_RC(ctx);` (GnuTLS returns ssize_t)

**Replace `uretprobe_pr_read` with:** Same as `uretprobe_ssl_read` above.
Copy the entire function and change only the SEC name and function name:
- SEC: `"uretprobe/PR_Read"`
- Function name: `uretprobe_pr_read`

**Rewrite `kretprobe_sys_read` (complete replacement):**

The kretprobe version is almost identical to the uprobe version, with two differences:
- FD comes from `args->fd` (saved in entry probe), not from TID
- req_map key uses real FD: `((__u64)pid << 32) | (__u32)fd`

```c
SEC("kretprobe/sys_read")
int kretprobe_sys_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_filter_pid(pid))
        return 0;

    ssize_t ret = (ssize_t)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    // Look up saved read arguments from entry probe
    struct read_args_t *args = bpf_map_lookup_elem(&read_args_map, &pid_tgid);
    if (!args)
        return 0;
    __u64 buf_ptr = args->buf_ptr;
    __u32 fd = args->fd;
    bpf_map_delete_elem(&read_args_map, &pid_tgid);

    __u64 now = bpf_ktime_get_ns() / 1000;

    // Look up the pending request (kprobes key by real FD, not TID)
    __u64 req_key = ((__u64)pid << 32) | fd;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &req_key);
    if (!req)
        return 0;

    __u64 latency_us = now - req->start_time;
    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    __u32 zero = 0;
    struct event_t *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    event->timestamp_us = now;
    event->latency_us = latency_us;
    event->pid = pid;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->fd = fd;
    __builtin_memcpy(event->comm, req->comm, TASK_COMM_LEN);
    event->req_size = req->req_size;
    event->resp_size = (__u32)ret;
    event->actual_resp_bytes = (__u32)ret;
    event->is_partial = 0;
    event->client_type = req->client_type;
    __builtin_memcpy(event->data, req->data, MAX_DATA_SIZE);

    __builtin_memset(event->resp_data, 0, MAX_RESP_SIZE);
    bpf_probe_read_user(event->resp_data, MAX_RESP_SIZE, (const char *)buf_ptr);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&req_map, &req_key);

    return 0;
}
```

#### Step 8: Summary of BPF Functions After All Changes

| SEC name | Status | Key type |
|----------|--------|----------|
| `kprobe/sys_write` | REWRITE | `pid<<32 \| fd` |
| `kprobe/sys_read` | REWRITE | saves to `read_args_map` |
| `kretprobe/sys_read` | REWRITE | `pid<<32 \| fd` |
| `uprobe/SSL_write` | REWRITE | `pid<<32 \| tid` |
| `uprobe/SSL_read` | **NEW** | saves to `read_args_map` |
| `uretprobe/SSL_read` | REWRITE | `pid<<32 \| tid` |
| `uprobe/gnutls_record_send` | REWRITE | `pid<<32 \| tid` |
| `uprobe/gnutls_record_recv` | **NEW** | saves to `read_args_map` |
| `uretprobe/gnutls_record_recv` | REWRITE | `pid<<32 \| tid` |
| `uprobe/PR_Write` | REWRITE | `pid<<32 \| tid` |
| `uprobe/PR_Read` | **NEW** | saves to `read_args_map` |
| `uretprobe/PR_Read` | REWRITE | `pid<<32 \| tid` |

#### Step 9: Update `RawEvent` in `internal/ebpf/types.go`

The Go struct MUST match the C `event_t` byte-for-byte. Change `Data` from
`[96]byte` to `[256]byte` and add `RespData`:

```go
type RawEvent struct {
    TimestampUs     uint64
    LatencyUs       uint64
    PID             uint32
    TID             uint32
    FD              uint32
    Comm            [16]byte
    ReqSize         uint32
    RespSize        uint32
    ActualRespBytes uint32
    IsPartial       uint8
    ClientType      uint8
    _               [2]byte
    Data            [256]byte   // was [96]byte
    RespData        [128]byte   // NEW — response headers for status code parsing
}
```

#### Step 10: Update `Pipeline.handleEvent` in `internal/ebpf/pipeline.go`

Add one line to pass captured response data to the status code parser. The
`ParseStatusCode` method already exists in `internal/event/event.go` and calls
`http.ParseHTTPResponse` — it just never had real data to parse until now.

In the `handleEvent` method, add after the existing `s3event.ClientType = ...` line:

```go
// Parse response status code from captured response data
s3event.ParseStatusCode(raw.RespData[:])
```

#### Step 11: Update `AttachUprobes` in `internal/ebpf/tracer.go`

Add entry probes for read functions. The entry probe and return probe for the same
symbol are attached separately — entry as `Uprobe`, return as `Uretprobe`.

For each TLS library's probe list, add the read entry probe BEFORE the return probe:

**OpenSSL (in the `ProbeModeOpenSSL` case):**
```go
{"SSL_write", "uprobe_ssl_write", false},
{"SSL_read", "uprobe_ssl_read", false},       // NEW: entry probe saves buf ptr
{"SSL_read", "uretprobe_ssl_read", true},
```

**GnuTLS (in the `ProbeModeGnuTLS` case):**
```go
{"gnutls_record_send", "uprobe_gnutls_send", false},
{"gnutls_record_recv", "uprobe_gnutls_recv", false},       // NEW
{"gnutls_record_recv", "uretprobe_gnutls_recv", true},
```

**NSS (in the `ProbeModeNSS` case):**
```go
{"PR_Write", "uprobe_pr_write", false},
{"PR_Read", "uprobe_pr_read", false},       // NEW
{"PR_Read", "uretprobe_pr_read", true},
```

#### Step 12: Regenerate BPF Bindings

**This step MUST be run on a Linux host with clang and bpftool installed.**

```bash
make generate
```

This compiles `s3slower.c` into `bpf_x86_bpfel.o` and generates `bpf_x86_bpfel.go`
with updated Go structs, program names, and map names.

After generation, verify the new artifacts by checking the generated Go file:
- New programs should appear: `UprobeSslRead`, `UprobeGnutlsRecv`, `UprobePrRead`
- New maps should appear: `EventHeap`, `ReqHeap`, `ReadArgsMap`
- `bpfReqInfoT.Data` should be `[256]int8` (was `[96]int8`)

```bash
# Quick verification
grep -c 'UprobeSslRead\|UprobeGnutlsRecv\|UprobePrRead' internal/ebpf/bpf_x86_bpfel.go
# Should output: 6 (each appears in ProgramSpecs and Programs structs)

grep 'EventHeap\|ReqHeap\|ReadArgsMap' internal/ebpf/bpf_x86_bpfel.go
# Should show map entries
```

Then build and test:

```bash
make build
make test
```

### BPF Pitfalls Checklist

Use this checklist to verify the implementation before committing:

- [ ] Every `bpf_map_lookup_elem` return is NULL-checked before any dereference
- [ ] `bpf_probe_read_user` always uses a compile-time constant for size
      (`MAX_DATA_SIZE`, `MAX_RESP_SIZE`, `HTTP_CHECK_SIZE`)
- [ ] `bpf_map_delete_elem` called on `req_map` and `read_args_map` after use
- [ ] Per-CPU heap values have every field set explicitly (no stale data from prior events)
- [ ] `resp_data` is zeroed with `__builtin_memset` BEFORE `bpf_probe_read_user`
- [ ] kprobes use real FD for req_map key: `pid<<32 | fd`
- [ ] uprobes use TID for req_map key: `pid<<32 | tid`
- [ ] `read_args_map` is keyed by raw `pid_tgid` (works for both kprobes and uprobes)
- [ ] `RawEvent` in `types.go` matches `event_t` byte-for-byte (448 bytes total)
- [ ] `make generate` was run AFTER modifying `s3slower.c`
- [ ] `bpf_x86_bpfel.go` and `bpf_x86_bpfel.o` were NOT hand-edited
- [ ] All 3 TLS library probe lists in `tracer.go` include the new read entry probes
- [ ] `pipeline.go` calls `s3event.ParseStatusCode(raw.RespData[:])` in handleEvent

### Tests

Existing tests use `MockTracer` and should pass without changes. Add verification:

```go
// In internal/ebpf/types_test.go (create if needed)
func TestRawEventSize(t *testing.T) {
    // Verify Go struct matches expected C struct size
    var event RawEvent
    size := unsafe.Sizeof(event)
    assert.Equal(t, uintptr(448), size,
        "RawEvent size must match C event_t (448 bytes including alignment padding)")
}
```

### Manual Integration Test

On a Linux host with root access:

```bash
# Terminal 1: Run s3slower in debug mode
sudo ./build/s3slower run --debug --no-log

# Terminal 2: Generate S3 traffic
aws s3 ls s3://some-bucket/
# or: curl http://minio-host:9000/bucket/key

# Verify in Terminal 1:
# 1. Event appears with correct S3 operation
# 2. Status code is populated (200, 403, 404, etc.) — NOT 0
# 3. Latency is non-zero
# 4. Longer paths are captured (benefits from 256-byte buffer)
```
