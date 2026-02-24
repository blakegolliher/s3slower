// Package runner provides the main execution loop for s3slower.
package runner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/s3slower/s3slower/internal/config"
	"github.com/s3slower/s3slower/internal/ebpf"
	"github.com/s3slower/s3slower/internal/event"
	"github.com/s3slower/s3slower/internal/logger"
	"github.com/s3slower/s3slower/internal/metrics"
	"github.com/s3slower/s3slower/internal/terminal"
	"github.com/s3slower/s3slower/internal/watcher"
)

// Config holds runner configuration.
type Config struct {
	// Probe settings
	Mode         string // http, openssl, gnutls, nss, auto
	TargetPID    uint32
	MinLatencyMs uint64
	LibraryPath  string

	// Output settings
	EnableTerminal    bool
	EnablePrometheus  bool
	EnableLogging     bool
	PrometheusPort    int
	PrometheusHost    string
	LogDir            string
	LogMaxSizeMB      int
	LogMaxBackups     int
	OutputFormat      string // "table", "simple", "json"

	// Screen settings
	TableFormat  bool
	MaxURLLength int

	// Watch settings
	WatchProcesses []string

	// Config file paths for hot-reload
	ConfigPath  string
	TargetsPath string

	// Debug
	Debug bool
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Mode:             "auto",
		EnableTerminal:   true,
		EnableLogging:    true,
		LogDir:           "/var/log/s3slower",
		LogMaxSizeMB:     100,
		LogMaxBackups:    5,
		PrometheusPort:   9000,
		PrometheusHost:   "::",
		OutputFormat:     "table",
		TableFormat:      true,
		MaxURLLength:     50,
	}
}

// Runner manages the s3slower execution.
type Runner struct {
	config          Config
	pipeline        *ebpf.Pipeline
	terminal        *terminal.Writer
	logger          *logger.RotatingLogger
	exporter        *metrics.Exporter
	metrics         *metrics.Metrics
	configWatcher   *config.ConfigWatcher
	targetWatcher   *watcher.TargetWatcher

	// Mutex for config updates
	mu           sync.RWMutex
	targets      []config.TargetConfig
	minLatencyMs uint64

	// targetLabels maps PIDs to their target's Prometheus labels
	targetLabels map[uint32]map[string]string
}

// New creates a new runner.
func New(cfg Config) (*Runner, error) {
	r := &Runner{
		config:       cfg,
		minLatencyMs: cfg.MinLatencyMs,
	}

	// Set up terminal output
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

	// Set up file logging
	if cfg.EnableLogging {
		logCfg := logger.Config{
			Dir:        cfg.LogDir,
			Prefix:     "s3slower",
			MaxSizeMB:  cfg.LogMaxSizeMB,
			MaxBackups: cfg.LogMaxBackups,
		}
		l, err := logger.NewRotatingLogger(logCfg)
		if err != nil {
			// Non-fatal: warn and continue without logging
			fmt.Fprintf(os.Stderr, "Warning: failed to create logger: %v\n", err)
		} else {
			r.logger = l
		}
	}

	// Set up config watcher for hot-reload
	if cfg.ConfigPath != "" || cfg.TargetsPath != "" {
		cw, err := config.NewConfigWatcher(cfg.ConfigPath, cfg.TargetsPath)
		if err != nil {
			// Non-fatal: warn and continue without hot-reload
			fmt.Fprintf(os.Stderr, "Warning: failed to create config watcher: %v\n", err)
		} else {
			r.configWatcher = cw

			// Set up callbacks
			cw.OnAppConfigChange(r.handleAppConfigChange)
			cw.OnTargetsChange(r.handleTargetsChange)

			// Load initial targets
			if targets := cw.Targets(); targets != nil {
				r.targets = targets
			}
		}
	}

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

	// Set up Prometheus metrics (after targets are loaded for label collection)
	if cfg.EnablePrometheus {
		addr := fmt.Sprintf("%s:%d", cfg.PrometheusHost, cfg.PrometheusPort)
		extraLabels := config.CollectExtraLabelKeys(r.targets)
		r.exporter = metrics.NewExporter(addr, extraLabels)
		r.metrics = r.exporter.Metrics()
	}

	// Set up target watcher for process monitoring
	if len(r.targets) > 0 {
		r.targetWatcher = watcher.NewTargetWatcher(r.targets, r.onProcessAttach)
	}

	return r, nil
}

// onProcessAttach is called when a matching process is found by the target watcher.
// Probes are attached globally (not per-process). The watcher provides process
// identification for Prometheus label enrichment and PID-based filtering.
func (r *Runner) onProcessAttach(pid int, comm string, target *config.TargetConfig) {
	r.debugf("Matched process: pid=%d comm=%s target=%s mode=%s",
		pid, comm, target.ID, target.Mode)

	fmt.Fprintf(os.Stderr, "Detected S3 client: %s (PID %d, target: %s)\n",
		comm, pid, target.ID)

	// Store the target association for label enrichment
	if len(target.PromLabels) > 0 {
		r.mu.Lock()
		if r.targetLabels == nil {
			r.targetLabels = make(map[uint32]map[string]string)
		}
		r.targetLabels[uint32(pid)] = target.PromLabels
		r.mu.Unlock()
	}
}

// handleAppConfigChange is called when the app config file changes.
func (r *Runner) handleAppConfigChange(cfg *config.AppConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Update min latency (can be changed at runtime)
	if cfg.MinLatencyMs > 0 {
		r.minLatencyMs = uint64(cfg.MinLatencyMs)
		fmt.Fprintf(os.Stderr, "Updated min latency to %dms\n", cfg.MinLatencyMs)
	}

	// Debug mode change
	if cfg.Debug != r.config.Debug {
		r.config.Debug = cfg.Debug
		fmt.Fprintf(os.Stderr, "Debug mode: %v\n", cfg.Debug)
	}
}

// handleTargetsChange is called when the targets config file changes.
func (r *Runner) handleTargetsChange(targets []config.TargetConfig) {
	r.mu.Lock()
	r.targets = targets
	tw := r.targetWatcher
	r.mu.Unlock()

	fmt.Fprintf(os.Stderr, "Updated targets: %d configured\n", len(targets))

	// Print target IDs for visibility
	for _, t := range targets {
		fmt.Fprintf(os.Stderr, "  - %s (match: %s=%s, mode: %s)\n",
			t.ID, t.MatchType, t.MatchValue, t.Mode)
	}

	// Update the target watcher with new targets
	if tw != nil {
		tw.UpdateTargets(targets)
	} else if len(targets) > 0 {
		// Create a new target watcher if we didn't have one
		r.mu.Lock()
		r.targetWatcher = watcher.NewTargetWatcher(targets, r.onProcessAttach)
		r.targetWatcher.Start()
		r.mu.Unlock()
	}
}

// Targets returns the current target configurations.
func (r *Runner) Targets() []config.TargetConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.targets
}

// MinLatencyMs returns the current minimum latency filter.
func (r *Runner) MinLatencyMs() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.minLatencyMs
}

// Run starts the tracer and runs until interrupted.
func (r *Runner) Run(ctx context.Context) error {
	// Start config watcher for hot-reload
	if r.configWatcher != nil {
		r.configWatcher.Start()
		defer r.configWatcher.Stop()
	}

	// Start target watcher for process detection
	if r.targetWatcher != nil {
		if err := r.targetWatcher.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to start target watcher: %v\n", err)
		} else {
			defer r.targetWatcher.Stop()
			fmt.Fprintf(os.Stderr, "Watching for %d target processes\n", len(r.targets))
		}
	}

	// Convert mode string to ProbeMode
	mode := ebpf.ProbeModeAuto
	switch r.config.Mode {
	case "http":
		mode = ebpf.ProbeModeHTTP
	case "openssl":
		mode = ebpf.ProbeModeOpenSSL
	case "gnutls":
		mode = ebpf.ProbeModeGnuTLS
	case "nss":
		mode = ebpf.ProbeModeNSS
	case "auto":
		mode = ebpf.ProbeModeAuto
	}

	// Create pipeline configuration
	pipelineCfg := ebpf.PipelineConfig{
		Mode:         mode,
		TargetPID:    r.config.TargetPID,
		MinLatencyMs: r.config.MinLatencyMs,
		LibraryPath:  r.config.LibraryPath,
		BufferSize:   1000,
		Debug:        r.config.Debug,
	}

	// Try to create real BPF pipeline, fall back to mock if not available
	pipeline, err := ebpf.NewPipeline(pipelineCfg)
	if err != nil {
		// Fall back to mock tracer (useful for development/testing without root)
		if r.config.Debug {
			fmt.Fprintf(os.Stderr, "BPF tracer unavailable (%v), using mock tracer\n", err)
		}
		pipeline, err = ebpf.NewPipelineWithMock(pipelineCfg)
		if err != nil {
			return fmt.Errorf("failed to create pipeline: %w", err)
		}
	}
	r.pipeline = pipeline
	r.debugf("Pipeline created with mode=%s targetPID=%d minLatencyMs=%d",
		mode, r.config.TargetPID, r.config.MinLatencyMs)

	// Start the pipeline
	if err := r.pipeline.Start(); err != nil {
		return fmt.Errorf("failed to start pipeline: %w", err)
	}
	defer r.pipeline.Stop()
	r.debugf("Pipeline started, reading events from perf buffer")

	// Print startup message
	fmt.Fprintln(os.Stderr, "s3slower tracer started")
	fmt.Fprintf(os.Stderr, "  Mode: %s\n", mode)
	if r.config.TargetPID > 0 {
		fmt.Fprintf(os.Stderr, "  Target PID: %d\n", r.config.TargetPID)
	}
	if r.config.MinLatencyMs > 0 {
		fmt.Fprintf(os.Stderr, "  Min latency: %dms\n", r.config.MinLatencyMs)
	}
	if r.logger != nil {
		fmt.Fprintf(os.Stderr, "  Logging to: %s\n", r.config.LogDir)
	}
	fmt.Fprintln(os.Stderr)

	// Write headers
	if r.terminal != nil {
		r.terminal.WriteHeader()
	}
	if r.logger != nil {
		r.logger.WriteHeader()
	}

	// Start Prometheus server if enabled
	if r.config.EnablePrometheus && r.metrics != nil {
		go r.startPrometheusServer()
	}

	if r.config.Debug {
		stats := r.pipeline.Stats()
		r.debugf("Active probes: %d", stats.TracerStats.ActiveProbes)
		r.debugf("Target watcher: %v (%d targets)", r.targetWatcher != nil, len(r.targets))
		r.debugf("Terminal: %v, Logger: %v, Prometheus: %v",
			r.terminal != nil, r.logger != nil, r.exporter != nil)
	}

	// Start periodic cleanup of stale PIDs and in-flight requests
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Main event loop
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "\nShutting down...")
			return nil

		case <-sigCh:
			fmt.Fprintln(os.Stderr, "\nReceived interrupt, shutting down...")
			return nil

		case <-cleanupTicker.C:
			if r.targetWatcher != nil {
				r.targetWatcher.CleanupExited()
				r.debugf("Cleanup: %d attached PIDs", len(r.targetWatcher.GetAttached()))
			}

		case evt, ok := <-r.pipeline.Events():
			if !ok {
				return nil
			}
			r.handleEvent(evt)
		}
	}
}

// handleEvent processes a single event.
func (r *Runner) handleEvent(evt *event.S3Event) {
	r.debugf("Event: pid=%d method=%s op=%s bucket=%s latency=%.2fms",
		evt.PID, evt.Method, evt.Operation, evt.Bucket, evt.LatencyMs)

	// Check against current min latency filter (from hot-reload)
	minLatency := r.MinLatencyMs()
	if minLatency > 0 && evt.LatencyMs < float64(minLatency) {
		return // Skip events below the threshold
	}

	// Write to terminal
	if r.terminal != nil {
		r.terminal.WriteEvent(evt)
	}

	// Write to log file
	if r.logger != nil {
		r.logger.WriteEvent(evt)
	}

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

// startPrometheusServer starts the Prometheus HTTP server.
func (r *Runner) startPrometheusServer() {
	if r.exporter == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "Starting Prometheus server on %s:%d\n", r.config.PrometheusHost, r.config.PrometheusPort)
	if err := r.exporter.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Prometheus server error: %v\n", err)
	}
}

// debugf prints a debug message if debug mode is enabled.
func (r *Runner) debugf(format string, args ...interface{}) {
	if r.config.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}

// Close cleans up resources.
func (r *Runner) Close() error {
	if r.targetWatcher != nil {
		r.targetWatcher.Stop()
	}
	if r.configWatcher != nil {
		r.configWatcher.Stop()
	}
	if r.pipeline != nil {
		r.pipeline.Stop()
	}
	if r.logger != nil {
		r.logger.Sync()
		r.logger.Close()
	}
	return nil
}

