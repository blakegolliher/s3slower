// Package runner provides the main execution loop for s3slower.
package runner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

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
}

// New creates a new runner.
func New(cfg Config) (*Runner, error) {
	r := &Runner{
		config:       cfg,
		minLatencyMs: cfg.MinLatencyMs,
	}

	// Set up terminal output
	if cfg.EnableTerminal {
		r.terminal = terminal.NewWriter(os.Stdout, terminal.OutputModeTable, 50)
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

	// Set up Prometheus metrics
	if cfg.EnablePrometheus {
		addr := fmt.Sprintf("%s:%d", cfg.PrometheusHost, cfg.PrometheusPort)
		r.exporter = metrics.NewExporter(addr, nil)
		r.metrics = r.exporter.Metrics()
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

	// Set up target watcher for process monitoring
	if len(r.targets) > 0 {
		r.targetWatcher = watcher.NewTargetWatcher(r.targets, r.onProcessAttach)
	}

	return r, nil
}

// onProcessAttach is called when a matching process is found.
func (r *Runner) onProcessAttach(pid int, comm string, target *config.TargetConfig) {
	fmt.Printf("Detected S3 client: %s (PID %d, target: %s, mode: %s)\n",
		comm, pid, target.ID, target.Mode)

	// TODO: Attach eBPF probes to this process
	// This will be implemented when we switch to the real tracer
}

// handleAppConfigChange is called when the app config file changes.
func (r *Runner) handleAppConfigChange(cfg *config.AppConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Update min latency (can be changed at runtime)
	if cfg.MinLatencyMs > 0 {
		r.minLatencyMs = uint64(cfg.MinLatencyMs)
		fmt.Printf("Updated min latency to %dms\n", cfg.MinLatencyMs)
	}

	// Debug mode change
	if cfg.Debug != r.config.Debug {
		r.config.Debug = cfg.Debug
		fmt.Printf("Debug mode: %v\n", cfg.Debug)
	}
}

// handleTargetsChange is called when the targets config file changes.
func (r *Runner) handleTargetsChange(targets []config.TargetConfig) {
	r.mu.Lock()
	r.targets = targets
	tw := r.targetWatcher
	r.mu.Unlock()

	fmt.Printf("Updated targets: %d configured\n", len(targets))

	// Print target IDs for visibility
	for _, t := range targets {
		fmt.Printf("  - %s (match: %s=%s, mode: %s)\n",
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
			fmt.Printf("Watching for %d target processes\n", len(r.targets))
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
	}

	// Create pipeline (use mock for now since BPF isn't compiled)
	pipeline, err := ebpf.NewPipelineWithMock(pipelineCfg)
	if err != nil {
		return fmt.Errorf("failed to create pipeline: %w", err)
	}
	r.pipeline = pipeline

	// Start the pipeline
	if err := r.pipeline.Start(); err != nil {
		return fmt.Errorf("failed to start pipeline: %w", err)
	}
	defer r.pipeline.Stop()

	// Print startup message
	fmt.Println("s3slower tracer started")
	fmt.Printf("  Mode: %s\n", mode)
	if r.config.TargetPID > 0 {
		fmt.Printf("  Target PID: %d\n", r.config.TargetPID)
	}
	if r.config.MinLatencyMs > 0 {
		fmt.Printf("  Min latency: %dms\n", r.config.MinLatencyMs)
	}
	if r.logger != nil {
		fmt.Printf("  Logging to: %s\n", r.config.LogDir)
	}
	fmt.Println()

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

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Main event loop
	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nShutting down...")
			return nil

		case <-sigCh:
			fmt.Println("\nReceived interrupt, shutting down...")
			return nil

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

	// Record metrics
	if r.metrics != nil {
		hostname, _ := os.Hostname()
		labels := map[string]string{
			"hostname":     hostname,
			"comm":         evt.Comm,
			"s3_operation": string(evt.Operation),
			"method":       evt.Method,
			"pid":          fmt.Sprintf("%d", evt.PID),
		}
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
	fmt.Printf("Starting Prometheus server on %s:%d\n", r.config.PrometheusHost, r.config.PrometheusPort)
	if err := r.exporter.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Prometheus server error: %v\n", err)
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

