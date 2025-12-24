// Package runner provides the main execution loop for s3slower.
package runner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/s3slower/s3slower/internal/ebpf"
	"github.com/s3slower/s3slower/internal/event"
	"github.com/s3slower/s3slower/internal/logger"
	"github.com/s3slower/s3slower/internal/metrics"
	"github.com/s3slower/s3slower/internal/terminal"
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

	// Debug
	Debug bool
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Mode:             "auto",
		EnableTerminal:   true,
		EnableLogging:    true,
		LogDir:           "/opt/s3slower",
		LogMaxSizeMB:     100,
		LogMaxBackups:    5,
		PrometheusPort:   9000,
		PrometheusHost:   "::",
	}
}

// Runner manages the s3slower execution.
type Runner struct {
	config   Config
	pipeline *ebpf.Pipeline
	terminal *terminal.Writer
	logger   *logger.RotatingLogger
	exporter *metrics.Exporter
	metrics  *metrics.Metrics
}

// New creates a new runner.
func New(cfg Config) (*Runner, error) {
	r := &Runner{
		config: cfg,
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

	return r, nil
}

// Run starts the tracer and runs until interrupted.
func (r *Runner) Run(ctx context.Context) error {
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
	if r.pipeline != nil {
		r.pipeline.Stop()
	}
	if r.logger != nil {
		r.logger.Sync()
		r.logger.Close()
	}
	return nil
}

// RunDemo runs a demo mode that generates sample events.
func (r *Runner) RunDemo(ctx context.Context) error {
	fmt.Println("s3slower demo mode")
	fmt.Println("Generating sample events...")
	fmt.Println()

	// Write header
	if r.terminal != nil {
		r.terminal.WriteHeader()
	}
	if r.logger != nil {
		r.logger.WriteHeader()
	}

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Sample events
	sampleEvents := []event.S3Event{
		{Timestamp: time.Now(), Method: "GET", Bucket: "my-bucket", Endpoint: "s3.amazonaws.com", ResponseSize: 1048576, LatencyMs: 45.2, Path: "/my-bucket/data/file1.json"},
		{Timestamp: time.Now(), Method: "PUT", Bucket: "backup-bucket", Endpoint: "s3.us-west-2.amazonaws.com", ResponseSize: 0, LatencyMs: 123.5, Path: "/backup-bucket/archive/2024/backup.tar.gz"},
		{Timestamp: time.Now(), Method: "GET", Bucket: "logs", Endpoint: "minio.local:9000", ResponseSize: 4096, LatencyMs: 12.3, Path: "/logs/app/2024-01-15/app.log"},
		{Timestamp: time.Now(), Method: "DELETE", Bucket: "temp", Endpoint: "s3.amazonaws.com", ResponseSize: 0, LatencyMs: 89.1, Path: "/temp/scratch/old-file.txt"},
		{Timestamp: time.Now(), Method: "HEAD", Bucket: "assets", Endpoint: "cdn.example.com", ResponseSize: 0, LatencyMs: 5.7, Path: "/assets/images/logo.png"},
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	idx := 0
	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nDemo complete.")
			return nil

		case <-sigCh:
			fmt.Println("\nDemo interrupted.")
			return nil

		case <-ticker.C:
			evt := sampleEvents[idx%len(sampleEvents)]
			evt.Timestamp = time.Now()
			r.handleEvent(&evt)
			idx++
		}
	}
}
