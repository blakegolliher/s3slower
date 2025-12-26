// Package runner provides tests for the s3slower runner.
package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/s3slower/s3slower/internal/event"
	"github.com/s3slower/s3slower/internal/terminal"
)

// TestDefaultConfig tests the DefaultConfig function.
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "auto", cfg.Mode)
	assert.True(t, cfg.EnableTerminal)
	assert.True(t, cfg.EnableLogging)
	assert.Equal(t, "/var/log/s3slower", cfg.LogDir)
	assert.Equal(t, 100, cfg.LogMaxSizeMB)
	assert.Equal(t, 5, cfg.LogMaxBackups)
	assert.Equal(t, 9000, cfg.PrometheusPort)
	assert.Equal(t, "::", cfg.PrometheusHost)
	assert.False(t, cfg.EnablePrometheus)
}

// TestNewRunner tests creating a new runner.
func TestNewRunner(t *testing.T) {
	t.Run("creates_runner_with_defaults", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := DefaultConfig()
		cfg.LogDir = tmpDir
		cfg.EnableLogging = true
		cfg.EnablePrometheus = false

		r, err := New(cfg)
		require.NoError(t, err)
		require.NotNil(t, r)
		defer r.Close()

		assert.NotNil(t, r.terminal)
		assert.NotNil(t, r.logger)
		assert.Nil(t, r.exporter)
	})

	t.Run("creates_runner_without_logging", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.EnableLogging = false

		r, err := New(cfg)
		require.NoError(t, err)
		require.NotNil(t, r)
		defer r.Close()

		assert.NotNil(t, r.terminal)
		assert.Nil(t, r.logger)
	})

	t.Run("creates_runner_without_terminal", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.EnableTerminal = false
		cfg.EnableLogging = false

		r, err := New(cfg)
		require.NoError(t, err)
		require.NotNil(t, r)
		defer r.Close()

		assert.Nil(t, r.terminal)
	})

	t.Run("creates_runner_with_prometheus", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.EnablePrometheus = true
		cfg.EnableLogging = false
		cfg.PrometheusPort = 9999

		r, err := New(cfg)
		require.NoError(t, err)
		require.NotNil(t, r)
		defer r.Close()

		assert.NotNil(t, r.exporter)
		assert.NotNil(t, r.metrics)
	})

	t.Run("handles_invalid_log_directory", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.EnableLogging = true
		cfg.LogDir = "/root/cannot_write_here"

		r, err := New(cfg)
		// Should still succeed but without logger (non-fatal warning)
		require.NoError(t, err)
		defer r.Close()
	})
}

// TestRunnerClose tests closing the runner.
func TestRunnerClose(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := DefaultConfig()
	cfg.LogDir = tmpDir
	cfg.EnableLogging = true

	r, err := New(cfg)
	require.NoError(t, err)

	err = r.Close()
	assert.NoError(t, err)

	// Double close should be safe
	err = r.Close()
	assert.NoError(t, err)
}

// TestHandleEvent tests event handling.
func TestHandleEvent(t *testing.T) {
	t.Run("writes_to_terminal", func(t *testing.T) {
		var buf bytes.Buffer
		r := &Runner{
			config:   DefaultConfig(),
			terminal: terminal.NewWriter(&buf, terminal.OutputModeTable, 50),
		}

		evt := &event.S3Event{
			Timestamp:    time.Now(),
			Method:       "GET",
			Bucket:       "my-bucket",
			Endpoint:     "s3.amazonaws.com",
			ResponseSize: 1024,
			LatencyMs:    50.0,
			Path:         "/my-bucket/key.txt",
		}

		r.handleEvent(evt)

		output := buf.String()
		assert.Contains(t, output, "GET")
		assert.Contains(t, output, "my-bucket")
		assert.Contains(t, output, "s3.amazonaws.com")
	})

	t.Run("writes_to_logger", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := DefaultConfig()
		cfg.LogDir = tmpDir
		cfg.EnableLogging = true
		cfg.EnableTerminal = false

		r, err := New(cfg)
		require.NoError(t, err)
		defer r.Close()

		evt := &event.S3Event{
			Timestamp:    time.Now(),
			Method:       "PUT",
			Bucket:       "test-bucket",
			Endpoint:     "minio.local",
			ResponseSize: 2048,
			LatencyMs:    100.0,
			Path:         "/test-bucket/data.json",
		}

		r.handleEvent(evt)
		r.logger.Sync()

		// Check log file
		matches, err := filepath.Glob(filepath.Join(tmpDir, "s3slower_*.log"))
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(matches), 1)

		content, err := os.ReadFile(matches[0])
		require.NoError(t, err)

		assert.Contains(t, string(content), "PUT")
		assert.Contains(t, string(content), "test-bucket")
	})

	t.Run("records_metrics", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.EnablePrometheus = true
		cfg.EnableLogging = false
		cfg.EnableTerminal = false

		r, err := New(cfg)
		require.NoError(t, err)
		defer r.Close()

		evt := &event.S3Event{
			Timestamp:    time.Now(),
			PID:          12345,
			Comm:         "aws",
			Method:       "GET",
			Operation:    "GetObject",
			Bucket:       "metrics-bucket",
			ResponseSize: 1024,
			LatencyMs:    75.0,
			Path:         "/metrics-bucket/file.txt",
		}

		// Should not panic
		r.handleEvent(evt)
	})
}

// TestConfigModes tests different configuration modes.
func TestConfigModes(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{"http", "http"},
		{"openssl", "openssl"},
		{"gnutls", "gnutls"},
		{"nss", "nss"},
		{"auto", "auto"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Mode = tt.mode
			cfg.EnableLogging = false
			cfg.EnableTerminal = false

			r, err := New(cfg)
			require.NoError(t, err)
			defer r.Close()

			assert.Equal(t, tt.mode, r.config.Mode)
		})
	}
}

// TestConfigFilters tests filter configuration.
func TestConfigFilters(t *testing.T) {
	t.Run("sets_target_pid", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.TargetPID = 12345
		cfg.EnableLogging = false

		r, err := New(cfg)
		require.NoError(t, err)
		defer r.Close()

		assert.Equal(t, uint32(12345), r.config.TargetPID)
	})

	t.Run("sets_min_latency", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.MinLatencyMs = 100
		cfg.EnableLogging = false

		r, err := New(cfg)
		require.NoError(t, err)
		defer r.Close()

		assert.Equal(t, uint64(100), r.config.MinLatencyMs)
	})

	t.Run("sets_watch_processes", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.WatchProcesses = []string{"mc", "warp", "aws"}
		cfg.EnableLogging = false

		r, err := New(cfg)
		require.NoError(t, err)
		defer r.Close()

		assert.Equal(t, []string{"mc", "warp", "aws"}, r.config.WatchProcesses)
	})
}

// TestLoggingConfig tests logging configuration.
func TestLoggingConfig(t *testing.T) {
	t.Run("custom_log_directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		customDir := filepath.Join(tmpDir, "custom_logs")

		cfg := DefaultConfig()
		cfg.LogDir = customDir
		cfg.EnableLogging = true

		r, err := New(cfg)
		require.NoError(t, err)
		defer r.Close()

		// Write an event
		evt := &event.S3Event{
			Timestamp: time.Now(),
			Method:    "GET",
			Path:      "/bucket/key",
		}
		r.handleEvent(evt)
		r.logger.Sync()

		// Check log file exists in custom directory
		matches, err := filepath.Glob(filepath.Join(customDir, "s3slower_*.log"))
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(matches), 1)
	})

	t.Run("custom_log_size", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := DefaultConfig()
		cfg.LogDir = tmpDir
		cfg.LogMaxSizeMB = 50

		r, err := New(cfg)
		require.NoError(t, err)
		defer r.Close()

		assert.Equal(t, 50, r.config.LogMaxSizeMB)
	})

	t.Run("custom_max_backups", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := DefaultConfig()
		cfg.LogDir = tmpDir
		cfg.LogMaxBackups = 10

		r, err := New(cfg)
		require.NoError(t, err)
		defer r.Close()

		assert.Equal(t, 10, r.config.LogMaxBackups)
	})
}

// TestPrometheusConfig tests Prometheus configuration.
func TestPrometheusConfig(t *testing.T) {
	t.Run("custom_port", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.EnablePrometheus = true
		cfg.PrometheusPort = 8080
		cfg.EnableLogging = false

		r, err := New(cfg)
		require.NoError(t, err)
		defer r.Close()

		assert.Equal(t, 8080, r.config.PrometheusPort)
	})

	t.Run("custom_host", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.EnablePrometheus = true
		cfg.PrometheusHost = "127.0.0.1"
		cfg.EnableLogging = false

		r, err := New(cfg)
		require.NoError(t, err)
		defer r.Close()

		assert.Equal(t, "127.0.0.1", r.config.PrometheusHost)
	})
}

// TestDebugMode tests debug mode configuration.
func TestDebugMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Debug = true
	cfg.EnableLogging = false

	r, err := New(cfg)
	require.NoError(t, err)
	defer r.Close()

	assert.True(t, r.config.Debug)
}

// BenchmarkHandleEvent benchmarks event handling.
func BenchmarkHandleEvent(b *testing.B) {
	var buf bytes.Buffer
	r := &Runner{
		config:   DefaultConfig(),
		terminal: terminal.NewWriter(&buf, terminal.OutputModeTable, 50),
	}

	evt := &event.S3Event{
		Timestamp:    time.Now(),
		Method:       "GET",
		Bucket:       "my-bucket",
		Endpoint:     "s3.amazonaws.com",
		ResponseSize: 1024,
		LatencyMs:    50.0,
		Path:         "/my-bucket/key.txt",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.handleEvent(evt)
	}
}
