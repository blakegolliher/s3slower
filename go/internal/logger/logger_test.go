// Package logger provides rotating file logging tests.
package logger

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/s3slower/s3slower/internal/event"
)

// TestDefaultConfig tests the DefaultConfig function.
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "/opt/s3slower", cfg.Dir)
	assert.Equal(t, "s3slower", cfg.Prefix)
	assert.Equal(t, 100, cfg.MaxSizeMB)
	assert.Equal(t, 5, cfg.MaxBackups)
}

// TestNewRotatingLogger tests creating a new logger.
func TestNewRotatingLogger(t *testing.T) {
	t.Run("creates_logger_with_defaults", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := Config{
			Dir:        tmpDir,
			Prefix:     "test",
			MaxSizeMB:  1,
			MaxBackups: 3,
		}

		logger, err := NewRotatingLogger(cfg)
		require.NoError(t, err)
		require.NotNil(t, logger)
		defer logger.Close()

		assert.Equal(t, tmpDir, logger.dir)
		assert.Equal(t, "test", logger.prefix)
		assert.Equal(t, int64(1*1024*1024), logger.maxSize)
		assert.Equal(t, 3, logger.maxBackups)
	})

	t.Run("creates_directory_if_not_exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		newDir := filepath.Join(tmpDir, "logs", "nested")

		cfg := Config{
			Dir:        newDir,
			Prefix:     "test",
			MaxSizeMB:  1,
			MaxBackups: 3,
		}

		logger, err := NewRotatingLogger(cfg)
		require.NoError(t, err)
		defer logger.Close()

		// Directory should exist
		info, err := os.Stat(newDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("uses_defaults_for_zero_values", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := Config{
			Dir: tmpDir,
		}

		logger, err := NewRotatingLogger(cfg)
		require.NoError(t, err)
		defer logger.Close()

		assert.Equal(t, "s3slower", logger.prefix)
		assert.Equal(t, int64(100*1024*1024), logger.maxSize)
		assert.Equal(t, 5, logger.maxBackups)
	})

	t.Run("fails_on_invalid_directory", func(t *testing.T) {
		cfg := Config{
			Dir: "/root/cannot_create_here_without_permission",
		}

		logger, err := NewRotatingLogger(cfg)
		if err == nil {
			// If we're running as root, this might succeed
			logger.Close()
			t.Skip("running as root, cannot test permission error")
		}
		assert.Error(t, err)
	})
}

// TestWriteEvent tests writing events to the log.
func TestWriteEvent(t *testing.T) {
	t.Run("writes_event_to_file", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := Config{
			Dir:        tmpDir,
			Prefix:     "test",
			MaxSizeMB:  1,
			MaxBackups: 3,
		}

		logger, err := NewRotatingLogger(cfg)
		require.NoError(t, err)
		defer logger.Close()

		evt := &event.S3Event{
			Timestamp:    time.Now(),
			Method:       "GET",
			Bucket:       "my-bucket",
			Endpoint:     "s3.amazonaws.com",
			ResponseSize: 1024,
			LatencyMs:    45.5,
			Path:         "/my-bucket/data/file.json",
		}

		err = logger.WriteEvent(evt)
		require.NoError(t, err)

		// Sync and check file
		logger.Sync()

		// Find log file
		matches, err := filepath.Glob(filepath.Join(tmpDir, "test_*.log"))
		require.NoError(t, err)
		require.Len(t, matches, 1)

		content, err := os.ReadFile(matches[0])
		require.NoError(t, err)

		assert.Contains(t, string(content), "GET")
		assert.Contains(t, string(content), "my-bucket")
		assert.Contains(t, string(content), "s3.amazonaws.com")
		assert.Contains(t, string(content), "1024")
		assert.Contains(t, string(content), "45.5")
		assert.Contains(t, string(content), "/my-bucket/data/file.json")
	})

	t.Run("writes_multiple_events", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := Config{
			Dir:        tmpDir,
			Prefix:     "test",
			MaxSizeMB:  1,
			MaxBackups: 3,
		}

		logger, err := NewRotatingLogger(cfg)
		require.NoError(t, err)
		defer logger.Close()

		for i := 0; i < 10; i++ {
			evt := &event.S3Event{
				Timestamp:    time.Now(),
				Method:       "PUT",
				Bucket:       "bucket",
				ResponseSize: uint32(i * 100),
				LatencyMs:    float64(i) * 10.0,
				Path:         "/bucket/key",
			}
			err = logger.WriteEvent(evt)
			require.NoError(t, err)
		}

		logger.Sync()

		matches, err := filepath.Glob(filepath.Join(tmpDir, "test_*.log"))
		require.NoError(t, err)
		require.Len(t, matches, 1)

		content, err := os.ReadFile(matches[0])
		require.NoError(t, err)

		// Should have 10 lines
		lines := 0
		for _, c := range content {
			if c == '\n' {
				lines++
			}
		}
		assert.Equal(t, 10, lines)
	})
}

// TestWriteHeader tests writing the header.
func TestWriteHeader(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		Dir:        tmpDir,
		Prefix:     "test",
		MaxSizeMB:  1,
		MaxBackups: 3,
	}

	logger, err := NewRotatingLogger(cfg)
	require.NoError(t, err)
	defer logger.Close()

	err = logger.WriteHeader()
	require.NoError(t, err)

	logger.Sync()

	matches, err := filepath.Glob(filepath.Join(tmpDir, "test_*.log"))
	require.NoError(t, err)
	require.Len(t, matches, 1)

	content, err := os.ReadFile(matches[0])
	require.NoError(t, err)

	assert.Contains(t, string(content), "TIMESTAMP")
	assert.Contains(t, string(content), "METHOD")
	assert.Contains(t, string(content), "BUCKET")
	assert.Contains(t, string(content), "ENDPOINT")
	assert.Contains(t, string(content), "BYTES")
	assert.Contains(t, string(content), "LATENCY_MS")
	assert.Contains(t, string(content), "KEY")
	assert.Contains(t, string(content), "---")
}

// TestLogRotation tests log rotation by size.
func TestLogRotation(t *testing.T) {
	t.Run("rotates_when_size_exceeded", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := Config{
			Dir:        tmpDir,
			Prefix:     "test",
			MaxSizeMB:  0, // Will use default, but we'll override maxSize
			MaxBackups: 3,
		}

		logger, err := NewRotatingLogger(cfg)
		require.NoError(t, err)
		defer logger.Close()

		// Override max size to a very small value for testing
		logger.maxSize = 200 // 200 bytes

		// Write events until rotation - each event is ~100+ bytes
		for i := 0; i < 30; i++ {
			evt := &event.S3Event{
				Timestamp:    time.Now(),
				Method:       "GET",
				Bucket:       "bucket-name-that-is-long",
				Endpoint:     "s3.us-west-2.amazonaws.com",
				ResponseSize: 1024,
				LatencyMs:    100.0,
				Path:         "/bucket-name/some/very/long/path/to/file.json",
			}
			err = logger.WriteEvent(evt)
			require.NoError(t, err)

			// Small delay to ensure different timestamps for new files
			time.Sleep(5 * time.Millisecond)
		}

		logger.Sync()

		// Should have multiple log files
		matches, err := filepath.Glob(filepath.Join(tmpDir, "test_*.log"))
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(matches), 2, "should have rotated at least once")
	})

	t.Run("cleans_up_old_logs", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := Config{
			Dir:        tmpDir,
			Prefix:     "test",
			MaxSizeMB:  1,
			MaxBackups: 2, // Keep only 2 backups
		}

		logger, err := NewRotatingLogger(cfg)
		require.NoError(t, err)
		defer logger.Close()

		// Override max size
		logger.maxSize = 200

		// Write many events to trigger multiple rotations
		for i := 0; i < 50; i++ {
			evt := &event.S3Event{
				Timestamp:    time.Now(),
				Method:       "GET",
				Bucket:       "bucket",
				ResponseSize: 1024,
				LatencyMs:    100.0,
				Path:         "/bucket/file.json",
			}
			_ = logger.WriteEvent(evt)
			time.Sleep(5 * time.Millisecond)
		}

		logger.Sync()

		// Should have at most maxBackups + 1 log files
		matches, err := filepath.Glob(filepath.Join(tmpDir, "test_*.log"))
		require.NoError(t, err)
		assert.LessOrEqual(t, len(matches), 3, "should keep only maxBackups logs")
	})
}

// TestClose tests closing the logger.
func TestClose(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		Dir:        tmpDir,
		Prefix:     "test",
		MaxSizeMB:  1,
		MaxBackups: 3,
	}

	logger, err := NewRotatingLogger(cfg)
	require.NoError(t, err)

	// Write something
	evt := &event.S3Event{
		Timestamp: time.Now(),
		Method:    "GET",
		Bucket:    "bucket",
		Path:      "/bucket/key",
	}
	_ = logger.WriteEvent(evt)

	// Close should not error
	err = logger.Close()
	assert.NoError(t, err)

	// Double close should also not error
	err = logger.Close()
	assert.NoError(t, err)
}

// TestSync tests syncing the logger.
func TestSync(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		Dir:        tmpDir,
		Prefix:     "test",
		MaxSizeMB:  1,
		MaxBackups: 3,
	}

	logger, err := NewRotatingLogger(cfg)
	require.NoError(t, err)
	defer logger.Close()

	evt := &event.S3Event{
		Timestamp: time.Now(),
		Method:    "GET",
		Bucket:    "bucket",
		Path:      "/bucket/key",
	}
	_ = logger.WriteEvent(evt)

	err = logger.Sync()
	assert.NoError(t, err)
}

// TestTruncateLog tests the truncateLog helper function.
func TestTruncateLog(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is to"},
		{"", 10, ""},
		{"test", 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := truncateLog(tt.input, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRepeatChar tests the repeatChar helper function.
func TestRepeatChar(t *testing.T) {
	tests := []struct {
		char     rune
		n        int
		expected string
	}{
		{'-', 5, "-----"},
		{'*', 3, "***"},
		{'x', 0, ""},
		{'a', 1, "a"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := repeatChar(tt.char, tt.n)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestConcurrentWrites tests thread safety of the logger.
func TestConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		Dir:        tmpDir,
		Prefix:     "test",
		MaxSizeMB:  1,
		MaxBackups: 3,
	}

	logger, err := NewRotatingLogger(cfg)
	require.NoError(t, err)
	defer logger.Close()

	// Write from multiple goroutines
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				evt := &event.S3Event{
					Timestamp:    time.Now(),
					Method:       "GET",
					Bucket:       "bucket",
					ResponseSize: uint32(id * 100),
					LatencyMs:    float64(j),
					Path:         "/bucket/key",
				}
				_ = logger.WriteEvent(evt)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	logger.Sync()

	// Should have written all events without panic
	matches, err := filepath.Glob(filepath.Join(tmpDir, "test_*.log"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(matches), 1)
}

// BenchmarkWriteEvent benchmarks event writing.
func BenchmarkWriteEvent(b *testing.B) {
	tmpDir := b.TempDir()
	cfg := Config{
		Dir:        tmpDir,
		Prefix:     "bench",
		MaxSizeMB:  100,
		MaxBackups: 1,
	}

	logger, _ := NewRotatingLogger(cfg)
	defer logger.Close()

	evt := &event.S3Event{
		Timestamp:    time.Now(),
		Method:       "GET",
		Bucket:       "my-bucket",
		Endpoint:     "s3.amazonaws.com",
		ResponseSize: 1024,
		LatencyMs:    45.5,
		Path:         "/my-bucket/data/file.json",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.WriteEvent(evt)
	}
}
