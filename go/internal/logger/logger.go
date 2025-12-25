// Package logger provides rotating file logging for s3slower.
package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/s3slower/s3slower/internal/event"
)

// RotatingLogger handles log rotation by size.
type RotatingLogger struct {
	mu sync.Mutex

	dir         string
	prefix      string
	maxSize     int64  // max size in bytes
	maxBackups  int    // number of old logs to keep
	currentFile *os.File
	currentSize int64
}

// Config holds logger configuration.
type Config struct {
	Dir        string // Log directory (default: /opt/s3slower)
	Prefix     string // Log file prefix (default: s3slower)
	MaxSizeMB  int    // Max size in MB before rotation (default: 100)
	MaxBackups int    // Number of old logs to keep (default: 5)
}

// DefaultConfig returns default logger configuration.
func DefaultConfig() Config {
	return Config{
		Dir:        "/opt/s3slower",
		Prefix:     "s3slower",
		MaxSizeMB:  100,
		MaxBackups: 5,
	}
}

// NewRotatingLogger creates a new rotating logger.
func NewRotatingLogger(cfg Config) (*RotatingLogger, error) {
	if cfg.Dir == "" {
		cfg.Dir = "/opt/s3slower"
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "s3slower"
	}
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 100
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 5
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	l := &RotatingLogger{
		dir:        cfg.Dir,
		prefix:     cfg.Prefix,
		maxSize:    int64(cfg.MaxSizeMB) * 1024 * 1024,
		maxBackups: cfg.MaxBackups,
	}

	// Open initial log file
	if err := l.openNewFile(); err != nil {
		return nil, err
	}

	return l, nil
}

// openNewFile opens a new log file with timestamp.
func (l *RotatingLogger) openNewFile() error {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("%s_%s.log", l.prefix, timestamp)
	path := filepath.Join(l.dir, filename)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Get current size
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to stat log file: %w", err)
	}

	l.currentFile = f
	l.currentSize = info.Size()

	return nil
}

// rotate rotates the log file if needed.
func (l *RotatingLogger) rotate() error {
	if l.currentSize < l.maxSize {
		return nil
	}

	// Close current file
	if l.currentFile != nil {
		l.currentFile.Close()
	}

	// Clean up old backups
	l.cleanupOldLogs()

	// Open new file
	return l.openNewFile()
}

// cleanupOldLogs removes old log files beyond maxBackups.
func (l *RotatingLogger) cleanupOldLogs() {
	pattern := filepath.Join(l.dir, l.prefix+"_*.log")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	if len(matches) <= l.maxBackups {
		return
	}

	// Sort by modification time (oldest first)
	sort.Slice(matches, func(i, j int) bool {
		infoI, _ := os.Stat(matches[i])
		infoJ, _ := os.Stat(matches[j])
		if infoI == nil || infoJ == nil {
			return false
		}
		return infoI.ModTime().Before(infoJ.ModTime())
	})

	// Remove oldest files
	toRemove := len(matches) - l.maxBackups
	for i := 0; i < toRemove; i++ {
		os.Remove(matches[i])
	}
}

// WriteEvent writes an event to the log file.
func (l *RotatingLogger) WriteEvent(e *event.S3Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check for rotation
	if err := l.rotate(); err != nil {
		return err
	}

	// Format log line with full details
	line := l.formatEvent(e)

	n, err := l.currentFile.WriteString(line)
	if err != nil {
		return err
	}

	l.currentSize += int64(n)
	return nil
}

// formatEvent formats an event for the log file (with full key).
func (l *RotatingLogger) formatEvent(e *event.S3Event) string {
	return fmt.Sprintf("%s | %-6s | %-20s | %-30s | %10d | %10.2f | %s\n",
		e.Timestamp.Format("2006-01-02 15:04:05.000"),
		e.Method,
		truncateLog(e.Bucket, 20),
		truncateLog(e.Endpoint, 30),
		e.ResponseSize,
		e.LatencyMs,
		e.Path, // Full key/path in log
	)
}

// WriteHeader writes a header line to the log.
func (l *RotatingLogger) WriteHeader() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	header := fmt.Sprintf("%s | %-6s | %-20s | %-30s | %10s | %10s | %s\n",
		"TIMESTAMP              ",
		"METHOD",
		"BUCKET",
		"ENDPOINT",
		"BYTES",
		"LATENCY_MS",
		"KEY",
	)
	separator := fmt.Sprintf("%s\n", repeatChar('-', 120))

	_, err := l.currentFile.WriteString(header + separator)
	return err
}

// Close closes the logger.
func (l *RotatingLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.currentFile != nil {
		err := l.currentFile.Close()
		l.currentFile = nil
		return err
	}
	return nil
}

// Sync flushes the log file.
func (l *RotatingLogger) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.currentFile != nil {
		return l.currentFile.Sync()
	}
	return nil
}

// truncateLog truncates a string for log output.
func truncateLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// repeatChar repeats a character n times.
func repeatChar(c rune, n int) string {
	result := make([]rune, n)
	for i := range result {
		result[i] = c
	}
	return string(result)
}
