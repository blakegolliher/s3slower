// Package utils provides utility functions for s3slower.
package utils

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GetHostname returns the system hostname.
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// FileExists checks if a file exists.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsDir checks if a path is a directory.
func IsDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// ExpandPath expands ~ and environment variables in a path.
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	return os.ExpandEnv(path)
}

// FindLibrary searches for a library in common paths.
func FindLibrary(name string) string {
	paths := []string{
		"/lib64",
		"/usr/lib64",
		"/lib/x86_64-linux-gnu",
		"/usr/lib/x86_64-linux-gnu",
		"/lib",
		"/usr/lib",
		"/usr/local/lib",
		"/usr/local/lib64",
	}

	for _, p := range paths {
		full := filepath.Join(p, name)
		if FileExists(full) {
			return full
		}

		// Try with .so suffix variations
		matches, _ := filepath.Glob(filepath.Join(p, name+"*"))
		for _, m := range matches {
			return m
		}
	}

	return ""
}

// FindOpenSSL searches for libssl.so.
func FindOpenSSL() string {
	names := []string{
		"libssl.so.3",
		"libssl.so.1.1",
		"libssl.so.1.0.0",
		"libssl.so",
	}

	for _, name := range names {
		if path := FindLibrary(name); path != "" {
			return path
		}
	}

	return ""
}

// FindGnuTLS searches for libgnutls.so.
func FindGnuTLS() string {
	names := []string{
		"libgnutls.so.30",
		"libgnutls.so.28",
		"libgnutls.so",
	}

	for _, name := range names {
		if path := FindLibrary(name); path != "" {
			return path
		}
	}

	return ""
}

// FindNSS searches for libnspr4.so.
func FindNSS() string {
	return FindLibrary("libnspr4.so")
}

// ParseDuration parses a duration string with support for common units.
func ParseDuration(s string) (time.Duration, error) {
	// Handle common shorthand
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}

	return time.ParseDuration(s)
}

// MinInt returns the minimum of two integers.
func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MaxInt returns the maximum of two integers.
func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ClampInt clamps an integer to a range.
func ClampInt(val, min, max int) int {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

// StringSliceContains checks if a string slice contains a value.
func StringSliceContains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// UniqueStrings returns a slice with duplicate strings removed.
func UniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))

	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// SafeString returns a default value if the string is empty.
func SafeString(s, defaultVal string) string {
	if s == "" {
		return defaultVal
	}
	return s
}

// TruncateString truncates a string to a maximum length.
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// IsRoot checks if the current process is running as root.
func IsRoot() bool {
	return os.Geteuid() == 0
}

// EnsureDir ensures a directory exists.
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// WriteFileSafe writes to a file atomically by writing to a temp file first.
func WriteFileSafe(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}

	tmpFile := path + ".tmp"
	if err := os.WriteFile(tmpFile, data, perm); err != nil {
		return err
	}

	return os.Rename(tmpFile, path)
}
