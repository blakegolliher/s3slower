// Package utils provides utility function tests.
package utils

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetHostname tests the GetHostname function.
func TestGetHostname(t *testing.T) {
	hostname := GetHostname()
	assert.NotEmpty(t, hostname)
	assert.NotEqual(t, "unknown", hostname)
}

// TestFileExists tests the FileExists function.
func TestFileExists(t *testing.T) {
	t.Run("existing_file", func(t *testing.T) {
		// Create temp file
		tmpFile, err := os.CreateTemp("", "test")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		assert.True(t, FileExists(tmpFile.Name()))
	})

	t.Run("non_existing_file", func(t *testing.T) {
		assert.False(t, FileExists("/nonexistent/path/file.txt"))
	})
}

// TestIsDir tests the IsDir function.
func TestIsDir(t *testing.T) {
	t.Run("existing_dir", func(t *testing.T) {
		tmpDir := t.TempDir()
		assert.True(t, IsDir(tmpDir))
	})

	t.Run("file_not_dir", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		assert.False(t, IsDir(tmpFile.Name()))
	})

	t.Run("non_existing", func(t *testing.T) {
		assert.False(t, IsDir("/nonexistent/path"))
	})
}

// TestExpandPath tests the ExpandPath function.
func TestExpandPath(t *testing.T) {
	t.Run("expands_home", func(t *testing.T) {
		home, err := os.UserHomeDir()
		require.NoError(t, err)

		result := ExpandPath("~/test/path")
		assert.Equal(t, filepath.Join(home, "test/path"), result)
	})

	t.Run("expands_env_var", func(t *testing.T) {
		os.Setenv("TEST_VAR", "testvalue")
		defer os.Unsetenv("TEST_VAR")

		result := ExpandPath("/path/$TEST_VAR/file")
		assert.Contains(t, result, "testvalue")
	})

	t.Run("no_expansion_needed", func(t *testing.T) {
		result := ExpandPath("/absolute/path")
		assert.Equal(t, "/absolute/path", result)
	})
}

// TestParseDuration tests the ParseDuration function.
func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		hasError bool
	}{
		{input: "", expected: 0, hasError: false},
		{input: "0", expected: 0, hasError: false},
		{input: "100ms", expected: 100 * time.Millisecond, hasError: false},
		{input: "1s", expected: time.Second, hasError: false},
		{input: "5m", expected: 5 * time.Minute, hasError: false},
		{input: "1h", expected: time.Hour, hasError: false},
		{input: "  100ms  ", expected: 100 * time.Millisecond, hasError: false},
		{input: "invalid", expected: 0, hasError: true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseDuration(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestMinInt tests the MinInt function.
func TestMinInt(t *testing.T) {
	tests := []struct {
		a, b     int
		expected int
	}{
		{1, 2, 1},
		{5, 3, 3},
		{0, 0, 0},
		{-1, 1, -1},
		{10, 10, 10},
	}

	for _, tt := range tests {
		result := MinInt(tt.a, tt.b)
		assert.Equal(t, tt.expected, result)
	}
}

// TestMaxInt tests the MaxInt function.
func TestMaxInt(t *testing.T) {
	tests := []struct {
		a, b     int
		expected int
	}{
		{1, 2, 2},
		{5, 3, 5},
		{0, 0, 0},
		{-1, 1, 1},
		{10, 10, 10},
	}

	for _, tt := range tests {
		result := MaxInt(tt.a, tt.b)
		assert.Equal(t, tt.expected, result)
	}
}

// TestClampInt tests the ClampInt function.
func TestClampInt(t *testing.T) {
	tests := []struct {
		val, min, max int
		expected      int
	}{
		{5, 0, 10, 5},
		{-5, 0, 10, 0},
		{15, 0, 10, 10},
		{0, 0, 10, 0},
		{10, 0, 10, 10},
	}

	for _, tt := range tests {
		result := ClampInt(tt.val, tt.min, tt.max)
		assert.Equal(t, tt.expected, result)
	}
}

// TestStringSliceContains tests the StringSliceContains function.
func TestStringSliceContains(t *testing.T) {
	slice := []string{"apple", "banana", "cherry"}

	assert.True(t, StringSliceContains(slice, "banana"))
	assert.False(t, StringSliceContains(slice, "date"))
	assert.False(t, StringSliceContains(nil, "apple"))
	assert.False(t, StringSliceContains([]string{}, "apple"))
}

// TestUniqueStrings tests the UniqueStrings function.
func TestUniqueStrings(t *testing.T) {
	tests := []struct {
		input    []string
		expected []string
	}{
		{
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			input:    []string{},
			expected: []string{},
		},
		{
			input:    []string{"a", "a", "a"},
			expected: []string{"a"},
		},
	}

	for _, tt := range tests {
		result := UniqueStrings(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}

// TestSafeString tests the SafeString function.
func TestSafeString(t *testing.T) {
	assert.Equal(t, "value", SafeString("value", "default"))
	assert.Equal(t, "default", SafeString("", "default"))
}

// TestTruncateString tests the TruncateString function.
func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{input: "short", maxLen: 10, expected: "short"},
		{input: "exactly10!", maxLen: 10, expected: "exactly10!"},
		{input: "this is a long string", maxLen: 10, expected: "this is..."},
		{input: "abc", maxLen: 2, expected: "ab"},
		{input: "", maxLen: 10, expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := TruncateString(tt.input, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsRoot tests the IsRoot function.
func TestIsRoot(t *testing.T) {
	// Just verify it doesn't panic
	result := IsRoot()
	// Result depends on test environment
	_ = result
}

// TestEnsureDir tests the EnsureDir function.
func TestEnsureDir(t *testing.T) {
	tmpDir := t.TempDir()
	newDir := filepath.Join(tmpDir, "new", "nested", "dir")

	err := EnsureDir(newDir)
	require.NoError(t, err)
	assert.True(t, IsDir(newDir))

	// Should be idempotent
	err = EnsureDir(newDir)
	require.NoError(t, err)
}

// TestWriteFileSafe tests the WriteFileSafe function.
func TestWriteFileSafe(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	data := []byte("test content")
	err := WriteFileSafe(filePath, data, 0644)
	require.NoError(t, err)

	// Verify file was written
	content, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, data, content)

	// Verify temp file was cleaned up
	assert.False(t, FileExists(filePath+".tmp"))
}

// TestFindLibrary tests the FindLibrary function.
func TestFindLibrary(t *testing.T) {
	// This test depends on system libraries being present
	// We just verify it doesn't panic

	t.Run("find_libc", func(t *testing.T) {
		result := FindLibrary("libc.so")
		// Result may be empty if not found
		_ = result
	})

	t.Run("nonexistent_library", func(t *testing.T) {
		result := FindLibrary("libnonexistent12345.so")
		assert.Empty(t, result)
	})
}

// TestFindOpenSSL tests the FindOpenSSL function.
func TestFindOpenSSL(t *testing.T) {
	// Just verify it doesn't panic
	result := FindOpenSSL()
	_ = result
}

// TestFindGnuTLS tests the FindGnuTLS function.
func TestFindGnuTLS(t *testing.T) {
	// Just verify it doesn't panic
	result := FindGnuTLS()
	_ = result
}

// TestFindNSS tests the FindNSS function.
func TestFindNSS(t *testing.T) {
	// Just verify it doesn't panic
	result := FindNSS()
	_ = result
}
