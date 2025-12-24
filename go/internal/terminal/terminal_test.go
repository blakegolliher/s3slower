// Package terminal provides terminal output tests.
package terminal

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/s3slower/s3slower/internal/event"
	"github.com/s3slower/s3slower/internal/http"
)

// TestNewWriter tests the NewWriter function.
func TestNewWriter(t *testing.T) {
	t.Run("creates_with_defaults", func(t *testing.T) {
		w := NewWriter(nil, OutputModeTable, 0)

		assert.NotNil(t, w)
		assert.Equal(t, 50, w.maxURLLen)
	})

	t.Run("respects_custom_max_url_len", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeTable, 100)

		assert.Equal(t, 100, w.maxURLLen)
	})
}

// TestWriteHeader tests the WriteHeader method.
func TestWriteHeader(t *testing.T) {
	t.Run("table_mode_writes_header", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeTable, 50)

		w.WriteHeader()

		output := buf.String()
		assert.Contains(t, output, "TIME")
		assert.Contains(t, output, "PID")
		assert.Contains(t, output, "COMM")
		assert.Contains(t, output, "OPERATION")
		assert.Contains(t, output, "LAT(ms)")
	})

	t.Run("header_only_written_once", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeTable, 50)

		w.WriteHeader()
		firstLen := buf.Len()

		w.WriteHeader()
		secondLen := buf.Len()

		assert.Equal(t, firstLen, secondLen)
	})

	t.Run("simple_mode_no_header", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeSimple, 50)

		w.WriteHeader()

		assert.Empty(t, buf.String())
	})
}

// TestWriteEvent tests the WriteEvent method.
func TestWriteEvent(t *testing.T) {
	makeTestEvent := func() *event.S3Event {
		return &event.S3Event{
			Timestamp:    time.Date(2024, 1, 15, 10, 30, 45, 123000000, time.UTC),
			PID:          12345,
			Comm:         "aws",
			ClientType:   "aws-cli",
			Method:       "GET",
			Operation:    http.OpGetObject,
			Bucket:       "mybucket",
			LatencyMs:    123.45,
			StatusCode:   200,
			ResponseSize: 1024,
		}
	}

	t.Run("table_mode", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeTable, 50)

		w.WriteEvent(makeTestEvent())

		output := buf.String()
		assert.Contains(t, output, "10:30:45")
		assert.Contains(t, output, "12345")
		assert.Contains(t, output, "aws")
		assert.Contains(t, output, "GET_OBJECT")
		assert.Contains(t, output, "200")
		assert.Contains(t, output, "123.45")
		assert.Contains(t, output, "mybucket")
	})

	t.Run("simple_mode", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeSimple, 50)

		e := makeTestEvent()
		e.Path = "/mybucket/mykey"
		w.WriteEvent(e)

		output := buf.String()
		assert.Contains(t, output, "12345")
		assert.Contains(t, output, "aws")
		assert.Contains(t, output, "GET")
		assert.Contains(t, output, "123.45ms")
	})

	t.Run("json_mode", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf, OutputModeJSON, 50)

		e := makeTestEvent()
		e.Path = "/mybucket/mykey"
		w.WriteEvent(e)

		output := buf.String()
		assert.Contains(t, output, `"pid":12345`)
		assert.Contains(t, output, `"comm":"aws"`)
		assert.Contains(t, output, `"method":"GET"`)
		assert.Contains(t, output, `"latency_ms":123.45`)
		assert.Contains(t, output, `"status":200`)
	})
}

// TestTruncate tests the truncate function.
func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{input: "short", maxLen: 10, expected: "short"},
		{input: "exactly10!", maxLen: 10, expected: "exactly10!"},
		{input: "this is a long string", maxLen: 10, expected: "this is..."},
		{input: "abc", maxLen: 2, expected: "ab"},
		{input: "abc", maxLen: 3, expected: "abc"},
		{input: "", maxLen: 10, expected: ""},
		{input: "test", maxLen: 0, expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := truncate(tt.input, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFormatBytes tests the FormatBytes function.
func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{bytes: 0, expected: "0 B"},
		{bytes: 100, expected: "100 B"},
		{bytes: 1023, expected: "1023 B"},
		{bytes: 1024, expected: "1.0 KB"},
		{bytes: 1536, expected: "1.5 KB"},
		{bytes: 1048576, expected: "1.0 MB"},
		{bytes: 1073741824, expected: "1.0 GB"},
		{bytes: 1099511627776, expected: "1.0 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := FormatBytes(tt.bytes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFormatDuration tests the FormatDuration function.
func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{duration: 500 * time.Microsecond, expected: "500µs"},
		{duration: 1 * time.Millisecond, expected: "1.0ms"},
		{duration: 100 * time.Millisecond, expected: "100.0ms"},
		{duration: 1 * time.Second, expected: "1.00s"},
		{duration: 30 * time.Second, expected: "30.00s"},
		{duration: 1 * time.Minute, expected: "1.0m"},
		{duration: 5 * time.Minute, expected: "5.0m"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := FormatDuration(tt.duration)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestColorize tests the Colorize function.
func TestColorize(t *testing.T) {
	result := Colorize("test", ColorRed)
	assert.Contains(t, result, "\033[31m")
	assert.Contains(t, result, "test")
	assert.Contains(t, result, "\033[0m")
}

// TestStatusColor tests the StatusColor function.
func TestStatusColor(t *testing.T) {
	tests := []struct {
		status   int
		expected ColorCode
	}{
		{status: 200, expected: ColorGreen},
		{status: 201, expected: ColorGreen},
		{status: 204, expected: ColorGreen},
		{status: 301, expected: ColorYellow},
		{status: 304, expected: ColorYellow},
		{status: 400, expected: ColorRed},
		{status: 403, expected: ColorRed},
		{status: 404, expected: ColorRed},
		{status: 500, expected: ColorMagenta},
		{status: 503, expected: ColorMagenta},
		{status: 0, expected: ColorWhite},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := StatusColor(tt.status)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestLatencyColor tests the LatencyColor function.
func TestLatencyColor(t *testing.T) {
	tests := []struct {
		latencyMs float64
		expected  ColorCode
	}{
		{latencyMs: 50, expected: ColorGreen},
		{latencyMs: 99, expected: ColorGreen},
		{latencyMs: 100, expected: ColorYellow},
		{latencyMs: 250, expected: ColorYellow},
		{latencyMs: 500, expected: ColorRed},
		{latencyMs: 750, expected: ColorRed},
		{latencyMs: 1000, expected: ColorMagenta},
		{latencyMs: 5000, expected: ColorMagenta},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := LatencyColor(tt.latencyMs)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestOutputModes tests the output mode constants.
func TestOutputModes(t *testing.T) {
	assert.Equal(t, OutputMode(0), OutputModeTable)
	assert.Equal(t, OutputMode(1), OutputModeSimple)
	assert.Equal(t, OutputMode(2), OutputModeJSON)
}
