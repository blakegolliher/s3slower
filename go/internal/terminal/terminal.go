// Package terminal provides terminal output formatting.
package terminal

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/s3slower/s3slower/internal/event"
)

// OutputMode represents the output display mode.
type OutputMode int

const (
	OutputModeTable  OutputMode = iota
	OutputModeSimple
	OutputModeJSON
)

// Writer handles terminal output.
type Writer struct {
	out        io.Writer
	mode       OutputMode
	maxURLLen  int
	headerPrinted bool
}

// NewWriter creates a new terminal writer.
func NewWriter(out io.Writer, mode OutputMode, maxURLLen int) *Writer {
	if out == nil {
		out = os.Stdout
	}
	if maxURLLen <= 0 {
		maxURLLen = 50
	}
	return &Writer{
		out:       out,
		mode:      mode,
		maxURLLen: maxURLLen,
	}
}

// WriteHeader writes the table header.
func (w *Writer) WriteHeader() {
	if w.headerPrinted {
		return
	}

	switch w.mode {
	case OutputModeTable:
		w.writeTableHeader()
	case OutputModeSimple:
		// No header for simple mode
	case OutputModeJSON:
		// No header for JSON mode
	}

	w.headerPrinted = true
}

func (w *Writer) writeTableHeader() {
	fmt.Fprintf(w.out, "%-12s %-6s %-16s %-24s %10s %10s %-30s\n",
		"TIME", "METHOD", "BUCKET", "ENDPOINT", "BYTES", "LAT(ms)", "KEY")
	fmt.Fprintf(w.out, "%s\n", strings.Repeat("-", 115))
}

// WriteEvent writes a single event.
func (w *Writer) WriteEvent(e *event.S3Event) {
	switch w.mode {
	case OutputModeTable:
		w.writeTableEvent(e)
	case OutputModeSimple:
		w.writeSimpleEvent(e)
	case OutputModeJSON:
		w.writeJSONEvent(e)
	}
}

func (w *Writer) writeTableEvent(e *event.S3Event) {
	timeStr := e.Timestamp.Format("15:04:05.000")

	// Extract key from path (after bucket prefix)
	key := e.Path
	if len(key) > 0 && key[0] == '/' {
		key = key[1:]
	}
	// Remove bucket prefix if present
	if e.Bucket != "" && strings.HasPrefix(key, e.Bucket+"/") {
		key = key[len(e.Bucket)+1:]
	}

	fmt.Fprintf(w.out, "%-12s %-6s %-16s %-24s %10d %10.2f %-30s\n",
		timeStr,
		e.Method,
		truncate(e.Bucket, 16),
		truncate(e.Endpoint, 24),
		e.ResponseSize,
		e.LatencyMs,
		truncate(key, 30),
	)
}

func (w *Writer) writeSimpleEvent(e *event.S3Event) {
	fmt.Fprintf(w.out, "%s %d %s %s %s %.2fms\n",
		e.Timestamp.Format(time.RFC3339),
		e.PID,
		e.Comm,
		e.Method,
		e.Path,
		e.LatencyMs,
	)
}

func (w *Writer) writeJSONEvent(e *event.S3Event) {
	fmt.Fprintf(w.out, `{"timestamp":"%s","pid":%d,"comm":"%s","method":"%s","path":"%s","latency_ms":%.2f,"status":%d}`+"\n",
		e.Timestamp.Format(time.RFC3339),
		e.PID,
		e.Comm,
		e.Method,
		e.Path,
		e.LatencyMs,
		e.StatusCode,
	)
}

// Flush flushes any buffered output.
func (w *Writer) Flush() error {
	if f, ok := w.out.(*os.File); ok {
		return f.Sync()
	}
	return nil
}

// truncate truncates a string to max length, adding ellipsis if needed.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// FormatBytes formats bytes as a human-readable string.
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatDuration formats a duration as a human-readable string.
func FormatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.0fµs", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	}
	if d < time.Minute {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return fmt.Sprintf("%.1fm", d.Minutes())
}

// ColorCode represents ANSI color codes.
type ColorCode string

const (
	ColorReset   ColorCode = "\033[0m"
	ColorRed     ColorCode = "\033[31m"
	ColorGreen   ColorCode = "\033[32m"
	ColorYellow  ColorCode = "\033[33m"
	ColorBlue    ColorCode = "\033[34m"
	ColorMagenta ColorCode = "\033[35m"
	ColorCyan    ColorCode = "\033[36m"
	ColorWhite   ColorCode = "\033[37m"
)

// Colorize wraps text with ANSI color codes.
func Colorize(text string, color ColorCode) string {
	return string(color) + text + string(ColorReset)
}

// StatusColor returns the appropriate color for an HTTP status code.
func StatusColor(status int) ColorCode {
	switch {
	case status >= 200 && status < 300:
		return ColorGreen
	case status >= 300 && status < 400:
		return ColorYellow
	case status >= 400 && status < 500:
		return ColorRed
	case status >= 500:
		return ColorMagenta
	default:
		return ColorWhite
	}
}

// LatencyColor returns the appropriate color for a latency value.
func LatencyColor(latencyMs float64) ColorCode {
	switch {
	case latencyMs < 100:
		return ColorGreen
	case latencyMs < 500:
		return ColorYellow
	case latencyMs < 1000:
		return ColorRed
	default:
		return ColorMagenta
	}
}
