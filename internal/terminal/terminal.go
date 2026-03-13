// Package terminal provides terminal output formatting.
package terminal

import (
	"encoding/json"
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
	fmt.Fprintf(w.out, "%-12s %-6s %-8s %-14s %-15s %8s %9s %-26s\n",
		"TIME", "METHOD", "OP", "BUCKET", "ENDPOINT", "BYTES", "LAT(ms)", "KEY")
	fmt.Fprintf(w.out, "%s\n", strings.Repeat("-", 105))
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

	// Format operation - use abbreviated Operation if set, otherwise show "-"
	operation := abbreviateOp(string(e.Operation))
	if operation == "" {
		operation = "-"
	}

	fmt.Fprintf(w.out, "%-12s %-6s %-8s %-14s %-15s %8d %9.2f %-26s\n",
		timeStr,
		e.Method,
		operation,
		truncate(e.Bucket, 14),
		truncate(e.Endpoint, 15),
		e.ResponseSize,
		e.LatencyMs,
		truncate(key, 26),
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

// jsonEvent is the JSON representation of an S3 event.
type jsonEvent struct {
	Timestamp    string  `json:"timestamp"`
	PID          uint32  `json:"pid"`
	TID          uint32  `json:"tid"`
	Comm         string  `json:"comm"`
	Method       string  `json:"method"`
	Operation    string  `json:"operation,omitempty"`
	Bucket       string  `json:"bucket,omitempty"`
	Endpoint     string  `json:"endpoint,omitempty"`
	Path         string  `json:"path"`
	LatencyMs    float64 `json:"latency_ms"`
	RequestSize  uint32  `json:"request_size"`
	ResponseSize uint32  `json:"response_size"`
	StatusCode   int     `json:"status_code,omitempty"`
	IsError      bool    `json:"is_error,omitempty"`
	ClientType   string  `json:"client_type,omitempty"`
}

func (w *Writer) writeJSONEvent(e *event.S3Event) {
	je := jsonEvent{
		Timestamp:    e.Timestamp.Format(time.RFC3339Nano),
		PID:          e.PID,
		TID:          e.TID,
		Comm:         e.Comm,
		Method:       e.Method,
		Operation:    string(e.Operation),
		Bucket:       e.Bucket,
		Endpoint:     e.Endpoint,
		Path:         e.Path,
		LatencyMs:    e.LatencyMs,
		RequestSize:  e.RequestSize,
		ResponseSize: e.ResponseSize,
		StatusCode:   e.StatusCode,
		IsError:      e.IsError,
		ClientType:   e.ClientType,
	}

	data, err := json.Marshal(je)
	if err != nil {
		return
	}
	w.out.Write(data)
	w.out.Write([]byte("\n"))
}

// Flush flushes any buffered output.
func (w *Writer) Flush() error {
	if f, ok := w.out.(*os.File); ok {
		return f.Sync()
	}
	return nil
}

// abbreviateOp returns a shortened operation name for display.
func abbreviateOp(op string) string {
	switch op {
	case "GET_OBJECT":
		return "GET"
	case "PUT_OBJECT":
		return "PUT"
	case "DELETE_OBJECT":
		return "DELETE"
	case "HEAD_OBJECT":
		return "HEAD"
	case "LIST_OBJECTS":
		return "LIST"
	case "LIST_PREFIX":
		return "LIST_PFX"
	case "MPU_CREATE":
		return "MPU_INIT"
	case "MPU_PART":
		return "MPU_PART"
	case "MPU_COMPLETE":
		return "MPU_DONE"
	case "MPU_ABORT":
		return "MPU_ABRT"
	case "CREATE_BUCKET":
		return "CRT_BKT"
	case "DELETE_BUCKET":
		return "DEL_BKT"
	case "HEAD_BUCKET":
		return "HEAD_BKT"
	default:
		return op
	}
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

