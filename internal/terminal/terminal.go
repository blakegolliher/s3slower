// Package terminal provides terminal output formatting.
package terminal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/s3slower/s3slower/internal/event"
)

// OutputMode represents the output display mode.
type OutputMode int

const (
	OutputModeTable OutputMode = iota
	OutputModeSimple
	OutputModeJSON
	OutputModeTop // refreshing per-operation summary
)

// Writer handles terminal output.
type Writer struct {
	out           io.Writer
	mode          OutputMode
	maxURLLen     int
	headerPrinted bool

	top     *topView
	topStop chan struct{}
}

// NewWriter creates a new terminal writer.
func NewWriter(out io.Writer, mode OutputMode, maxURLLen int) *Writer {
	if out == nil {
		out = os.Stdout
	}
	if maxURLLen <= 0 {
		maxURLLen = 50
	}
	w := &Writer{
		out:       out,
		mode:      mode,
		maxURLLen: maxURLLen,
	}
	if mode == OutputModeTop {
		w.top = newTopView()
	}
	return w
}

// Start begins periodic redraws for the top view; other modes need no
// background work.
func (w *Writer) Start() {
	if w.top != nil && w.topStop == nil {
		w.topStop = make(chan struct{})
		go w.top.run(w.out, w.topStop)
	}
}

// Stop ends periodic redraws started by Start.
func (w *Writer) Stop() {
	if w.topStop != nil {
		close(w.topStop)
		w.topStop = nil
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
	case OutputModeJSON, OutputModeTop:
		// No header
	}

	w.headerPrinted = true
}

// Table column widths.
const (
	procWidth     = 10
	bucketWidth   = 20
	endpointWidth = 22
)

func (w *Writer) writeTableHeader() {
	fmt.Fprintf(w.out, "%-12s %-*s %-8s %4s %10s %9s %-*s %-*s %s\n",
		"TIME", procWidth, "PROC", "OP", "STAT", "BYTES", "LAT(ms)",
		bucketWidth, "BUCKET", endpointWidth, "ENDPOINT", "KEY")
	fmt.Fprintf(w.out, "%s\n", strings.Repeat("-", 130))
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
	case OutputModeTop:
		w.top.add(e)
	}
}

func (w *Writer) writeTableEvent(e *event.S3Event) {
	timeStr := e.Timestamp.Format("15:04:05.000")

	key := truncateLeft(displayKey(e), w.maxURLLen)
	if e.Range != "" {
		key += " [" + e.Range + "]"
	}

	operation := abbreviateOp(string(e.Operation))
	if operation == "" {
		operation = "-"
	}

	status := "-"
	if e.StatusCode > 0 {
		status = fmt.Sprintf("%d", e.StatusCode)
	}

	proc := e.ClientType
	if proc == "" {
		proc = e.Comm
	}

	// For uploads (PUT/POST with a body), show the request size (object
	// being uploaded). Otherwise show the response payload size.
	displayBytes := e.ResponseSize
	if (e.Method == "PUT" || e.Method == "POST") && e.RequestSize > 0 {
		displayBytes = e.RequestSize
	}

	fmt.Fprintf(w.out, "%-12s %-*s %-8s %4s %10d %9.2f %-*s %-*s %s\n",
		timeStr,
		procWidth, truncateRight(proc, procWidth),
		operation,
		status,
		displayBytes,
		e.LatencyMs,
		bucketWidth, truncateRight(e.Bucket, bucketWidth),
		endpointWidth, truncateRight(e.Endpoint, endpointWidth),
		key,
	)
}

// displayKey returns the object key for the KEY column: the path after the
// bucket, without the query string (the OP column already says what it
// encoded). Listings show the listed prefix followed by "*".
func displayKey(e *event.S3Event) string {
	path, query, _ := strings.Cut(e.Path, "?")
	key := strings.TrimPrefix(path, "/")
	if e.Bucket != "" && (key == e.Bucket || strings.HasPrefix(key, e.Bucket+"/")) {
		key = strings.TrimPrefix(key[len(e.Bucket):], "/")
	}
	if e.Operation == "LIST_PREFIX" || e.Operation == "LIST_OBJECTS" {
		if v, err := url.ParseQuery(query); err == nil {
			return v.Get("prefix") + "*"
		}
	}
	return key
}

// truncateRight shortens s to at most n characters, marking the cut with
// a trailing "~".
func truncateRight(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

// truncateLeft shortens s to at most n characters, keeping the end (the
// most specific part of an object key) and marking the cut with "...".
func truncateLeft(s string, n int) string {
	if n <= 3 || len(s) <= n {
		return s
	}
	return "..." + s[len(s)-(n-3):]
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
	Process      string  `json:"process,omitempty"`
	Method       string  `json:"method"`
	Operation    string  `json:"operation,omitempty"`
	Bucket       string  `json:"bucket,omitempty"`
	Endpoint     string  `json:"endpoint,omitempty"`
	Path         string  `json:"path"`
	Range        string  `json:"range,omitempty"`
	LatencyMs    float64 `json:"latency_ms"`
	RequestSize  uint64  `json:"request_size"`
	ResponseSize uint64  `json:"response_size"`
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
		Process:      e.Process,
		Method:       e.Method,
		Operation:    string(e.Operation),
		Bucket:       e.Bucket,
		Endpoint:     e.Endpoint,
		Path:         e.Path,
		Range:        e.Range,
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

// abbreviateOp returns a shortened (at most 8 characters) operation name
// for display.
func abbreviateOp(op string) string {
	switch op {
	case "GET_OBJECT":
		return "GET"
	case "GET_OBJECT_RANGE":
		return "GET_RNG"
	case "PUT_OBJECT":
		return "PUT"
	case "COPY_OBJECT":
		return "COPY"
	case "DELETE_OBJECT":
		return "DELETE"
	case "DELETE_OBJECTS":
		return "DEL_BULK"
	case "HEAD_OBJECT":
		return "HEAD"
	case "LIST_OBJECTS":
		return "LIST"
	case "LIST_PREFIX":
		return "LIST_PFX"
	case "LIST_BUCKETS":
		return "LIST_BKT"
	case "MPU_CREATE":
		return "MPU_INIT"
	case "MPU_PART":
		return "MPU_PART"
	case "MPU_COMPLETE":
		return "MPU_DONE"
	case "MPU_ABORT":
		return "MPU_ABRT"
	case "MPU_LIST":
		return "MPU_LIST"
	case "MPU_LIST_PARTS":
		return "MPU_LSTP"
	case "CREATE_BUCKET":
		return "CRT_BKT"
	case "DELETE_BUCKET":
		return "DEL_BKT"
	case "HEAD_BUCKET":
		return "HEAD_BKT"
	case "BUCKET_CONFIG":
		return "BKT_CFG"
	default:
		return op
	}
}
