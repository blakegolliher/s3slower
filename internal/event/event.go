// Package event provides S3 event processing and correlation.
package event

import (
	"time"

	"github.com/s3slower/s3slower/internal/http"
)

// S3Event represents a captured S3 operation event.
type S3Event struct {
	// Timing
	Timestamp   time.Time
	LatencyUs   uint64
	LatencyMs   float64

	// Process info
	PID       uint32
	TID       uint32
	Comm      string
	ClientType string

	// Request details
	Method      string
	Host        string
	Path        string
	Operation   http.S3Operation
	Bucket      string
	Endpoint    string

	// Sizes
	RequestSize  uint32
	ResponseSize uint32

	// Status
	StatusCode int
	IsPartial  bool
	IsError    bool

	// File descriptor for correlation
	FD int32

	// S3 traffic detection
	IsS3Traffic bool

	// Raw data sample (first bytes of request)
	RawData []byte
}

// NewS3Event creates a new S3Event from raw BPF event data.
func NewS3Event() *S3Event {
	return &S3Event{
		Timestamp: time.Now(),
	}
}

// ParseFromRaw populates the event from raw HTTP data.
func (e *S3Event) ParseFromRaw(data []byte) {
	method, host, path, contentLength := http.ParseHTTPRequest(data)

	e.Method = method
	e.Host = host
	e.Path = path

	if contentLength > 0 {
		e.RequestSize = uint32(contentLength)
	}

	// Detect S3 operation
	e.Operation = http.DetectS3Operation(method, path)

	// Extract bucket and endpoint
	e.Bucket, e.Endpoint = http.ParseBucketEndpoint(host, path)

	// Check for S3-specific headers (x-amz-*, AWS4-HMAC-SHA256)
	e.IsS3Traffic = http.IsLikelyS3Traffic(data)

	// Store raw data for debugging
	if len(data) > 64 {
		e.RawData = data[:64]
	} else {
		e.RawData = data
	}
}

// ParseStatusCode extracts the status code and Content-Length from response data.
func (e *S3Event) ParseStatusCode(data []byte) {
	statusCode, contentLength := http.ParseHTTPResponse(data)
	e.StatusCode = statusCode
	e.IsError = statusCode >= 400
	// Use Content-Length for GET responses where the TLS read returns only
	// the first record (e.g. 4096 bytes) but the full object is larger.
	// Do NOT override for HEAD - it returns headers only, no body.
	if contentLength > 0 && e.Method != "HEAD" {
		e.ResponseSize = uint32(contentLength)
	}
}

// SetLatency sets the latency in microseconds and calculates milliseconds.
func (e *S3Event) SetLatency(latencyUs uint64) {
	e.LatencyUs = latencyUs
	e.LatencyMs = float64(latencyUs) / 1000.0
}

// EventProcessor handles incoming BPF events and produces S3Events.
type EventProcessor struct {
	eventChan chan *S3Event
}

// NewEventProcessor creates a new EventProcessor.
func NewEventProcessor(bufferSize int) *EventProcessor {
	return &EventProcessor{
		eventChan: make(chan *S3Event, bufferSize),
	}
}

// Events returns the channel for processed events.
func (p *EventProcessor) Events() <-chan *S3Event {
	return p.eventChan
}

// SendEvent sends an event directly to the channel (non-blocking).
func (p *EventProcessor) SendEvent(event *S3Event) bool {
	select {
	case p.eventChan <- event:
		return true
	default:
		return false
	}
}

// Close closes the event processor.
func (p *EventProcessor) Close() {
	close(p.eventChan)
}
