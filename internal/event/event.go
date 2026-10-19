// Package event provides S3 event processing and correlation.
package event

import (
	"bytes"
	"time"

	"github.com/s3slower/s3slower/internal/http"
)

// S3Event represents a captured S3 operation event.
type S3Event struct {
	// Timing
	Timestamp time.Time
	LatencyUs uint64
	LatencyMs float64

	// Process info
	PID        uint32
	TID        uint32
	Comm       string // name of the thread that made the request
	Process    string // name of the process (its main thread)
	ClientType string // well-known client (awscli, boto3, ...) or Process

	// Request details
	Method    string
	Path      string
	Range     string // Range header of a ranged GET, e.g. "bytes=0-65535"
	Operation http.S3Operation
	Bucket    string
	Endpoint  string

	// Sizes: payload (body) bytes in each direction. Header bytes are
	// not counted.
	RequestSize  uint64
	ResponseSize uint64

	// Status
	StatusCode int
	IsError    bool

	// S3 traffic detection
	IsS3Traffic bool
}

// NewS3Event creates a new S3Event from raw BPF event data.
func NewS3Event() *S3Event {
	return &S3Event{
		Timestamp: time.Now(),
	}
}

// ParseFromRaw populates the event from raw HTTP request data.
func (e *S3Event) ParseFromRaw(data []byte) {
	req := http.ParseRequest(data)

	e.Method = req.Method
	e.Path = req.Path
	e.Range = req.Range

	// RequestSize arrives as the size of the write that carried the
	// request head. Replace it with the body size when known. GET, HEAD
	// and DELETE never carry a body, and a complete header block without
	// Content-Length has none either. For a truncated PUT/POST head the
	// header may simply be past the capture limit, so keep the write size
	// as a best effort.
	switch {
	case req.HasContentLength:
		e.RequestSize = uint64(req.ContentLength)
	case req.HeadersComplete || (req.Method != "PUT" && req.Method != "POST"):
		e.RequestSize = 0
	}

	e.Operation = http.ClassifyRequest(req)
	e.Bucket, e.Endpoint = http.ParseBucketEndpoint(req.Host, req.Path)
	e.IsS3Traffic = http.IsLikelyS3Traffic(data)
}

// ParseStatusCode extracts the status code and payload size from response
// data, the bytes the response read returned. ResponseSize must already
// hold that read's byte count. early holds bytes of tiny reads that came
// before it (see the BPF program's EARLY_RESP_SIZE), or nil.
func (e *S3Event) ParseStatusCode(data, early []byte) {
	resp := http.ParseResponse(data)
	headerLen := resp.HeaderLen

	// botocore reads the status line of a response to an Expect:
	// 100-continue upload one byte at a time. When that response is final
	// (403, 503 SlowDown) the response read starts at the header lines and
	// the status is only in early.
	if resp.StatusCode == 0 && bytes.HasPrefix(early, []byte("HTTP/")) {
		head := make([]byte, 0, len(early)+2+len(data))
		head = append(append(append(head, early...), "\r\n"...), data...)
		if r := http.ParseResponse(head); r.StatusCode >= 200 {
			resp = r
			headerLen = 0
			if r.HeaderLen > len(early)+2 {
				headerLen = r.HeaderLen - len(early) - 2
			}
		}
	}

	e.StatusCode = resp.StatusCode
	e.IsError = resp.StatusCode >= 400

	// A 206 is a ranged read even if the Range header was past the
	// capture limit.
	if resp.StatusCode == 206 && e.Operation == http.OpGetObject {
		e.Operation = http.OpGetObjectRange
	}

	switch {
	case e.Method == "HEAD":
		// HEAD carries no body; its Content-Length describes the object.
		e.ResponseSize = 0
	case resp.HasContentLength:
		// The TLS read returns only the first record (e.g. 4096 bytes)
		// of a larger body; Content-Length has the full payload size.
		e.ResponseSize = uint64(resp.ContentLength)
	case headerLen > 0:
		// No Content-Length (204, chunked): count only the body bytes
		// that arrived with the head.
		if uint64(headerLen) < e.ResponseSize {
			e.ResponseSize -= uint64(headerLen)
		} else {
			e.ResponseSize = 0
		}
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
