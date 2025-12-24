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
	ActualBytes  uint32

	// Status
	StatusCode int
	IsPartial  bool
	IsError    bool

	// File descriptor for correlation
	FD int32

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

	// Store raw data for debugging
	if len(data) > 64 {
		e.RawData = data[:64]
	} else {
		e.RawData = data
	}
}

// ParseStatusCode extracts the status code from response data.
func (e *S3Event) ParseStatusCode(data []byte) {
	e.StatusCode = http.ParseHTTPResponse(data)
	e.IsError = e.StatusCode >= 400
}

// SetLatency sets the latency in microseconds and calculates milliseconds.
func (e *S3Event) SetLatency(latencyUs uint64) {
	e.LatencyUs = latencyUs
	e.LatencyMs = float64(latencyUs) / 1000.0
}

// RequestCorrelator tracks in-flight requests for response matching.
type RequestCorrelator struct {
	requests map[requestKey]*pendingRequest
}

type requestKey struct {
	pid uint32
	fd  int32
}

type pendingRequest struct {
	event     *S3Event
	startTime time.Time
}

// NewRequestCorrelator creates a new RequestCorrelator.
func NewRequestCorrelator() *RequestCorrelator {
	return &RequestCorrelator{
		requests: make(map[requestKey]*pendingRequest),
	}
}

// AddRequest adds a pending request.
func (c *RequestCorrelator) AddRequest(pid uint32, fd int32, event *S3Event) {
	key := requestKey{pid: pid, fd: fd}
	c.requests[key] = &pendingRequest{
		event:     event,
		startTime: time.Now(),
	}
}

// CompleteRequest completes a pending request and returns the event.
func (c *RequestCorrelator) CompleteRequest(pid uint32, fd int32) (*S3Event, bool) {
	key := requestKey{pid: pid, fd: fd}
	pending, ok := c.requests[key]
	if !ok {
		return nil, false
	}

	delete(c.requests, key)
	return pending.event, true
}

// GetPending returns the pending request for a PID/FD pair.
func (c *RequestCorrelator) GetPending(pid uint32, fd int32) (*S3Event, bool) {
	key := requestKey{pid: pid, fd: fd}
	pending, ok := c.requests[key]
	if !ok {
		return nil, false
	}
	return pending.event, true
}

// CleanupStale removes requests older than the given duration.
func (c *RequestCorrelator) CleanupStale(maxAge time.Duration) int {
	now := time.Now()
	removed := 0

	for key, pending := range c.requests {
		if now.Sub(pending.startTime) > maxAge {
			delete(c.requests, key)
			removed++
		}
	}

	return removed
}

// Len returns the number of pending requests.
func (c *RequestCorrelator) Len() int {
	return len(c.requests)
}

// EventProcessor handles incoming BPF events and produces S3Events.
type EventProcessor struct {
	correlator  *RequestCorrelator
	minLatency  time.Duration
	eventChan   chan *S3Event
}

// NewEventProcessor creates a new EventProcessor.
func NewEventProcessor(minLatency time.Duration, bufferSize int) *EventProcessor {
	return &EventProcessor{
		correlator: NewRequestCorrelator(),
		minLatency: minLatency,
		eventChan:  make(chan *S3Event, bufferSize),
	}
}

// Events returns the channel for processed events.
func (p *EventProcessor) Events() <-chan *S3Event {
	return p.eventChan
}

// ProcessWrite handles a write/send event.
func (p *EventProcessor) ProcessWrite(pid, tid uint32, fd int32, comm string, data []byte, timestamp time.Time) {
	event := NewS3Event()
	event.PID = pid
	event.TID = tid
	event.FD = fd
	event.Comm = comm
	event.Timestamp = timestamp

	event.ParseFromRaw(data)

	// Only track if it looks like an HTTP request
	if !http.IsS3Method(event.Method) {
		return
	}

	p.correlator.AddRequest(pid, fd, event)
}

// ProcessRead handles a read/recv event.
func (p *EventProcessor) ProcessRead(pid, tid uint32, fd int32, data []byte, respSize uint32, latencyUs uint64) {
	event, ok := p.correlator.CompleteRequest(pid, fd)
	if !ok {
		return
	}

	event.ParseStatusCode(data)
	event.ResponseSize = respSize
	event.SetLatency(latencyUs)

	// Filter by minimum latency
	if p.minLatency > 0 && time.Duration(latencyUs)*time.Microsecond < p.minLatency {
		return
	}

	// Send to channel (non-blocking)
	select {
	case p.eventChan <- event:
	default:
		// Channel full, drop event
	}
}

// Close closes the event processor.
func (p *EventProcessor) Close() {
	close(p.eventChan)
}

// Cleanup performs periodic cleanup of stale requests.
func (p *EventProcessor) Cleanup(maxAge time.Duration) int {
	return p.correlator.CleanupStale(maxAge)
}
