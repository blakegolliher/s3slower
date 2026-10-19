// Package event provides S3 event processing tests.
package event

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/s3slower/s3slower/internal/http"
)

// TestS3Event tests the S3Event struct.
func TestS3Event(t *testing.T) {
	t.Run("creates_new_event", func(t *testing.T) {
		event := NewS3Event()

		assert.NotNil(t, event)
		assert.False(t, event.Timestamp.IsZero())
	})
}

// TestParseFromRaw tests the ParseFromRaw method.
func TestParseFromRaw(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		wantMethod    string
		wantPath      string
		wantOperation http.S3Operation
		wantBucket    string
	}{
		{
			name:          "get_object_request",
			data:          []byte("GET /mybucket/mykey.txt HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "GET",
			wantPath:      "/mybucket/mykey.txt",
			wantOperation: http.OpGetObject,
			wantBucket:    "mybucket",
		},
		{
			name:          "put_object_request",
			data:          []byte("PUT /mybucket/mykey.txt HTTP/1.1\r\nHost: s3.amazonaws.com\r\nContent-Length: 1024\r\n\r\n"),
			wantMethod:    "PUT",
			wantPath:      "/mybucket/mykey.txt",
			wantOperation: http.OpPutObject,
			wantBucket:    "mybucket",
		},
		{
			name:          "list_objects_request",
			data:          []byte("GET /mybucket?list-type=2&prefix=foo/ HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "GET",
			wantPath:      "/mybucket?list-type=2&prefix=foo/",
			wantOperation: http.OpListPrefix,
			wantBucket:    "mybucket",
		},
		{
			name:          "multipart_create_request",
			data:          []byte("POST /mybucket/mykey?uploads HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "POST",
			wantPath:      "/mybucket/mykey?uploads",
			wantOperation: http.OpMPUCreate,
			wantBucket:    "mybucket",
		},
		{
			name:          "delete_object_request",
			data:          []byte("DELETE /mybucket/mykey.txt HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "DELETE",
			wantPath:      "/mybucket/mykey.txt",
			wantOperation: http.OpDeleteObject,
			wantBucket:    "mybucket",
		},
		{
			name:          "empty_data",
			data:          []byte{},
			wantMethod:    "",
			wantPath:      "",
			wantOperation: http.OpUnknown,
			wantBucket:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := NewS3Event()
			event.ParseFromRaw(tt.data)

			assert.Equal(t, tt.wantMethod, event.Method)
			assert.Equal(t, tt.wantPath, event.Path)
			assert.Equal(t, tt.wantOperation, event.Operation)
			assert.Equal(t, tt.wantBucket, event.Bucket)
		})
	}
}

// TestParseStatusCode tests the ParseStatusCode method.
func TestParseStatusCode(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantStatus  int
		wantIsError bool
	}{
		{
			name:        "200_ok",
			data:        []byte("HTTP/1.1 200 OK\r\n\r\n"),
			wantStatus:  200,
			wantIsError: false,
		},
		{
			name:        "201_created",
			data:        []byte("HTTP/1.1 201 Created\r\n\r\n"),
			wantStatus:  201,
			wantIsError: false,
		},
		{
			name:        "204_no_content",
			data:        []byte("HTTP/1.1 204 No Content\r\n\r\n"),
			wantStatus:  204,
			wantIsError: false,
		},
		{
			name:        "400_bad_request",
			data:        []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
			wantStatus:  400,
			wantIsError: true,
		},
		{
			name:        "403_forbidden",
			data:        []byte("HTTP/1.1 403 Forbidden\r\n\r\n"),
			wantStatus:  403,
			wantIsError: true,
		},
		{
			name:        "404_not_found",
			data:        []byte("HTTP/1.1 404 Not Found\r\n\r\n"),
			wantStatus:  404,
			wantIsError: true,
		},
		{
			name:        "500_internal_error",
			data:        []byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"),
			wantStatus:  500,
			wantIsError: true,
		},
		{
			name:        "empty_data",
			data:        []byte{},
			wantStatus:  0,
			wantIsError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := NewS3Event()
			event.ParseStatusCode(tt.data, nil)

			assert.Equal(t, tt.wantStatus, event.StatusCode)
			assert.Equal(t, tt.wantIsError, event.IsError)
		})
	}
}

// TestSetLatency tests the SetLatency method.
func TestSetLatency(t *testing.T) {
	tests := []struct {
		name      string
		latencyUs uint64
		wantMs    float64
	}{
		{name: "zero", latencyUs: 0, wantMs: 0},
		{name: "1ms", latencyUs: 1000, wantMs: 1.0},
		{name: "100ms", latencyUs: 100000, wantMs: 100.0},
		{name: "1.5ms", latencyUs: 1500, wantMs: 1.5},
		{name: "500us", latencyUs: 500, wantMs: 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := NewS3Event()
			event.SetLatency(tt.latencyUs)

			assert.Equal(t, tt.latencyUs, event.LatencyUs)
			assert.Equal(t, tt.wantMs, event.LatencyMs)
		})
	}
}

// TestEventProcessor tests the EventProcessor struct.
func TestEventProcessor(t *testing.T) {
	t.Run("creates_processor", func(t *testing.T) {
		p := NewEventProcessor(100)

		assert.NotNil(t, p)
		assert.NotNil(t, p.Events())
	})

	t.Run("send_event", func(t *testing.T) {
		p := NewEventProcessor(100)

		evt := NewS3Event()
		evt.Method = "GET"
		evt.LatencyMs = 50.0

		ok := p.SendEvent(evt)
		assert.True(t, ok)

		select {
		case received := <-p.Events():
			assert.Equal(t, "GET", received.Method)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("expected event not received")
		}
	})

	t.Run("send_event_full_channel", func(t *testing.T) {
		p := NewEventProcessor(1) // buffer size 1

		evt1 := NewS3Event()
		evt1.Method = "GET"
		ok := p.SendEvent(evt1)
		assert.True(t, ok)

		// Channel is now full
		evt2 := NewS3Event()
		evt2.Method = "PUT"
		ok = p.SendEvent(evt2)
		assert.False(t, ok) // Should drop
	})

	t.Run("close", func(t *testing.T) {
		p := NewEventProcessor(100)
		p.Close()

		// Channel should be closed
		_, ok := <-p.Events()
		assert.False(t, ok)
	})
}

// BenchmarkParseFromRaw benchmarks event parsing.
func BenchmarkParseFromRaw(b *testing.B) {
	data := []byte("GET /mybucket/mykey.txt HTTP/1.1\r\nHost: s3.amazonaws.com\r\nContent-Length: 1024\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := NewS3Event()
		event.ParseFromRaw(data)
	}
}

// TestPayloadSizesAndRange tests body-byte accounting and ranged-read
// classification across request and response parsing.
func TestPayloadSizesAndRange(t *testing.T) {
	const headWrite = 760 // size of the write that carried the request head

	newEvent := func(req string, respRead uint64, resp string) *S3Event {
		e := NewS3Event()
		e.RequestSize = headWrite
		e.ResponseSize = respRead
		e.ParseFromRaw([]byte(req))
		e.ParseStatusCode([]byte(resp), nil)
		return e
	}

	t.Run("get_without_body_reports_zero_request_bytes", func(t *testing.T) {
		e := newEvent("GET /b/k HTTP/1.1\r\nHost: h\r\n\r\n", 4096,
			"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n")
		assert.Equal(t, uint64(0), e.RequestSize)
		assert.Equal(t, uint64(1048576), e.ResponseSize)
		assert.Equal(t, http.OpGetObject, e.Operation)
	})

	t.Run("put_uses_content_length", func(t *testing.T) {
		e := newEvent("PUT /b/k HTTP/1.1\r\nContent-Length: 300000\r\n\r\n", 277,
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		assert.Equal(t, uint64(300000), e.RequestSize)
		assert.Equal(t, uint64(0), e.ResponseSize)
	})

	t.Run("truncated_head_keeps_write_size", func(t *testing.T) {
		e := newEvent("PUT /b/k HTTP/1.1\r\nHost: h\r\nAuthorization: AWS4", 0, "")
		assert.Equal(t, uint64(headWrite), e.RequestSize)
	})

	t.Run("range_header_marks_ranged_get", func(t *testing.T) {
		e := newEvent("GET /b/k HTTP/1.1\r\nRange: bytes=0-65535\r\n\r\n", 4096,
			"HTTP/1.1 206 Partial Content\r\nContent-Length: 65536\r\n\r\n")
		assert.Equal(t, http.OpGetObjectRange, e.Operation)
		assert.Equal(t, "bytes=0-65535", e.Range)
		assert.Equal(t, uint64(65536), e.ResponseSize)
	})

	t.Run("206_marks_ranged_get_without_header", func(t *testing.T) {
		e := newEvent("GET /b/k HTTP/1.1\r\nHost: h\r\n\r\n", 4096,
			"HTTP/1.1 206 Partial Content\r\nContent-Length: 1024\r\n\r\n")
		assert.Equal(t, http.OpGetObjectRange, e.Operation)
	})

	t.Run("head_has_no_body", func(t *testing.T) {
		e := newEvent("HEAD /b/k HTTP/1.1\r\nHost: h\r\n\r\n", 430,
			"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n")
		assert.Equal(t, uint64(0), e.ResponseSize)
	})

	t.Run("204_without_content_length_has_no_body", func(t *testing.T) {
		resp := "HTTP/1.1 204 No Content\r\nx-amz-request-id: abc\r\n\r\n"
		e := newEvent("DELETE /b/k HTTP/1.1\r\nHost: h\r\n\r\n", uint64(len(resp)), resp)
		assert.Equal(t, uint64(0), e.ResponseSize)
	})
}

// TestParseStatusCode_EarlyBytes tests recovering the status of a response
// whose status line the client read byte by byte.
func TestParseStatusCode_EarlyBytes(t *testing.T) {
	headers := "x-amz-request-id: 1\r\nContent-Length: 243\r\n\r\n<?xml"

	t.Run("final_status_from_early_bytes", func(t *testing.T) {
		e := NewS3Event()
		e.Method = "PUT"
		e.ResponseSize = uint64(len(headers))
		e.ParseStatusCode([]byte(headers), []byte("HTTP/1.1 503 Slo"))
		assert.Equal(t, 503, e.StatusCode)
		assert.True(t, e.IsError)
		assert.Equal(t, uint64(243), e.ResponseSize)
	})

	t.Run("interim_100_in_early_bytes_ignored", func(t *testing.T) {
		e := NewS3Event()
		e.ParseStatusCode([]byte(headers), []byte("HTTP/1.1 100 Con"))
		assert.Equal(t, 0, e.StatusCode)
	})

	t.Run("final_read_wins_over_early_bytes", func(t *testing.T) {
		e := NewS3Event()
		e.ParseStatusCode([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), []byte("HTTP/1.1 100 Con"))
		assert.Equal(t, 200, e.StatusCode)
	})
}

// TestParseFromRaw_TruncatedBodilessHead tests that a GET whose head was
// cut off at the capture limit still reports zero request bytes.
func TestParseFromRaw_TruncatedBodilessHead(t *testing.T) {
	e := NewS3Event()
	e.RequestSize = 2048
	e.ParseFromRaw([]byte("GET /b/k HTTP/1.1\r\nX-Amz-Security-Token: AAAA"))
	assert.Equal(t, uint64(0), e.RequestSize)

	e = NewS3Event()
	e.ParseFromRaw([]byte("PUT /b/k HTTP/1.1\r\nContent-Length: 6000000000\r\n\r\n"))
	assert.Equal(t, uint64(6000000000), e.RequestSize, "sizes above 4 GiB do not wrap")
}
