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
		wantHost      string
		wantPath      string
		wantOperation http.S3Operation
		wantBucket    string
	}{
		{
			name:          "get_object_request",
			data:          []byte("GET /mybucket/mykey.txt HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "GET",
			wantHost:      "s3.amazonaws.com",
			wantPath:      "/mybucket/mykey.txt",
			wantOperation: http.OpGetObject,
			wantBucket:    "mybucket",
		},
		{
			name:          "put_object_request",
			data:          []byte("PUT /mybucket/mykey.txt HTTP/1.1\r\nHost: s3.amazonaws.com\r\nContent-Length: 1024\r\n\r\n"),
			wantMethod:    "PUT",
			wantHost:      "s3.amazonaws.com",
			wantPath:      "/mybucket/mykey.txt",
			wantOperation: http.OpPutObject,
			wantBucket:    "mybucket",
		},
		{
			name:          "list_objects_request",
			data:          []byte("GET /mybucket?list-type=2&prefix=foo/ HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "GET",
			wantHost:      "s3.amazonaws.com",
			wantPath:      "/mybucket?list-type=2&prefix=foo/",
			wantOperation: http.OpListPrefix,
			wantBucket:    "mybucket",
		},
		{
			name:          "multipart_create_request",
			data:          []byte("POST /mybucket/mykey?uploads HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "POST",
			wantHost:      "s3.amazonaws.com",
			wantPath:      "/mybucket/mykey?uploads",
			wantOperation: http.OpMPUCreate,
			wantBucket:    "mybucket",
		},
		{
			name:          "delete_object_request",
			data:          []byte("DELETE /mybucket/mykey.txt HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n"),
			wantMethod:    "DELETE",
			wantHost:      "s3.amazonaws.com",
			wantPath:      "/mybucket/mykey.txt",
			wantOperation: http.OpDeleteObject,
			wantBucket:    "mybucket",
		},
		{
			name:          "empty_data",
			data:          []byte{},
			wantMethod:    "",
			wantHost:      "",
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
			assert.Equal(t, tt.wantHost, event.Host)
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
			event.ParseStatusCode(tt.data)

			assert.Equal(t, tt.wantStatus, event.StatusCode)
			assert.Equal(t, tt.wantIsError, event.IsError)
		})
	}
}

// TestSetLatency tests the SetLatency method.
func TestSetLatency(t *testing.T) {
	tests := []struct {
		name       string
		latencyUs  uint64
		wantMs     float64
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

// TestRequestCorrelator tests the RequestCorrelator struct.
func TestRequestCorrelator(t *testing.T) {
	t.Run("add_and_complete", func(t *testing.T) {
		c := NewRequestCorrelator()
		event := NewS3Event()
		event.Method = "GET"

		c.AddRequest(12345, 3, event)
		assert.Equal(t, 1, c.Len())

		result, ok := c.CompleteRequest(12345, 3)
		assert.True(t, ok)
		assert.Equal(t, "GET", result.Method)
		assert.Equal(t, 0, c.Len())
	})

	t.Run("complete_missing_request", func(t *testing.T) {
		c := NewRequestCorrelator()

		result, ok := c.CompleteRequest(12345, 3)
		assert.False(t, ok)
		assert.Nil(t, result)
	})

	t.Run("get_pending", func(t *testing.T) {
		c := NewRequestCorrelator()
		event := NewS3Event()
		event.Method = "PUT"

		c.AddRequest(12345, 5, event)

		result, ok := c.GetPending(12345, 5)
		assert.True(t, ok)
		assert.Equal(t, "PUT", result.Method)

		// Should still be there
		assert.Equal(t, 1, c.Len())
	})

	t.Run("different_pid_fd_pairs", func(t *testing.T) {
		c := NewRequestCorrelator()

		event1 := NewS3Event()
		event1.Method = "GET"

		event2 := NewS3Event()
		event2.Method = "PUT"

		c.AddRequest(12345, 3, event1)
		c.AddRequest(12345, 4, event2)
		c.AddRequest(67890, 3, &S3Event{Method: "DELETE"})

		assert.Equal(t, 3, c.Len())

		r1, ok := c.CompleteRequest(12345, 3)
		assert.True(t, ok)
		assert.Equal(t, "GET", r1.Method)

		r2, ok := c.CompleteRequest(12345, 4)
		assert.True(t, ok)
		assert.Equal(t, "PUT", r2.Method)

		r3, ok := c.CompleteRequest(67890, 3)
		assert.True(t, ok)
		assert.Equal(t, "DELETE", r3.Method)
	})

	t.Run("cleanup_stale", func(t *testing.T) {
		c := NewRequestCorrelator()

		// Add a request
		event := NewS3Event()
		c.AddRequest(12345, 3, event)

		// Cleanup with short max age shouldn't remove anything yet
		removed := c.CleanupStale(time.Hour)
		assert.Equal(t, 0, removed)
		assert.Equal(t, 1, c.Len())

		// Cleanup with zero max age should remove everything
		removed = c.CleanupStale(0)
		assert.Equal(t, 1, removed)
		assert.Equal(t, 0, c.Len())
	})
}

// TestEventProcessor tests the EventProcessor struct.
func TestEventProcessor(t *testing.T) {
	t.Run("creates_processor", func(t *testing.T) {
		p := NewEventProcessor(0, 100)

		assert.NotNil(t, p)
		assert.NotNil(t, p.Events())
	})

	t.Run("process_write_and_read", func(t *testing.T) {
		p := NewEventProcessor(0, 100)

		// Simulate write (request)
		reqData := []byte("GET /mybucket/mykey.txt HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n")
		p.ProcessWrite(12345, 12345, 3, "aws", reqData, time.Now())

		// Simulate read (response)
		respData := []byte("HTTP/1.1 200 OK\r\n\r\n")
		p.ProcessRead(12345, 12345, 3, respData, 1024, 10000) // 10ms

		// Check event was produced
		select {
		case event := <-p.Events():
			assert.Equal(t, "GET", event.Method)
			assert.Equal(t, 200, event.StatusCode)
			assert.Equal(t, 10.0, event.LatencyMs)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("expected event not received")
		}
	})

	t.Run("filters_by_min_latency", func(t *testing.T) {
		p := NewEventProcessor(100*time.Millisecond, 100) // 100ms minimum

		// Send request/response with 10ms latency (below threshold)
		reqData := []byte("GET /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n")
		p.ProcessWrite(12345, 12345, 3, "aws", reqData, time.Now())

		respData := []byte("HTTP/1.1 200 OK\r\n\r\n")
		p.ProcessRead(12345, 12345, 3, respData, 1024, 10000) // 10ms

		// Check no event was produced
		select {
		case <-p.Events():
			t.Fatal("expected no event due to latency filter")
		case <-time.After(50 * time.Millisecond):
			// Expected - no event
		}
	})

	t.Run("ignores_non_http_methods", func(t *testing.T) {
		p := NewEventProcessor(0, 100)

		// Send non-HTTP data
		data := []byte("This is not an HTTP request")
		p.ProcessWrite(12345, 12345, 3, "test", data, time.Now())

		// No pending request should exist
		assert.Equal(t, 0, p.correlator.Len())
	})

	t.Run("handles_orphan_read", func(t *testing.T) {
		p := NewEventProcessor(0, 100)

		// Send read without matching write
		respData := []byte("HTTP/1.1 200 OK\r\n\r\n")
		p.ProcessRead(12345, 12345, 3, respData, 1024, 10000)

		// Should not panic and no event should be produced
		select {
		case <-p.Events():
			t.Fatal("expected no event for orphan read")
		case <-time.After(50 * time.Millisecond):
			// Expected
		}
	})

	t.Run("cleanup", func(t *testing.T) {
		p := NewEventProcessor(0, 100)

		// Add some requests
		reqData := []byte("GET /bucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n")
		p.ProcessWrite(12345, 12345, 3, "aws", reqData, time.Now())
		p.ProcessWrite(12345, 12345, 4, "aws", reqData, time.Now())

		removed := p.Cleanup(0) // Remove everything
		assert.Equal(t, 2, removed)
	})

	t.Run("close", func(t *testing.T) {
		p := NewEventProcessor(0, 100)
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

// BenchmarkRequestCorrelator benchmarks request correlation.
func BenchmarkRequestCorrelator(b *testing.B) {
	c := NewRequestCorrelator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := NewS3Event()
		pid := uint32(i % 1000)
		fd := int32(i % 10)

		c.AddRequest(pid, fd, event)
		c.CompleteRequest(pid, fd)
	}
}
