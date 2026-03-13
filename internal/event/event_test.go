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

