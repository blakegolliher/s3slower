package terminal

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/s3slower/s3slower/internal/event"
	"github.com/s3slower/s3slower/internal/http"
)

func topEvent(op http.S3Operation, client string, latency float64, req, resp uint64, isErr bool) *event.S3Event {
	return &event.S3Event{Operation: op, ClientType: client, LatencyMs: latency,
		RequestSize: req, ResponseSize: resp, IsError: isErr}
}

// TestTopViewRender tests window aggregation, rates and percentiles.
func TestTopViewRender(t *testing.T) {
	v := newTopView()
	for i := 1; i <= 100; i++ {
		v.add(topEvent(http.OpGetObjectRange, "boto3", float64(i), 0, 65536, false))
	}
	v.add(topEvent(http.OpHeadObject, "aws", 2, 0, 0, true))
	v.tick() // close the first second

	out := v.render(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	lines := strings.Split(out, "\n")

	assert.Contains(t, lines[0], "101.0 req/s")
	assert.Contains(t, lines[0], "read 6.6MB/s")
	var rangeLine, headLine string
	for _, l := range lines {
		if strings.HasPrefix(l, "GET_OBJECT_RANGE") {
			rangeLine = l
		}
		if strings.HasPrefix(l, "HEAD_OBJECT") {
			headLine = l
		}
	}
	fields := strings.Fields(rangeLine)
	assert.Equal(t, "100.0", fields[1], "req/s")
	assert.Equal(t, "65.5kB", fields[4], "avg size")
	assert.Equal(t, "51.00", fields[5], "p50")
	assert.Equal(t, "100.00", fields[6], "p99")
	assert.Equal(t, "100", fields[9], "total")
	assert.Contains(t, headLine, "100.0") // 100% errors
	assert.Contains(t, out, "boto3")
	assert.Contains(t, out, "aws")
}

// TestTopViewExcludesCurrentSlot checks that the partial current second
// does not count until it is closed.
func TestTopViewExcludesCurrentSlot(t *testing.T) {
	v := newTopView()
	v.add(topEvent(http.OpGetObject, "boto3", 1, 0, 10, false))
	assert.Contains(t, v.render(time.Now()), "(no requests in window)")

	// Old slots age out after topWindow ticks.
	for i := 0; i < topWindow+1; i++ {
		v.tick()
	}
	assert.Contains(t, v.render(time.Now()), "(no requests in window)")
}

// TestTopModeWriter checks the writer routes events to the view and
// redraws with a clear-screen sequence.
func TestTopModeWriter(t *testing.T) {
	var buf safeBuffer
	w := NewWriter(&buf, OutputModeTop, 50)
	w.WriteHeader()
	w.WriteEvent(topEvent(http.OpPutObject, "awscli", 5, 1024, 0, false))
	assert.Empty(t, buf.String(), "top mode draws only on ticks")

	w.Start()
	time.Sleep(1100 * time.Millisecond)
	w.Stop()
	assert.Contains(t, buf.String(), "\x1b[H\x1b[2J")
	assert.Contains(t, buf.String(), "PUT_OBJECT")
}

// TestTopViewSteadyRate checks a constant rate reads correctly once the
// window is full.
func TestTopViewSteadyRate(t *testing.T) {
	v := newTopView()
	for s := 0; s < 10; s++ {
		for i := 0; i < 10; i++ {
			v.add(topEvent(http.OpGetObject, "boto3", 1, 0, 1000, false))
		}
		v.tick()
	}
	out := v.render(time.Now())
	assert.Contains(t, out, "(last 5s)   10.0 req/s")
	assert.Contains(t, out, "read 10.0kB/s")
}

func TestHumanBytes(t *testing.T) {
	assert.Equal(t, "999B", humanBytes(999))
	assert.Equal(t, "1.0kB", humanBytes(1000))
	assert.Equal(t, "8.4MB", humanBytes(8388608))
}

// safeBuffer is a bytes.Buffer safe for the redraw goroutine and the test.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
