// Package runner — tests for the three correctness fixes in commit 3:
// IPv6-safe isLocalEndpoint, label-union pre-fill, and detach callback wiring.
package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/s3slower/s3slower/internal/event"
	"github.com/s3slower/s3slower/internal/metrics"
)

func TestIsLocalEndpoint(t *testing.T) {
	addrs := map[string]bool{
		"127.0.0.1":      true,
		"::1":            true,
		"localhost":      true,
		"fe80::1":        true,
		"10.143.11.203":  true,
		"host.local":     true,
		"2001:db8::dead": true,
	}

	cases := []struct {
		endpoint string
		want     bool
	}{
		// IPv4 with and without port.
		{"127.0.0.1", true},
		{"127.0.0.1:9000", true},
		{"10.143.11.203:443", true},
		{"8.8.8.8:443", false},

		// IPv6 in the bracketed host:port form that HTTP parsers emit.
		{"[::1]:9000", true},
		{"[fe80::1]:80", true},
		{"[2001:db8::dead]:443", true},

		// Bare IPv6, no port. The old LastIndex(":") split mangled these.
		{"::1", true},
		{"fe80::1", true},
		{"2001:db8::dead", true},

		// Hostnames with and without port.
		{"localhost", true},
		{"localhost:9000", true},
		{"host.local", true},
		{"host.local:80", true},
		{"example.com:443", false},
	}

	for _, tc := range cases {
		got := isLocalEndpoint(tc.endpoint, addrs)
		assert.Equalf(t, tc.want, got, "isLocalEndpoint(%q)", tc.endpoint)
	}
}

func TestOnProcessDetachRemovesLabels(t *testing.T) {
	r := &Runner{
		targetLabels: map[uint32]map[string]string{
			100: {"env": "prod"},
			200: {"env": "dev"},
		},
	}

	r.onProcessDetach(100)

	r.mu.RLock()
	_, has100 := r.targetLabels[100]
	_, has200 := r.targetLabels[200]
	r.mu.RUnlock()

	assert.False(t, has100, "pid 100 should be removed from targetLabels")
	assert.True(t, has200, "pid 200 should remain in targetLabels")
}

// TestHandleEventPrefillsExtraLabels covers bug #4. Metrics are registered
// with a non-empty extra-label union; an event arrives from a PID that is
// not in r.targetLabels (startup race, non-target traffic that passes the
// S3 filter, or a target without its own prom_labels). Before the fix this
// called CounterVec.With with fewer label values than the descriptor and
// panicked with "inconsistent label cardinality". After the fix, missing
// keys are filled with "".
func TestHandleEventPrefillsExtraLabels(t *testing.T) {
	// Construct metrics directly with a non-empty extra-label union so the
	// registered vectors actually carry those keys.
	union := []string{"client", "env"}
	m := metrics.New(union)

	r := &Runner{
		config:         DefaultConfig(),
		metrics:        m,
		hostname:       "test-host",
		extraLabelKeys: union,
	}

	evt := &event.S3Event{
		PID:         99999, // not in targetLabels
		Method:      "GET",
		Operation:   "GetObject",
		ClientType:  "curl",
		Bucket:      "b",
		Endpoint:    "10.0.0.1:443",
		IsS3Traffic: true,
		LatencyMs:   10,
	}

	assert.NotPanics(t, func() { r.handleEvent(evt) })
}

// TestHandleEventMergesPartialExtraLabels covers a related case: the PID is
// present in targetLabels but carries only a subset of the registered union.
// The fix must fill the absent keys with "" rather than leaving them unset.
func TestHandleEventMergesPartialExtraLabels(t *testing.T) {
	union := []string{"client", "env"}
	m := metrics.New(union)

	r := &Runner{
		config:         DefaultConfig(),
		metrics:        m,
		hostname:       "test-host",
		extraLabelKeys: union,
		targetLabels: map[uint32]map[string]string{
			4242: {"client": "awscli"}, // no "env"
		},
	}

	evt := &event.S3Event{
		PID:         4242,
		Method:      "GET",
		Operation:   "GetObject",
		ClientType:  "awscli",
		Bucket:      "b",
		Endpoint:    "10.0.0.1:443",
		IsS3Traffic: true,
		LatencyMs:   10,
	}

	assert.NotPanics(t, func() { r.handleEvent(evt) })
}
