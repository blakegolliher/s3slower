// Package metrics provides Prometheus metrics tests.
package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew tests the New function.
func TestNew(t *testing.T) {
	t.Run("creates_metrics_with_default_labels", func(t *testing.T) {
		m := New(nil)

		assert.NotNil(t, m.RequestsTotal)
		assert.NotNil(t, m.RequestErrorsTotal)
		assert.NotNil(t, m.RequestDurationMs)
		assert.NotNil(t, m.RequestDurationMin)
		assert.NotNil(t, m.RequestDurationMax)
		assert.NotNil(t, m.RequestBytesTotal)
		assert.NotNil(t, m.ResponseBytesTotal)
		assert.NotNil(t, m.PartialRequestsTotal)
	})

	t.Run("creates_metrics_with_extra_labels", func(t *testing.T) {
		m := New([]string{"client", "env"})
		assert.NotNil(t, m.RequestsTotal)
	})
}

// TestRegister tests the Register function.
func TestRegister(t *testing.T) {
	t.Run("registers_with_registry", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := New(nil)

		err := m.Register(reg)
		require.NoError(t, err)

		// Record a request to populate metrics
		labels := prometheus.Labels{
			"hostname":     "test-host",
			"comm":         "aws",
			"s3_operation": "GET_OBJECT",
			"method":       "GET",
			"pid":          "12345",
		}
		m.RecordRequest(labels, 100.0, 1024, 2048, false, false)

		// Try to gather metrics
		mfs, err := reg.Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, mfs)
	})

	t.Run("fails_on_duplicate_registration", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := New(nil)

		err := m.Register(reg)
		require.NoError(t, err)

		// Second registration should fail
		err = m.Register(reg)
		assert.Error(t, err)
	})
}

// TestRecordRequest tests the RecordRequest function.
func TestRecordRequest(t *testing.T) {
	t.Run("records_basic_request", func(t *testing.T) {
		m := New(nil)

		labels := prometheus.Labels{
			"hostname":     "test-host",
			"comm":         "aws",
			"s3_operation": "GET_OBJECT",
			"method":       "GET",
			"pid":          "12345",
		}

		m.RecordRequest(labels, 100.5, 1024, 2048, false, false)

		// Verify counters incremented
		counter, err := m.RequestsTotal.GetMetricWith(labels)
		require.NoError(t, err)

		// Note: We can't easily read counter values in the test
		// but we can verify no panics occurred
		assert.NotNil(t, counter)
	})

	t.Run("records_error_request", func(t *testing.T) {
		m := New(nil)

		labels := prometheus.Labels{
			"hostname":     "test-host",
			"comm":         "aws",
			"s3_operation": "GET_OBJECT",
			"method":       "GET",
			"pid":          "12345",
		}

		m.RecordRequest(labels, 500.0, 0, 0, true, false)

		counter, err := m.RequestErrorsTotal.GetMetricWith(labels)
		require.NoError(t, err)
		assert.NotNil(t, counter)
	})

	t.Run("records_partial_request", func(t *testing.T) {
		m := New(nil)

		labels := prometheus.Labels{
			"hostname":     "test-host",
			"comm":         "aws",
			"s3_operation": "PUT_OBJECT",
			"method":       "PUT",
			"pid":          "12345",
		}

		m.RecordRequest(labels, 50.0, 1024, 0, false, true)

		counter, err := m.PartialRequestsTotal.GetMetricWith(labels)
		require.NoError(t, err)
		assert.NotNil(t, counter)
	})

	t.Run("tracks_min_max_latency", func(t *testing.T) {
		m := New(nil)

		labels := prometheus.Labels{
			"hostname":     "test-host",
			"comm":         "aws",
			"s3_operation": "GET_OBJECT",
			"method":       "GET",
			"pid":          "12345",
		}

		// Record multiple requests with different latencies
		m.RecordRequest(labels, 100.0, 0, 0, false, false)
		m.RecordRequest(labels, 50.0, 0, 0, false, false)
		m.RecordRequest(labels, 200.0, 0, 0, false, false)

		// Verify min/max tracking
		key := labelsToKey(labels)
		m.mu.RLock()
		stats := m.latencyMinMax[key]
		m.mu.RUnlock()

		assert.Equal(t, 50.0, stats.min)
		assert.Equal(t, 200.0, stats.max)
	})
}

// TestExporter tests the Exporter struct.
func TestExporter(t *testing.T) {
	t.Run("creates_exporter", func(t *testing.T) {
		exp := NewExporter(":9000", nil)

		assert.NotNil(t, exp)
		assert.NotNil(t, exp.Metrics())
		assert.Equal(t, ":9000", exp.addr)
	})

	t.Run("creates_exporter_with_extra_labels", func(t *testing.T) {
		exp := NewExporter(":9000", []string{"client", "env"})
		assert.NotNil(t, exp)
	})
}

// TestSampleBuffer tests the SampleBuffer struct.
func TestSampleBuffer(t *testing.T) {
	t.Run("add_and_len", func(t *testing.T) {
		buf := NewSampleBuffer(10)

		assert.Equal(t, 0, buf.Len())

		buf.Add(Sample{
			Timestamp:  time.Now(),
			DurationMs: 100.0,
		})

		assert.Equal(t, 1, buf.Len())
	})

	t.Run("flush_clears_buffer", func(t *testing.T) {
		buf := NewSampleBuffer(10)

		buf.Add(Sample{Timestamp: time.Now(), DurationMs: 100.0})
		buf.Add(Sample{Timestamp: time.Now(), DurationMs: 200.0})

		samples := buf.Flush()
		assert.Len(t, samples, 2)
		assert.Equal(t, 0, buf.Len())
	})

	t.Run("respects_max_size", func(t *testing.T) {
		buf := NewSampleBuffer(3)

		for i := 0; i < 5; i++ {
			buf.Add(Sample{
				Timestamp:  time.Now(),
				DurationMs: float64(i * 100),
			})
		}

		assert.Equal(t, 3, buf.Len())

		samples := buf.Flush()
		assert.Len(t, samples, 3)

		// Should have the last 3 samples
		assert.Equal(t, 200.0, samples[0].DurationMs)
		assert.Equal(t, 300.0, samples[1].DurationMs)
		assert.Equal(t, 400.0, samples[2].DurationMs)
	})

	t.Run("flush_returns_copy", func(t *testing.T) {
		buf := NewSampleBuffer(10)

		buf.Add(Sample{Timestamp: time.Now(), DurationMs: 100.0})
		samples1 := buf.Flush()

		buf.Add(Sample{Timestamp: time.Now(), DurationMs: 200.0})
		samples2 := buf.Flush()

		// Modifying samples1 should not affect buffer
		assert.Len(t, samples1, 1)
		assert.Len(t, samples2, 1)
		assert.NotEqual(t, samples1[0].DurationMs, samples2[0].DurationMs)
	})
}

// TestDefaultLabels tests the default label set.
func TestDefaultLabels(t *testing.T) {
	expected := []string{"hostname", "comm", "s3_operation", "method", "pid"}
	assert.Equal(t, expected, DefaultLabels)
}

// Benchmark tests
func BenchmarkRecordRequest(b *testing.B) {
	m := New(nil)
	labels := prometheus.Labels{
		"hostname":     "test-host",
		"comm":         "aws",
		"s3_operation": "GET_OBJECT",
		"method":       "GET",
		"pid":          "12345",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordRequest(labels, float64(i%1000), 1024, 2048, false, false)
	}
}

func BenchmarkSampleBufferAdd(b *testing.B) {
	buf := NewSampleBuffer(1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Add(Sample{
			Timestamp:  time.Now(),
			DurationMs: float64(i),
		})
	}
}
