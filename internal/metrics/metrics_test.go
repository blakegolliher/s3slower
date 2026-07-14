// Package metrics provides Prometheus metrics tests.
package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew tests the New function.
func TestNew(t *testing.T) {
	t.Run("creates_metrics_with_core_labels", func(t *testing.T) {
		m := New(nil, nil)

		assert.NotNil(t, m.RequestsTotal)
		assert.NotNil(t, m.RequestErrorsTotal)
		assert.NotNil(t, m.RequestDurationMs)
		assert.NotNil(t, m.RequestBytesTotal)
		assert.NotNil(t, m.ResponseBytesTotal)
		assert.NotNil(t, m.EventsDroppedTotal)
	})

	t.Run("creates_metrics_with_optional_and_extra_labels", func(t *testing.T) {
		m := New([]string{"bucket", "endpoint"}, []string{"client", "env"})
		assert.NotNil(t, m.RequestsTotal)
	})
}

// TestRegister tests the Register function.
func TestRegister(t *testing.T) {
	t.Run("registers_with_registry", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := New([]string{"bucket", "endpoint"}, nil)

		require.NoError(t, m.Register(reg))

		m.RecordRequest(prometheus.Labels{
			"comm":         "aws",
			"s3_operation": "GET_OBJECT",
			"bucket":       "test-bucket",
			"endpoint":     "http://localhost:9000",
		}, 100.0, 1024, 2048, false, 200)

		mfs, err := reg.Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, mfs)
	})

	t.Run("fails_on_duplicate_registration", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := New(nil, nil)

		require.NoError(t, m.Register(reg))
		assert.Error(t, m.Register(reg))
	})
}

// TestRecordRequest tests the RecordRequest function.
func TestRecordRequest(t *testing.T) {
	t.Run("records_with_only_core_labels", func(t *testing.T) {
		m := New(nil, nil)
		labels := prometheus.Labels{
			"comm":         "aws",
			"s3_operation": "GET_OBJECT",
		}

		m.RecordRequest(labels, 100.5, 1024, 2048, false, 200)

		counter, err := m.RequestsTotal.GetMetricWith(labels)
		require.NoError(t, err)
		assert.NotNil(t, counter)
	})

	t.Run("records_with_optional_labels", func(t *testing.T) {
		m := New([]string{"bucket", "endpoint"}, nil)
		labels := prometheus.Labels{
			"comm":         "aws",
			"s3_operation": "GET_OBJECT",
			"bucket":       "test-bucket",
			"endpoint":     "10.0.0.1",
		}

		m.RecordRequest(labels, 500.0, 0, 0, true, 503)

		counter, err := m.RequestErrorsTotal.GetMetricWith(labels)
		require.NoError(t, err)
		assert.NotNil(t, counter)
	})

	t.Run("response_status_omits_bucket_when_disabled", func(t *testing.T) {
		m := New(nil, nil)
		labels := prometheus.Labels{
			"comm":         "aws",
			"s3_operation": "GET_OBJECT",
		}
		m.RecordRequest(labels, 10, 0, 0, false, 200)

		// The metric should be reachable via just status_code.
		counter, err := m.ResponseStatusTotal.GetMetricWith(prometheus.Labels{
			"status_code": "200",
		})
		require.NoError(t, err)
		assert.NotNil(t, counter)
	})
}

// TestRecordDrop tests the RecordDrop function.
func TestRecordDrop(t *testing.T) {
	m := New(nil, nil)

	m.RecordDrop(DropReasonPerfLost, 3)
	m.RecordDrop(DropReasonChannelFull, 7)
	// A zero count must not touch the counter.
	m.RecordDrop(DropReasonPerfLost, 0)

	assertCounter := func(reason string, want float64) {
		t.Helper()
		var out dto.Metric
		require.NoError(t, m.EventsDroppedTotal.WithLabelValues(reason).Write(&out))
		assert.Equal(t, want, out.GetCounter().GetValue())
	}
	assertCounter(DropReasonPerfLost, 3)
	assertCounter(DropReasonChannelFull, 7)
}

// TestExporter tests the Exporter struct.
func TestExporter(t *testing.T) {
	t.Run("creates_exporter", func(t *testing.T) {
		exp, err := NewExporter(":9000", nil, nil)

		require.NoError(t, err)
		assert.NotNil(t, exp)
		assert.NotNil(t, exp.Metrics())
		assert.Equal(t, ":9000", exp.addr)
	})

	t.Run("creates_exporter_with_labels", func(t *testing.T) {
		exp, err := NewExporter(":9000", []string{"bucket"}, []string{"client", "env"})
		require.NoError(t, err)
		assert.NotNil(t, exp)
	})
}

// TestLabelConstants pins the label set used by the exporter.
func TestLabelConstants(t *testing.T) {
	assert.Equal(t, []string{"comm", "s3_operation"}, CoreLabels)
	assert.Equal(t, []string{"bucket", "endpoint"}, OptionalLabels)
	assert.True(t, IsOptionalLabel("bucket"))
	assert.True(t, IsOptionalLabel("endpoint"))
	assert.False(t, IsOptionalLabel("hostname"))
}

// Benchmark tests
func BenchmarkRecordRequest(b *testing.B) {
	m := New([]string{"bucket", "endpoint"}, nil)
	labels := prometheus.Labels{
		"comm":         "aws",
		"s3_operation": "GET_OBJECT",
		"bucket":       "test-bucket",
		"endpoint":     "http://localhost:9000",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordRequest(labels, float64(i%1000), 1024, 2048, false, 200)
	}
}
