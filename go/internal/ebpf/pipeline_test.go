// Package ebpf provides eBPF program loading and management for S3 traffic tracing.
package ebpf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestPipelineConfig tests pipeline configuration.
func TestPipelineConfig(t *testing.T) {
	t.Run("creates_config_with_defaults", func(t *testing.T) {
		config := PipelineConfig{
			Mode: ProbeModeHTTP,
		}

		assert.Equal(t, ProbeModeHTTP, config.Mode)
		assert.Equal(t, uint32(0), config.TargetPID)
		assert.Equal(t, uint64(0), config.MinLatencyMs)
		assert.Empty(t, config.LibraryPath)
	})

	t.Run("creates_config_with_all_options", func(t *testing.T) {
		config := PipelineConfig{
			Mode:         ProbeModeOpenSSL,
			TargetPID:    12345,
			MinLatencyMs: 100,
			LibraryPath:  "/usr/lib/libssl.so.3",
			BufferSize:   500,
		}

		assert.Equal(t, ProbeModeOpenSSL, config.Mode)
		assert.Equal(t, uint32(12345), config.TargetPID)
		assert.Equal(t, uint64(100), config.MinLatencyMs)
		assert.Equal(t, "/usr/lib/libssl.so.3", config.LibraryPath)
		assert.Equal(t, 500, config.BufferSize)
	})
}

// TestNewPipelineWithMock tests creating a pipeline with mock tracer.
func TestNewPipelineWithMock(t *testing.T) {
	t.Run("creates_pipeline", func(t *testing.T) {
		config := PipelineConfig{
			Mode:       ProbeModeHTTP,
			BufferSize: 100,
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)
		assert.NotNil(t, pipeline)
	})

	t.Run("converts_latency_to_microseconds", func(t *testing.T) {
		config := PipelineConfig{
			Mode:         ProbeModeHTTP,
			MinLatencyMs: 100, // 100ms
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)
		assert.Equal(t, uint64(100000), pipeline.minLatencyUs) // 100ms = 100000us
	})
}

// TestPipelineStart tests starting the pipeline.
func TestPipelineStart(t *testing.T) {
	t.Run("starts_http_mode", func(t *testing.T) {
		config := PipelineConfig{
			Mode: ProbeModeHTTP,
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)

		err = pipeline.Start()
		assert.NoError(t, err)
		defer pipeline.Stop()

		assert.True(t, pipeline.running)
	})

	t.Run("starts_openssl_mode", func(t *testing.T) {
		config := PipelineConfig{
			Mode:        ProbeModeOpenSSL,
			LibraryPath: "/usr/lib/libssl.so", // Mock doesn't validate path
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)

		// Set up mock library finder to return our path
		if finder, ok := pipeline.libraryFinder.(*MockLibraryFinder); ok {
			finder.SetOpenSSLPath("/usr/lib/libssl.so", nil)
		}

		err = pipeline.Start()
		assert.NoError(t, err)
		defer pipeline.Stop()

		assert.True(t, pipeline.running)
	})

	t.Run("fails_when_already_running", func(t *testing.T) {
		config := PipelineConfig{
			Mode: ProbeModeHTTP,
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)

		err = pipeline.Start()
		assert.NoError(t, err)
		defer pipeline.Stop()

		err = pipeline.Start()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already running")
	})
}

// TestPipelineStop tests stopping the pipeline.
func TestPipelineStop(t *testing.T) {
	t.Run("stops_running_pipeline", func(t *testing.T) {
		config := PipelineConfig{
			Mode: ProbeModeHTTP,
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)

		err = pipeline.Start()
		assert.NoError(t, err)

		pipeline.Stop()
		assert.False(t, pipeline.running)
	})

	t.Run("handles_stop_when_not_running", func(t *testing.T) {
		config := PipelineConfig{
			Mode: ProbeModeHTTP,
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)

		// Should not panic
		pipeline.Stop()
		assert.False(t, pipeline.running)
	})
}

// TestPipelineEvents tests event processing.
func TestPipelineEvents(t *testing.T) {
	t.Run("receives_events", func(t *testing.T) {
		config := PipelineConfig{
			Mode:       ProbeModeHTTP,
			BufferSize: 10,
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)

		err = pipeline.Start()
		assert.NoError(t, err)
		defer pipeline.Stop()

		// Get the mock tracer
		mockTracer := pipeline.tracer.(*MockTracer)

		// Inject an event
		rawEvent := &RawEvent{
			PID:       12345,
			TID:       12345,
			FD:        3,
			LatencyUs: 5000,
			ReqSize:   1024,
			RespSize:  2048,
		}
		copy(rawEvent.Comm[:], "aws")
		copy(rawEvent.Data[:], "GET /bucket/key HTTP/1.1")

		mockTracer.InjectEvent(rawEvent)

		// Wait for event
		select {
		case event := <-pipeline.Events():
			assert.Equal(t, uint32(12345), event.PID)
			assert.Equal(t, "aws", event.Comm)
			assert.Equal(t, 5.0, event.LatencyMs)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("expected event not received")
		}
	})
}

// TestPipelineStats tests statistics reporting.
func TestPipelineStats(t *testing.T) {
	t.Run("returns_stats", func(t *testing.T) {
		config := PipelineConfig{
			Mode:         ProbeModeHTTP,
			TargetPID:    12345,
			MinLatencyMs: 100,
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)

		err = pipeline.Start()
		assert.NoError(t, err)
		defer pipeline.Stop()

		stats := pipeline.Stats()
		assert.Equal(t, ProbeModeHTTP, stats.Mode)
		assert.Equal(t, uint32(12345), stats.TargetPID)
		assert.Equal(t, uint64(100000), stats.MinLatencyUs)
		assert.True(t, stats.Running)
	})
}

// TestPipelineFilters tests dynamic filter updates.
func TestPipelineFilters(t *testing.T) {
	t.Run("updates_target_pid", func(t *testing.T) {
		config := PipelineConfig{
			Mode: ProbeModeHTTP,
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)

		err = pipeline.Start()
		assert.NoError(t, err)
		defer pipeline.Stop()

		pipeline.SetTargetPID(12345)

		stats := pipeline.Stats()
		assert.Equal(t, uint32(12345), stats.TargetPID)
	})

	t.Run("updates_min_latency", func(t *testing.T) {
		config := PipelineConfig{
			Mode: ProbeModeHTTP,
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)

		err = pipeline.Start()
		assert.NoError(t, err)
		defer pipeline.Stop()

		pipeline.SetMinLatency(200) // 200ms

		stats := pipeline.Stats()
		assert.Equal(t, uint64(200000), stats.MinLatencyUs) // 200ms = 200000us
	})
}

// TestPipelineAutoMode tests auto probe mode.
func TestPipelineAutoMode(t *testing.T) {
	t.Run("attaches_all_available_probes", func(t *testing.T) {
		config := PipelineConfig{
			Mode: ProbeModeAuto,
		}

		pipeline, err := NewPipelineWithMock(config)
		assert.NoError(t, err)

		// Set up mock library finder
		if finder, ok := pipeline.libraryFinder.(*MockLibraryFinder); ok {
			finder.SetOpenSSLPath("/usr/lib/libssl.so", nil)
		}

		err = pipeline.Start()
		assert.NoError(t, err)
		defer pipeline.Stop()

		// Should have attached both kprobes and uprobes
		mockTracer := pipeline.tracer.(*MockTracer)
		probes := mockTracer.AttachedProbes()

		// Should have kprobes
		assert.Contains(t, probes, "sys_read")
		assert.Contains(t, probes, "sys_write")

		// Should have SSL uprobes
		assert.Contains(t, probes, "SSL_read")
		assert.Contains(t, probes, "SSL_write")
	})
}

// TestClientTypeToString tests client type conversion.
func TestClientTypeToString(t *testing.T) {
	tests := []struct {
		name       string
		clientType uint8
		want       string
	}{
		{"unknown", ClientUnknown, "unknown"},
		{"warp", ClientWarp, "warp"},
		{"elbencho", ClientElbencho, "elbencho"},
		{"boto3", ClientBoto3, "boto3"},
		{"s3cmd", ClientS3cmd, "s3cmd"},
		{"awscli", ClientAWSCLI, "awscli"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := clientTypeToString(tt.clientType)
			assert.Equal(t, tt.want, result)
		})
	}
}

// BenchmarkPipelineEvent benchmarks event processing through the pipeline.
func BenchmarkPipelineEvent(b *testing.B) {
	config := PipelineConfig{
		Mode:       ProbeModeHTTP,
		BufferSize: 1000,
	}

	pipeline, _ := NewPipelineWithMock(config)
	_ = pipeline.Start()
	defer pipeline.Stop()

	mockTracer := pipeline.tracer.(*MockTracer)

	rawEvent := &RawEvent{
		PID:       12345,
		LatencyUs: 5000,
	}
	copy(rawEvent.Data[:], "GET /bucket/key HTTP/1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mockTracer.InjectEvent(rawEvent)
	}
}
