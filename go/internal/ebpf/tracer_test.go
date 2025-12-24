// Package ebpf provides eBPF program loading and management for S3 traffic tracing.
package ebpf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestProbeType tests probe type constants.
func TestProbeType(t *testing.T) {
	tests := []struct {
		name      string
		probeType ProbeType
		want      int
	}{
		{"kprobe", ProbeTypeKprobe, 0},
		{"uprobe", ProbeTypeUprobe, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, int(tt.probeType))
		})
	}
}

// TestProbeMode tests probe mode constants.
func TestProbeMode(t *testing.T) {
	tests := []struct {
		name string
		mode ProbeMode
		want string
	}{
		{"http", ProbeModeHTTP, "http"},
		{"openssl", ProbeModeOpenSSL, "openssl"},
		{"gnutls", ProbeModeGnuTLS, "gnutls"},
		{"nss", ProbeModeNSS, "nss"},
		{"auto", ProbeModeAuto, "auto"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.mode))
		})
	}
}

// TestRawEvent tests the RawEvent struct.
func TestRawEvent(t *testing.T) {
	t.Run("creates_event_with_fields", func(t *testing.T) {
		event := RawEvent{
			TimestampUs:     1000000,
			LatencyUs:       5000,
			PID:             12345,
			TID:             12345,
			FD:              3,
			Comm:            [16]byte{'a', 'w', 's'},
			ReqSize:         1024,
			RespSize:        2048,
			ActualRespBytes: 2048,
			IsPartial:       0,
			ClientType:      ClientAWSCLI,
		}

		assert.Equal(t, uint64(1000000), event.TimestampUs)
		assert.Equal(t, uint64(5000), event.LatencyUs)
		assert.Equal(t, uint32(12345), event.PID)
		assert.Equal(t, uint32(3), event.FD)
		assert.Equal(t, uint32(1024), event.ReqSize)
		assert.Equal(t, uint32(2048), event.RespSize)
		assert.Equal(t, uint8(ClientAWSCLI), event.ClientType)
	})

	t.Run("comm_to_string", func(t *testing.T) {
		event := RawEvent{
			Comm: [16]byte{'p', 'y', 't', 'h', 'o', 'n', '3', 0},
		}

		// Convert comm to string
		comm := commToString(event.Comm[:])
		assert.Equal(t, "python3", comm)
	})

	t.Run("data_field", func(t *testing.T) {
		event := RawEvent{}
		copy(event.Data[:], []byte("GET /bucket/key HTTP/1.1"))

		data := string(event.Data[:24])
		assert.Equal(t, "GET /bucket/key HTTP/1.1", data)
	})
}

// TestClientTypeConstants tests client type constants.
func TestClientTypeConstants(t *testing.T) {
	tests := []struct {
		name       string
		clientType uint8
		want       uint8
	}{
		{"unknown", ClientUnknown, 0},
		{"warp", ClientWarp, 1},
		{"elbencho", ClientElbencho, 2},
		{"boto3", ClientBoto3, 3},
		{"s3cmd", ClientS3cmd, 4},
		{"awscli", ClientAWSCLI, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.clientType)
		})
	}
}

// TestProbeConfig tests the ProbeConfig struct.
func TestProbeConfig(t *testing.T) {
	t.Run("creates_config_with_defaults", func(t *testing.T) {
		config := ProbeConfig{
			Mode:         ProbeModeHTTP,
			TargetPID:    0,
			MinLatencyUs: 0,
		}

		assert.Equal(t, ProbeModeHTTP, config.Mode)
		assert.Equal(t, uint32(0), config.TargetPID)
		assert.Equal(t, uint64(0), config.MinLatencyUs)
		assert.Empty(t, config.LibraryPath)
	})

	t.Run("creates_config_for_openssl", func(t *testing.T) {
		config := ProbeConfig{
			Mode:         ProbeModeOpenSSL,
			TargetPID:    12345,
			MinLatencyUs: 1000,
			LibraryPath:  "/usr/lib/x86_64-linux-gnu/libssl.so.3",
		}

		assert.Equal(t, ProbeModeOpenSSL, config.Mode)
		assert.Equal(t, uint32(12345), config.TargetPID)
		assert.Equal(t, uint64(1000), config.MinLatencyUs)
		assert.Equal(t, "/usr/lib/x86_64-linux-gnu/libssl.so.3", config.LibraryPath)
	})
}

// TestProbeStats tests the ProbeStats struct.
func TestProbeStats(t *testing.T) {
	t.Run("creates_stats", func(t *testing.T) {
		now := time.Now()
		stats := ProbeStats{
			EventsReceived: 100,
			EventsDropped:  5,
			AttachTime:     now,
			LastEventTime:  now.Add(time.Second),
			ActiveProbes:   4,
		}

		assert.Equal(t, uint64(100), stats.EventsReceived)
		assert.Equal(t, uint64(5), stats.EventsDropped)
		assert.Equal(t, now, stats.AttachTime)
		assert.Equal(t, 4, stats.ActiveProbes)
	})

	t.Run("calculates_drop_rate", func(t *testing.T) {
		stats := ProbeStats{
			EventsReceived: 95,
			EventsDropped:  5,
		}

		total := stats.EventsReceived + stats.EventsDropped
		dropRate := float64(stats.EventsDropped) / float64(total) * 100

		assert.Equal(t, float64(5), dropRate)
	})
}

// TestMockTracer tests using a mock tracer implementation.
func TestMockTracer(t *testing.T) {
	t.Run("mock_tracer_lifecycle", func(t *testing.T) {
		tracer := NewMockTracer()

		// Load
		err := tracer.Load()
		assert.NoError(t, err)
		assert.True(t, tracer.IsLoaded())

		// Attach kprobes
		err = tracer.AttachKprobes()
		assert.NoError(t, err)

		// Stats should show active probes
		stats := tracer.Stats()
		assert.True(t, stats.ActiveProbes > 0)

		// Detach
		err = tracer.DetachAll()
		assert.NoError(t, err)

		stats = tracer.Stats()
		assert.Equal(t, 0, stats.ActiveProbes)

		// Close
		err = tracer.Close()
		assert.NoError(t, err)
		assert.False(t, tracer.IsLoaded())
	})

	t.Run("mock_tracer_uprobe_attachment", func(t *testing.T) {
		tracer := NewMockTracer()
		defer tracer.Close()

		err := tracer.Load()
		assert.NoError(t, err)

		err = tracer.AttachUprobes("/usr/lib/libssl.so", ProbeModeOpenSSL)
		assert.NoError(t, err)

		stats := tracer.Stats()
		assert.True(t, stats.ActiveProbes > 0)
	})

	t.Run("mock_tracer_event_callback", func(t *testing.T) {
		tracer := NewMockTracer()
		defer tracer.Close()

		err := tracer.Load()
		assert.NoError(t, err)

		err = tracer.AttachKprobes()
		assert.NoError(t, err)

		eventReceived := make(chan *RawEvent, 1)
		err = tracer.Start(func(event *RawEvent) {
			eventReceived <- event
		})
		assert.NoError(t, err)

		// Inject a mock event
		tracer.InjectEvent(&RawEvent{
			PID:       12345,
			LatencyUs: 5000,
		})

		select {
		case event := <-eventReceived:
			assert.Equal(t, uint32(12345), event.PID)
			assert.Equal(t, uint64(5000), event.LatencyUs)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("expected event not received")
		}

		tracer.Stop()
	})

	t.Run("mock_tracer_set_target_pid", func(t *testing.T) {
		tracer := NewMockTracer()
		defer tracer.Close()

		err := tracer.Load()
		assert.NoError(t, err)

		tracer.SetTargetPID(12345)
		assert.Equal(t, uint32(12345), tracer.TargetPID())
	})

	t.Run("mock_tracer_set_min_latency", func(t *testing.T) {
		tracer := NewMockTracer()
		defer tracer.Close()

		err := tracer.Load()
		assert.NoError(t, err)

		tracer.SetMinLatency(1000)
		assert.Equal(t, uint64(1000), tracer.MinLatency())
	})

	t.Run("mock_tracer_load_error", func(t *testing.T) {
		tracer := NewMockTracer()
		tracer.SetLoadError(assert.AnError)

		err := tracer.Load()
		assert.Error(t, err)
	})

	t.Run("mock_tracer_attach_before_load", func(t *testing.T) {
		tracer := NewMockTracer()

		err := tracer.AttachKprobes()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not loaded")
	})
}

// TestKprobeAttachment tests kprobe-specific functionality.
func TestKprobeAttachment(t *testing.T) {
	t.Run("attaches_read_write_probes", func(t *testing.T) {
		tracer := NewMockTracer()
		defer tracer.Close()

		err := tracer.Load()
		assert.NoError(t, err)

		err = tracer.AttachKprobes()
		assert.NoError(t, err)

		// Should have probes for read and write syscalls
		probes := tracer.AttachedProbes()
		assert.Contains(t, probes, "sys_read")
		assert.Contains(t, probes, "sys_write")
	})
}

// TestUprobeAttachment tests uprobe-specific functionality.
func TestUprobeAttachment(t *testing.T) {
	t.Run("attaches_ssl_probes", func(t *testing.T) {
		tracer := NewMockTracer()
		defer tracer.Close()

		err := tracer.Load()
		assert.NoError(t, err)

		err = tracer.AttachUprobes("/usr/lib/libssl.so.3", ProbeModeOpenSSL)
		assert.NoError(t, err)

		probes := tracer.AttachedProbes()
		assert.Contains(t, probes, "SSL_read")
		assert.Contains(t, probes, "SSL_write")
	})

	t.Run("attaches_gnutls_probes", func(t *testing.T) {
		tracer := NewMockTracer()
		defer tracer.Close()

		err := tracer.Load()
		assert.NoError(t, err)

		err = tracer.AttachUprobes("/usr/lib/libgnutls.so", ProbeModeGnuTLS)
		assert.NoError(t, err)

		probes := tracer.AttachedProbes()
		assert.Contains(t, probes, "gnutls_record_recv")
		assert.Contains(t, probes, "gnutls_record_send")
	})

	t.Run("attaches_nss_probes", func(t *testing.T) {
		tracer := NewMockTracer()
		defer tracer.Close()

		err := tracer.Load()
		assert.NoError(t, err)

		err = tracer.AttachUprobes("/usr/lib/libnss3.so", ProbeModeNSS)
		assert.NoError(t, err)

		probes := tracer.AttachedProbes()
		assert.Contains(t, probes, "PR_Read")
		assert.Contains(t, probes, "PR_Write")
	})

	t.Run("fails_with_invalid_library_path", func(t *testing.T) {
		tracer := NewMockTracer()
		tracer.SetUprobeError(assert.AnError)
		defer tracer.Close()

		err := tracer.Load()
		assert.NoError(t, err)

		err = tracer.AttachUprobes("/nonexistent/libssl.so", ProbeModeOpenSSL)
		assert.Error(t, err)
	})
}

// TestEventFiltering tests event filtering by PID and latency.
func TestEventFiltering(t *testing.T) {
	t.Run("filters_by_pid", func(t *testing.T) {
		tracer := NewMockTracer()
		defer tracer.Close()

		err := tracer.Load()
		assert.NoError(t, err)

		tracer.SetTargetPID(12345)

		err = tracer.AttachKprobes()
		assert.NoError(t, err)

		eventReceived := make(chan *RawEvent, 2)
		err = tracer.Start(func(event *RawEvent) {
			eventReceived <- event
		})
		assert.NoError(t, err)

		// Inject events for different PIDs
		tracer.InjectEvent(&RawEvent{PID: 12345, LatencyUs: 1000})
		tracer.InjectEvent(&RawEvent{PID: 99999, LatencyUs: 1000})

		// Only the matching PID event should be received
		select {
		case event := <-eventReceived:
			assert.Equal(t, uint32(12345), event.PID)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("expected event not received")
		}

		// Second event should be filtered
		select {
		case <-eventReceived:
			t.Fatal("unexpected event received - PID filter not working")
		case <-time.After(50 * time.Millisecond):
			// Expected
		}

		tracer.Stop()
	})

	t.Run("filters_by_min_latency", func(t *testing.T) {
		tracer := NewMockTracer()
		defer tracer.Close()

		err := tracer.Load()
		assert.NoError(t, err)

		tracer.SetMinLatency(5000) // 5ms

		err = tracer.AttachKprobes()
		assert.NoError(t, err)

		eventReceived := make(chan *RawEvent, 2)
		err = tracer.Start(func(event *RawEvent) {
			eventReceived <- event
		})
		assert.NoError(t, err)

		// Inject events with different latencies
		tracer.InjectEvent(&RawEvent{PID: 12345, LatencyUs: 10000}) // 10ms - should pass
		tracer.InjectEvent(&RawEvent{PID: 12345, LatencyUs: 1000})  // 1ms - should be filtered

		// Only high latency event should pass
		select {
		case event := <-eventReceived:
			assert.Equal(t, uint64(10000), event.LatencyUs)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("expected event not received")
		}

		// Low latency event should be filtered
		select {
		case <-eventReceived:
			t.Fatal("unexpected event received - latency filter not working")
		case <-time.After(50 * time.Millisecond):
			// Expected
		}

		tracer.Stop()
	})
}

// helper function - will be implemented in tracer.go
func commToString(comm []byte) string {
	for i, b := range comm {
		if b == 0 {
			return string(comm[:i])
		}
	}
	return string(comm)
}

// BenchmarkEventProcessing benchmarks event processing overhead.
func BenchmarkEventProcessing(b *testing.B) {
	tracer := NewMockTracer()
	_ = tracer.Load()
	_ = tracer.AttachKprobes()

	events := make([]*RawEvent, 1000)
	for i := range events {
		events[i] = &RawEvent{
			PID:       uint32(i),
			LatencyUs: uint64(i * 1000),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracer.InjectEvent(events[i%len(events)])
	}
}
