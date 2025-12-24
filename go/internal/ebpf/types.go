// Package ebpf provides eBPF program loading and management for S3 traffic tracing.
package ebpf

import (
	"time"
)

// ProbeType represents the type of probe to attach.
type ProbeType int

const (
	// ProbeTypeKprobe attaches to kernel functions (syscalls).
	ProbeTypeKprobe ProbeType = iota
	// ProbeTypeUprobe attaches to userspace functions (SSL libraries).
	ProbeTypeUprobe
)

// ProbeMode represents the tracing mode.
type ProbeMode string

const (
	// ProbeModeHTTP traces plain HTTP via syscall kprobes.
	ProbeModeHTTP ProbeMode = "http"
	// ProbeModeOpenSSL traces HTTPS via OpenSSL uprobes.
	ProbeModeOpenSSL ProbeMode = "openssl"
	// ProbeModeGnuTLS traces HTTPS via GnuTLS uprobes.
	ProbeModeGnuTLS ProbeMode = "gnutls"
	// ProbeModeNSS traces HTTPS via NSS uprobes.
	ProbeModeNSS ProbeMode = "nss"
	// ProbeModeAuto automatically detects available TLS libraries.
	ProbeModeAuto ProbeMode = "auto"
)

// RawEvent represents a raw event from the BPF perf buffer.
type RawEvent struct {
	TimestampUs    uint64
	LatencyUs      uint64
	PID            uint32
	TID            uint32
	FD             uint32
	Comm           [16]byte
	ReqSize        uint32
	RespSize       uint32
	ActualRespBytes uint32
	IsPartial      uint8
	ClientType     uint8
	_              [2]byte // padding
	Data           [64]byte
}

// ClientType constants matching BPF program.
const (
	ClientUnknown  uint8 = 0
	ClientWarp     uint8 = 1
	ClientElbencho uint8 = 2
	ClientBoto3    uint8 = 3
	ClientS3cmd    uint8 = 4
	ClientAWSCLI   uint8 = 5
)

// EventCallback is called for each captured event.
type EventCallback func(event *RawEvent)

// ProbeConfig holds configuration for probe attachment.
type ProbeConfig struct {
	// Mode specifies the probe mode (http, openssl, etc.)
	Mode ProbeMode

	// TargetPID filters events to a specific process (0 = all)
	TargetPID uint32

	// MinLatencyUs filters events below this latency threshold
	MinLatencyUs uint64

	// LibraryPath is the path to the TLS library (for uprobes)
	LibraryPath string
}

// ProbeStats holds statistics about probe operation.
type ProbeStats struct {
	EventsReceived   uint64
	EventsDropped    uint64
	AttachTime       time.Time
	LastEventTime    time.Time
	ActiveProbes     int
}

// Probe represents an attached eBPF probe.
type Probe interface {
	// Type returns the probe type (kprobe or uprobe).
	Type() ProbeType

	// Mode returns the probe mode.
	Mode() ProbeMode

	// Attach attaches the probe to its target.
	Attach() error

	// Detach detaches the probe from its target.
	Detach() error

	// IsAttached returns whether the probe is currently attached.
	IsAttached() bool
}

// Tracer manages eBPF program loading and event collection.
type Tracer interface {
	// Load loads the BPF program into the kernel.
	Load() error

	// Close unloads the BPF program and releases resources.
	Close() error

	// AttachKprobes attaches kprobes for HTTP tracing.
	AttachKprobes() error

	// AttachUprobes attaches uprobes to a TLS library.
	AttachUprobes(libraryPath string, mode ProbeMode) error

	// DetachAll detaches all probes.
	DetachAll() error

	// Start begins reading events from the perf buffer.
	Start(callback EventCallback) error

	// Stop stops reading events.
	Stop()

	// Stats returns current probe statistics.
	Stats() ProbeStats

	// SetTargetPID sets the target PID filter.
	SetTargetPID(pid uint32)

	// SetMinLatency sets the minimum latency filter.
	SetMinLatency(latencyUs uint64)
}

// LibraryFinder finds TLS library paths on the system.
type LibraryFinder interface {
	// FindOpenSSL returns the path to libssl.so.
	FindOpenSSL() (string, error)

	// FindGnuTLS returns the path to libgnutls.so.
	FindGnuTLS() (string, error)

	// FindNSS returns the path to libnspr4.so.
	FindNSS() (string, error)

	// FindAll returns all available TLS libraries.
	FindAll() map[ProbeMode]string
}
