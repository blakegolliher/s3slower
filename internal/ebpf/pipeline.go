// Package ebpf provides eBPF program loading and management for S3 traffic tracing.
package ebpf

import (
	"fmt"
	"os"
	"sync"

	"github.com/s3slower/s3slower/internal/event"
)

// DropCallback is invoked whenever an event is dropped either at the
// kernel perf ring (LostSamples > 0) or when the userspace channel is
// full. Runner wires this to the Prometheus events_dropped_total counter.
type DropCallback func(reason string, count uint64)

// Pipeline connects the BPF tracer to the event processor.
type Pipeline struct {
	mu sync.RWMutex

	tracer    Tracer
	processor *event.EventProcessor
	running   bool
	stopCh    chan struct{}
	debug     bool

	onDrop DropCallback

	// Configuration
	mode          ProbeMode
	targetPID     uint32
	minLatencyUs  uint64
	libraryPath   string
	libraryFinder LibraryFinder

	// checkedGoTLS caches binary paths we've already inspected for
	// Go crypto/tls symbols (true = has them, false = doesn't).
	// attachedGoTLS tracks binaries with uprobes successfully attached.
	checkedGoTLS  map[string]bool
	attachedGoTLS map[string]bool
}

// SetDropCallback registers a callback invoked on every dropped event.
// The callback runs on the perf-reader goroutine and must not block.
func (p *Pipeline) SetDropCallback(cb DropCallback) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onDrop = cb
	p.tracer.SetDropCallback(cb)
}

func (p *Pipeline) debugf(format string, args ...interface{}) {
	if p.debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] [pipeline] "+format+"\n", args...)
	}
}

// PipelineConfig holds configuration for the pipeline.
type PipelineConfig struct {
	Mode         ProbeMode
	TargetPID    uint32
	MinLatencyMs uint64
	LibraryPath  string
	BufferSize   int
	Debug        bool
}

const defaultBufferSize = 100

// NewPipeline creates a new event processing pipeline backed by the real
// eBPF tracer and library finder.
func NewPipeline(config PipelineConfig) (*Pipeline, error) {
	tracer, err := NewBPFTracer()
	if err != nil {
		return nil, fmt.Errorf("failed to create tracer: %w", err)
	}
	return newPipeline(tracer, NewLibraryFinder(), config), nil
}

// NewPipelineWithMock returns a pipeline wired to the mock tracer / finder,
// used for tests and as a fallback when the real BPF tracer cannot load
// (e.g. running as non-root in development).
func NewPipelineWithMock(config PipelineConfig) (*Pipeline, error) {
	return newPipeline(NewMockTracer(), NewMockLibraryFinder(), config), nil
}

func newPipeline(tracer Tracer, finder LibraryFinder, config PipelineConfig) *Pipeline {
	bufferSize := config.BufferSize
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}
	return &Pipeline{
		tracer:        tracer,
		processor:     event.NewEventProcessor(bufferSize),
		mode:          config.Mode,
		targetPID:     config.TargetPID,
		minLatencyUs:  config.MinLatencyMs * 1000,
		libraryPath:   config.LibraryPath,
		libraryFinder: finder,
		debug:         config.Debug,
		stopCh:        make(chan struct{}),
	}
}

// Start initializes and starts the pipeline.
func (p *Pipeline) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("pipeline already running")
	}

	// Load the BPF program
	if err := p.tracer.Load(); err != nil {
		return fmt.Errorf("failed to load tracer: %w", err)
	}

	// Set filters
	p.tracer.SetTargetPID(p.targetPID)
	p.tracer.SetMinLatency(p.minLatencyUs)

	// Attach probes based on mode
	if err := p.attachProbes(); err != nil {
		p.tracer.Close()
		return fmt.Errorf("failed to attach probes: %w", err)
	}

	// Start event reading
	if err := p.tracer.Start(p.handleEvent); err != nil {
		p.tracer.DetachAll()
		p.tracer.Close()
		return fmt.Errorf("failed to start tracer: %w", err)
	}

	p.running = true
	p.stopCh = make(chan struct{})

	// In auto or gotls mode (without an explicit path), watch for new
	// process starts so Go TLS binaries are discovered instantly.
	if p.mode == ProbeModeAuto || (p.mode == ProbeModeGoTLS && p.libraryPath == "") {
		if err := p.tracer.WatchExec(p.onExec); err != nil {
			fmt.Fprintf(os.Stderr, "warning: exec watcher unavailable, Go TLS auto-discovery disabled: %v\n", err)
		}
	}

	return nil
}

// attachProbes attaches the appropriate probes based on mode.
func (p *Pipeline) attachProbes() error {
	p.debugf("Attaching probes in mode: %s", p.mode)
	switch p.mode {
	case ProbeModeHTTP:
		return p.tracer.AttachKprobes()

	case ProbeModeOpenSSL, ProbeModeGnuTLS, ProbeModeNSS, ProbeModeS2N:
		libPath := p.libraryPath
		if libPath == "" {
			// Auto-detect library path
			var err error
			switch p.mode {
			case ProbeModeOpenSSL:
				libPath, err = p.libraryFinder.FindOpenSSL()
			case ProbeModeGnuTLS:
				libPath, err = p.libraryFinder.FindGnuTLS()
			case ProbeModeNSS:
				libPath, err = p.libraryFinder.FindNSS()
			case ProbeModeS2N:
				libPath, err = p.libraryFinder.FindS2N()
			}
			if err != nil {
				return fmt.Errorf("failed to find %s library: %w", p.mode, err)
			}
		}
		return p.tracer.AttachUprobes(libPath, p.mode)

	case ProbeModeGoTLS:
		if p.libraryPath != "" {
			return p.tracer.AttachUprobes(p.libraryPath, ProbeModeGoTLS)
		}
		// Initial scan; background scanner (started in Start()) picks up
		// binaries that appear later.
		p.scanGoTLS()
		return nil

	case ProbeModeAuto:
		// Try to attach all available probes
		// First attach kprobes for HTTP
		if err := p.tracer.AttachKprobes(); err != nil {
			return fmt.Errorf("failed to attach kprobes: %w", err)
		}

		// Then try to attach uprobes for available TLS libraries
		libs := p.libraryFinder.FindAll()
		for mode, path := range libs {
			if err := p.tracer.AttachUprobes(path, mode); err != nil {
				// Log but don't fail - some libraries may not be available
				fmt.Fprintf(os.Stderr, "warning: failed to attach %s uprobes to %s: %v\n", mode, path, err)
			}
		}

		// Attach to statically-linked binaries that embed OpenSSL
		for _, binPath := range p.libraryFinder.FindStaticBinaries() {
			p.debugf("Found statically-linked SSL binary: %s", binPath)
			if err := p.tracer.AttachUprobes(binPath, ProbeModeOpenSSL); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to attach uprobes to %s: %v\n", binPath, err)
			}
		}

		// Initial scan for Go binaries with crypto/tls; the background
		// scanner (started in Start()) picks up binaries that appear later.
		p.scanGoTLS()
		return nil

	default:
		return fmt.Errorf("unsupported probe mode: %s", p.mode)
	}
}

// handleEvent processes a raw event from the BPF tracer.
func (p *Pipeline) handleEvent(raw *RawEvent) {
	// Convert raw event to S3Event
	s3event := event.NewS3Event()

	s3event.PID = raw.PID
	s3event.TID = raw.TID
	s3event.Comm = commToString(raw.Comm[:])
	s3event.RequestSize = raw.ReqSize
	s3event.ResponseSize = raw.RespSize

	// Set latency
	s3event.SetLatency(raw.LatencyUs)

	// Parse HTTP data
	s3event.ParseFromRaw(raw.Data[:])

	// Parse response status code from response data
	s3event.ParseStatusCode(raw.RespData[:])

	// Set client type
	s3event.ClientType = clientTypeToString(raw.ClientType)

	// Send to processor (non-blocking). If the buffer is full we drop and
	// account for it so the drop is observable, not silent.
	if !p.processor.SendEvent(s3event) {
		if p.onDrop != nil {
			p.onDrop("channel_full", 1)
		}
	}
}

// clientTypeToString converts a client type constant to a string.
func clientTypeToString(ct uint8) string {
	switch ct {
	case ClientWarp:
		return "warp"
	case ClientElbencho:
		return "elbencho"
	case ClientBoto3:
		return "boto3"
	case ClientS3cmd:
		return "s3cmd"
	case ClientAWSCLI:
		return "awscli"
	default:
		return "unknown"
	}
}

// Stop stops the pipeline.
func (p *Pipeline) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return
	}

	close(p.stopCh)
	p.running = false

	p.tracer.Stop()
	p.tracer.DetachAll()
	p.tracer.Close()
	p.processor.Close()
}

// Events returns the channel of processed events.
func (p *Pipeline) Events() <-chan *event.S3Event {
	return p.processor.Events()
}

// Stats returns statistics about the pipeline.
func (p *Pipeline) Stats() PipelineStats {
	tracerStats := p.tracer.Stats()

	return PipelineStats{
		TracerStats:  tracerStats,
		Mode:         p.mode,
		TargetPID:    p.targetPID,
		MinLatencyUs: p.minLatencyUs,
		Running:      p.running,
	}
}

// PipelineStats holds statistics about the pipeline.
type PipelineStats struct {
	TracerStats  ProbeStats
	Mode         ProbeMode
	TargetPID    uint32
	MinLatencyUs uint64
	Running      bool
}

// SetTargetPID updates the target PID filter.
func (p *Pipeline) SetTargetPID(pid uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.targetPID = pid
	p.tracer.SetTargetPID(pid)
}

// onExec is called by WatchExec for every newly exec'd process.
// It checks if the binary is a Go program using crypto/tls and
// attaches uprobes if so.
func (p *Pipeline) onExec(pid uint32) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	resolved, err := os.Readlink(exePath)
	if err != nil {
		return // process may have already exited
	}

	p.mu.Lock()
	// Fast path: we've already inspected this binary.
	if p.checkedGoTLS != nil {
		if _, ok := p.checkedGoTLS[resolved]; ok {
			alreadyAttached := p.attachedGoTLS[resolved]
			p.mu.Unlock()
			if alreadyAttached {
				return
			}
			// Previously analyzed but attach failed; fall through to retry.
		} else {
			p.mu.Unlock()
		}
	} else {
		p.mu.Unlock()
	}

	// Single-pass analysis: open ELF once, check Go + TLS + find RET offsets.
	analysis, err := analyzeGoTLSBinary(resolved)
	if err != nil {
		p.debugf("Go TLS analysis failed for %s: %v", resolved, err)
		return
	}

	p.mu.Lock()
	if p.checkedGoTLS == nil {
		p.checkedGoTLS = make(map[string]bool)
	}
	p.checkedGoTLS[resolved] = analysis.hasTLS
	p.mu.Unlock()

	if !analysis.hasTLS {
		return
	}

	p.debugf("Discovered Go TLS binary: %s (PID %d)", resolved, pid)
	if err := p.tracer.AttachGoTLSUprobes(resolved, analysis.retOffsets); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to attach Go TLS uprobes to %s: %v\n", resolved, err)
		return
	}

	p.mu.Lock()
	if p.attachedGoTLS == nil {
		p.attachedGoTLS = make(map[string]bool)
	}
	p.attachedGoTLS[resolved] = true
	p.mu.Unlock()
}

// scanGoTLS does an initial one-shot scan for Go TLS binaries that
// are already running or installed at known paths.
func (p *Pipeline) scanGoTLS() {
	for _, binPath := range p.libraryFinder.FindGoTLS() {
		if p.attachedGoTLS[binPath] {
			continue
		}
		analysis, err := analyzeGoTLSBinary(binPath)
		if err != nil || !analysis.hasTLS {
			continue
		}
		p.debugf("Found Go TLS binary: %s", binPath)
		if err := p.tracer.AttachGoTLSUprobes(binPath, analysis.retOffsets); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to attach Go TLS uprobes to %s: %v\n", binPath, err)
			continue
		}
		if p.attachedGoTLS == nil {
			p.attachedGoTLS = make(map[string]bool)
		}
		p.attachedGoTLS[binPath] = true
	}
}

// SetMinLatency updates the minimum latency filter.
func (p *Pipeline) SetMinLatency(latencyMs uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.minLatencyUs = latencyMs * 1000
	p.tracer.SetMinLatency(p.minLatencyUs)
}
