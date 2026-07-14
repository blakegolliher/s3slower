// Package ebpf provides eBPF program loading and management for S3 traffic tracing.
package ebpf

import (
	"fmt"
	"os"
	"sync"

	"github.com/s3slower/s3slower/internal/event"
)

// Pipeline connects the BPF tracer to the event processor.
type Pipeline struct {
	mu sync.RWMutex

	tracer    Tracer
	processor *event.EventProcessor
	running   bool
	stopCh    chan struct{}
	debug     bool

	// Configuration
	mode           ProbeMode
	targetPID      uint32
	minLatencyUs   uint64
	libraryPath    string
	libraryFinder  LibraryFinder
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

	return nil
}

// attachProbes attaches the appropriate probes based on mode.
func (p *Pipeline) attachProbes() error {
	p.debugf("Attaching probes in mode: %s", p.mode)
	switch p.mode {
	case ProbeModeHTTP:
		return p.tracer.AttachKprobes()

	case ProbeModeOpenSSL, ProbeModeGnuTLS, ProbeModeNSS:
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
			}
			if err != nil {
				return fmt.Errorf("failed to find %s library: %w", p.mode, err)
			}
		}
		return p.tracer.AttachUprobes(libPath, p.mode)

	case ProbeModeAuto:
		// Attach syscall kprobes for plain HTTP first.
		if err := p.tracer.AttachKprobes(); err != nil {
			return fmt.Errorf("failed to attach kprobes: %w", err)
		}

		// Attach uprobes to every TLS library we can find; a missing library
		// is expected on many hosts and must not fail the entire attach.
		for mode, path := range p.libraryFinder.FindAll() {
			if err := p.tracer.AttachUprobes(path, mode); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to attach %s uprobes to %s: %v\n", mode, path, err)
			}
		}

		// Attach to statically-linked binaries that embed OpenSSL.
		for _, binPath := range p.libraryFinder.FindStaticBinaries() {
			p.debugf("Found statically-linked SSL binary: %s", binPath)
			if err := p.tracer.AttachUprobes(binPath, ProbeModeOpenSSL); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to attach uprobes to %s: %v\n", binPath, err)
			}
		}
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

	// Send to processor (non-blocking)
	p.processor.SendEvent(s3event)
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
		TracerStats:   tracerStats,
		Mode:          p.mode,
		TargetPID:     p.targetPID,
		MinLatencyUs:  p.minLatencyUs,
		Running:       p.running,
	}
}

// PipelineStats holds statistics about the pipeline.
type PipelineStats struct {
	TracerStats   ProbeStats
	Mode          ProbeMode
	TargetPID     uint32
	MinLatencyUs  uint64
	Running       bool
}

// SetTargetPID updates the target PID filter.
func (p *Pipeline) SetTargetPID(pid uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.targetPID = pid
	p.tracer.SetTargetPID(pid)
}

// SetMinLatency updates the minimum latency filter.
func (p *Pipeline) SetMinLatency(latencyMs uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.minLatencyUs = latencyMs * 1000
	p.tracer.SetMinLatency(p.minLatencyUs)
}
