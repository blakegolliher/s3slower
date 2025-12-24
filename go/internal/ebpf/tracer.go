// Package ebpf provides eBPF program loading and management for S3 traffic tracing.
package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// BPF config map keys
const (
	configTargetPID    = 0
	configMinLatencyUs = 1
)

// BPFTracer implements the Tracer interface using cilium/ebpf.
type BPFTracer struct {
	mu sync.RWMutex

	spec       *ebpf.CollectionSpec
	collection *ebpf.Collection
	reader     *perf.Reader

	links      []link.Link
	callback   EventCallback
	running    bool
	stopCh     chan struct{}

	targetPID    uint32
	minLatencyUs uint64

	attachTime    time.Time
	eventsRecv    uint64
	eventsDrop    uint64
	lastEventTime time.Time
}

// NewBPFTracer creates a new BPF tracer from embedded BPF program.
func NewBPFTracer() (*BPFTracer, error) {
	// Remove memlock limit for BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	return &BPFTracer{
		links:  make([]link.Link, 0),
		stopCh: make(chan struct{}),
	}, nil
}

// NewBPFTracerFromSpec creates a tracer from a collection spec (for testing).
func NewBPFTracerFromSpec(spec *ebpf.CollectionSpec) (*BPFTracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	return &BPFTracer{
		spec:   spec,
		links:  make([]link.Link, 0),
		stopCh: make(chan struct{}),
	}, nil
}

// Load loads the BPF program into the kernel.
func (t *BPFTracer) Load() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.collection != nil {
		return errors.New("tracer already loaded")
	}

	var spec *ebpf.CollectionSpec
	var err error

	if t.spec != nil {
		spec = t.spec
	} else {
		// Load embedded BPF program
		spec, err = loadBPFSpec()
		if err != nil {
			return fmt.Errorf("failed to load BPF spec: %w", err)
		}
	}

	// Load the collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to load BPF collection: %w", err)
	}

	t.collection = coll
	return nil
}

// Close unloads the BPF program and releases resources.
func (t *BPFTracer) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Stop event reading
	if t.running {
		close(t.stopCh)
		t.running = false
	}

	// Close perf reader
	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}

	// Detach all probes
	for _, l := range t.links {
		l.Close()
	}
	t.links = nil

	// Close collection
	if t.collection != nil {
		t.collection.Close()
		t.collection = nil
	}

	return nil
}

// AttachKprobes attaches kprobes for HTTP tracing via syscalls.
func (t *BPFTracer) AttachKprobes() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.collection == nil {
		return errors.New("tracer not loaded")
	}

	// Attach kprobe for sys_write
	writeProbe, ok := t.collection.Programs["kprobe_sys_write"]
	if !ok {
		return errors.New("kprobe_sys_write program not found")
	}

	writeLink, err := link.Kprobe("sys_write", writeProbe, nil)
	if err != nil {
		// Try with __x64_sys_write for newer kernels
		writeLink, err = link.Kprobe("__x64_sys_write", writeProbe, nil)
		if err != nil {
			return fmt.Errorf("failed to attach kprobe/sys_write: %w", err)
		}
	}
	t.links = append(t.links, writeLink)

	// Attach kprobe for sys_read
	readProbe, ok := t.collection.Programs["kprobe_sys_read"]
	if ok {
		readLink, err := link.Kprobe("sys_read", readProbe, nil)
		if err != nil {
			readLink, err = link.Kprobe("__x64_sys_read", readProbe, nil)
			if err != nil {
				// Non-fatal, continue without read kprobe
				fmt.Fprintf(os.Stderr, "warning: failed to attach kprobe/sys_read: %v\n", err)
			}
		}
		if readLink != nil {
			t.links = append(t.links, readLink)
		}
	}

	// Attach kretprobe for sys_read
	readRetProbe, ok := t.collection.Programs["kretprobe_sys_read"]
	if ok {
		readRetLink, err := link.Kretprobe("sys_read", readRetProbe, nil)
		if err != nil {
			readRetLink, err = link.Kretprobe("__x64_sys_read", readRetProbe, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to attach kretprobe/sys_read: %v\n", err)
			}
		}
		if readRetLink != nil {
			t.links = append(t.links, readRetLink)
		}
	}

	t.attachTime = time.Now()
	return nil
}

// AttachUprobes attaches uprobes to a TLS library.
func (t *BPFTracer) AttachUprobes(libraryPath string, mode ProbeMode) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.collection == nil {
		return errors.New("tracer not loaded")
	}

	// Validate library path
	if err := validateLibraryPath(libraryPath); err != nil {
		return fmt.Errorf("invalid library path: %w", err)
	}

	// Open the executable
	ex, err := link.OpenExecutable(libraryPath)
	if err != nil {
		return fmt.Errorf("failed to open library %s: %w", libraryPath, err)
	}

	var probeNames []struct {
		symbol  string
		program string
		isRet   bool
	}

	switch mode {
	case ProbeModeOpenSSL:
		probeNames = []struct {
			symbol  string
			program string
			isRet   bool
		}{
			{"SSL_write", "uprobe_ssl_write", false},
			{"SSL_read", "uretprobe_ssl_read", true},
		}
	case ProbeModeGnuTLS:
		probeNames = []struct {
			symbol  string
			program string
			isRet   bool
		}{
			{"gnutls_record_send", "uprobe_gnutls_send", false},
			{"gnutls_record_recv", "uretprobe_gnutls_recv", true},
		}
	case ProbeModeNSS:
		probeNames = []struct {
			symbol  string
			program string
			isRet   bool
		}{
			{"PR_Write", "uprobe_pr_write", false},
			{"PR_Read", "uretprobe_pr_read", true},
		}
	default:
		return fmt.Errorf("unsupported probe mode: %s", mode)
	}

	for _, p := range probeNames {
		prog, ok := t.collection.Programs[p.program]
		if !ok {
			return fmt.Errorf("program %s not found", p.program)
		}

		var l link.Link
		if p.isRet {
			l, err = ex.Uretprobe(p.symbol, prog, nil)
		} else {
			l, err = ex.Uprobe(p.symbol, prog, nil)
		}
		if err != nil {
			return fmt.Errorf("failed to attach uprobe %s: %w", p.symbol, err)
		}
		t.links = append(t.links, l)
	}

	t.attachTime = time.Now()
	return nil
}

// DetachAll detaches all probes.
func (t *BPFTracer) DetachAll() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, l := range t.links {
		l.Close()
	}
	t.links = make([]link.Link, 0)
	return nil
}

// Start begins reading events from the perf buffer.
func (t *BPFTracer) Start(callback EventCallback) error {
	t.mu.Lock()
	if t.collection == nil {
		t.mu.Unlock()
		return errors.New("tracer not loaded")
	}
	if t.running {
		t.mu.Unlock()
		return errors.New("tracer already running")
	}

	// Get the events map
	eventsMap, ok := t.collection.Maps["events"]
	if !ok {
		t.mu.Unlock()
		return errors.New("events map not found")
	}

	// Create perf reader
	reader, err := perf.NewReader(eventsMap, os.Getpagesize()*16)
	if err != nil {
		t.mu.Unlock()
		return fmt.Errorf("failed to create perf reader: %w", err)
	}

	t.reader = reader
	t.callback = callback
	t.running = true
	t.stopCh = make(chan struct{})
	t.mu.Unlock()

	// Start reading events in a goroutine
	go t.readEvents()

	return nil
}

// readEvents reads events from the perf buffer.
func (t *BPFTracer) readEvents() {
	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			continue
		}

		if record.LostSamples > 0 {
			t.mu.Lock()
			t.eventsDrop += record.LostSamples
			t.mu.Unlock()
			continue
		}

		// Parse the event
		event, err := parseRawEvent(record.RawSample)
		if err != nil {
			continue
		}

		t.mu.Lock()
		t.eventsRecv++
		t.lastEventTime = time.Now()
		callback := t.callback
		t.mu.Unlock()

		if callback != nil {
			callback(event)
		}
	}
}

// parseRawEvent parses a raw event from the perf buffer.
func parseRawEvent(data []byte) (*RawEvent, error) {
	if len(data) < int(unsafe.Sizeof(RawEvent{})) {
		return nil, errors.New("event data too short")
	}

	event := &RawEvent{}
	reader := bytes.NewReader(data)

	if err := binary.Read(reader, binary.LittleEndian, event); err != nil {
		return nil, fmt.Errorf("failed to parse event: %w", err)
	}

	return event, nil
}

// Stop stops reading events.
func (t *BPFTracer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return
	}

	close(t.stopCh)
	t.running = false

	if t.reader != nil {
		t.reader.Close()
	}
}

// Stats returns current probe statistics.
func (t *BPFTracer) Stats() ProbeStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return ProbeStats{
		EventsReceived: t.eventsRecv,
		EventsDropped:  t.eventsDrop,
		AttachTime:     t.attachTime,
		LastEventTime:  t.lastEventTime,
		ActiveProbes:   len(t.links),
	}
}

// SetTargetPID sets the target PID filter.
func (t *BPFTracer) SetTargetPID(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.targetPID = pid

	if t.collection != nil {
		configMap, ok := t.collection.Maps["config_map"]
		if ok {
			key := uint32(configTargetPID)
			value := uint64(pid)
			configMap.Update(key, value, ebpf.UpdateAny)
		}
	}
}

// SetMinLatency sets the minimum latency filter.
func (t *BPFTracer) SetMinLatency(latencyUs uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.minLatencyUs = latencyUs

	if t.collection != nil {
		configMap, ok := t.collection.Maps["config_map"]
		if ok {
			key := uint32(configMinLatencyUs)
			configMap.Update(key, latencyUs, ebpf.UpdateAny)
		}
	}
}

// loadBPFSpec loads the embedded BPF program specification.
// This will be generated by bpf2go.
func loadBPFSpec() (*ebpf.CollectionSpec, error) {
	// For now, return an error indicating the BPF program needs to be compiled
	// In production, this would load from embedded bytes
	return nil, errors.New("BPF program not compiled - run 'make generate' to compile")
}

// CommToString converts a comm buffer to a string.
func CommToString(comm []byte) string {
	for i, b := range comm {
		if b == 0 {
			return string(comm[:i])
		}
	}
	return string(comm)
}
