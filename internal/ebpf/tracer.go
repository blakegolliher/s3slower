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
	wg sync.WaitGroup

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
	// On x86_64 kernels with CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y (>=4.17),
	// __x64_sys_write wraps the real implementation and takes a single
	// pt_regs* arg. Target ksys_write first, which takes the unwrapped
	// (fd, buf, count) args directly, matching what the BPF program expects.
	writeProbe, ok := t.collection.Programs["kprobe_sys_write"]
	if !ok {
		return errors.New("kprobe_sys_write program not found")
	}

	writeLink, err := link.Kprobe("ksys_write", writeProbe, nil)
	if err != nil {
		writeLink, err = link.Kprobe("sys_write", writeProbe, nil)
		if err != nil {
			writeLink, err = link.Kprobe("__x64_sys_write", writeProbe, nil)
			if err != nil {
				return fmt.Errorf("failed to attach kprobe/sys_write: %w", err)
			}
		}
	}
	t.links = append(t.links, writeLink)

	// Attach kprobe for sys_read (same wrapper logic)
	readProbe, ok := t.collection.Programs["kprobe_sys_read"]
	if ok {
		readLink, err := link.Kprobe("ksys_read", readProbe, nil)
		if err != nil {
			readLink, err = link.Kprobe("sys_read", readProbe, nil)
			if err != nil {
				readLink, err = link.Kprobe("__x64_sys_read", readProbe, nil)
				if err != nil {
					// Non-fatal, continue without read kprobe
					fmt.Fprintf(os.Stderr, "warning: failed to attach kprobe/sys_read: %v\n", err)
				}
			}
		}
		if readLink != nil {
			t.links = append(t.links, readLink)
		}
	}

	// Attach kretprobe for sys_read
	readRetProbe, ok := t.collection.Programs["kretprobe_sys_read"]
	if ok {
		readRetLink, err := link.Kretprobe("ksys_read", readRetProbe, nil)
		if err != nil {
			readRetLink, err = link.Kretprobe("sys_read", readRetProbe, nil)
			if err != nil {
				readRetLink, err = link.Kretprobe("__x64_sys_read", readRetProbe, nil)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to attach kretprobe/sys_read: %v\n", err)
				}
			}
		}
		if readRetLink != nil {
			t.links = append(t.links, readRetLink)
		}
	}

	// Attach kprobe for sendto (Python/urllib3 uses send()->sendto() for HTTP)
	sendtoProbe, ok := t.collection.Programs["kprobe_sys_sendto"]
	if ok {
		sendtoLink, err := link.Kprobe("__sys_sendto", sendtoProbe, nil)
		if err != nil {
			sendtoLink, err = link.Kprobe("sys_sendto", sendtoProbe, nil)
			if err != nil {
				sendtoLink, err = link.Kprobe("__x64_sys_sendto", sendtoProbe, nil)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to attach kprobe/sys_sendto: %v\n", err)
				}
			}
		}
		if sendtoLink != nil {
			t.links = append(t.links, sendtoLink)
		}
	}

	// Attach kprobe for recvfrom
	recvfromProbe, ok := t.collection.Programs["kprobe_sys_recvfrom"]
	if ok {
		recvfromLink, err := link.Kprobe("__sys_recvfrom", recvfromProbe, nil)
		if err != nil {
			recvfromLink, err = link.Kprobe("sys_recvfrom", recvfromProbe, nil)
			if err != nil {
				recvfromLink, err = link.Kprobe("__x64_sys_recvfrom", recvfromProbe, nil)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to attach kprobe/sys_recvfrom: %v\n", err)
				}
			}
		}
		if recvfromLink != nil {
			t.links = append(t.links, recvfromLink)
		}
	}

	// Attach kretprobe for recvfrom
	recvfromRetProbe, ok := t.collection.Programs["kretprobe_sys_recvfrom"]
	if ok {
		recvfromRetLink, err := link.Kretprobe("__sys_recvfrom", recvfromRetProbe, nil)
		if err != nil {
			recvfromRetLink, err = link.Kretprobe("sys_recvfrom", recvfromRetProbe, nil)
			if err != nil {
				recvfromRetLink, err = link.Kretprobe("__x64_sys_recvfrom", recvfromRetProbe, nil)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to attach kretprobe/sys_recvfrom: %v\n", err)
				}
			}
		}
		if recvfromRetLink != nil {
			t.links = append(t.links, recvfromRetLink)
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

	type uprobe struct {
		symbol   string
		program  string
		isRet    bool
		optional bool // if true, failure to attach is non-fatal
	}

	var probeNames []uprobe

	switch mode {
	case ProbeModeOpenSSL:
		probeNames = []uprobe{
			{"SSL_write", "uprobe_ssl_write", false, false},
			{"SSL_read", "uprobe_ssl_read", false, false},
			{"SSL_read", "uretprobe_ssl_read", true, false},
			// Modern OpenSSL 3.x / Python 3.10+ uses the _ex variants exclusively.
			// Same arg layout (ssl, buf, size) so the BPF programs work as-is.
			// Optional because older OpenSSL may not export these symbols.
			{"SSL_write_ex", "uprobe_ssl_write", false, true},
			{"SSL_read_ex", "uprobe_ssl_read", false, true},
			{"SSL_read_ex", "uretprobe_ssl_read", true, true},
		}
	case ProbeModeGnuTLS:
		probeNames = []uprobe{
			{"gnutls_record_send", "uprobe_gnutls_send", false, false},
			{"gnutls_record_recv", "uprobe_gnutls_recv", false, false},
			{"gnutls_record_recv", "uretprobe_gnutls_recv", true, false},
		}
	case ProbeModeNSS:
		probeNames = []uprobe{
			{"PR_Write", "uprobe_pr_write", false, false},
			{"PR_Read", "uprobe_pr_read", false, false},
			{"PR_Read", "uretprobe_pr_read", true, false},
		}
	case ProbeModeS2N:
		// s2n_send/s2n_recv have the same arg layout as SSL_write/SSL_read
		// (ctx, buf, size) so we reuse the SSL BPF programs.
		probeNames = []uprobe{
			{"s2n_send", "uprobe_ssl_write", false, false},
			{"s2n_recv", "uprobe_ssl_read", false, false},
			{"s2n_recv", "uretprobe_ssl_read", true, false},
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
			if p.optional {
				continue
			}
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
	t.wg.Add(1)
	go t.readEvents()

	return nil
}

// readEvents reads events from the perf buffer.
func (t *BPFTracer) readEvents() {
	defer t.wg.Done()
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

// Stop stops reading events and waits for the reader goroutine to exit.
func (t *BPFTracer) Stop() {
	t.mu.Lock()
	if !t.running {
		t.mu.Unlock()
		return
	}

	close(t.stopCh)
	t.running = false

	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}
	t.mu.Unlock()

	// Wait for readEvents goroutine to finish
	t.wg.Wait()
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
// This uses the generated code from bpf2go.
func loadBPFSpec() (*ebpf.CollectionSpec, error) {
	return loadBpf()
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
