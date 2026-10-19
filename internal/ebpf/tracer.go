// Package ebpf provides eBPF program loading and management for S3 traffic tracing.
package ebpf

import (
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
	execReader *perf.Reader

	links    []link.Link
	callback EventCallback
	onDrop   func(reason string, count uint64)
	running  bool
	stopCh   chan struct{}

	targetPID    uint32
	minLatencyUs uint64

	// perfBufferBytes is the per-CPU size of the events perf ring.
	// Zero means DefaultPerfBufferKB.
	perfBufferBytes int

	attachTime    time.Time
	eventsRecv    uint64
	eventsDrop    uint64
	lastEventTime time.Time
}

// DefaultPerfBufferKB is the default per-CPU size of the events perf ring.
// Each event is ~1.9 KB, so 256 KB holds ~140 in-flight events per CPU.
const DefaultPerfBufferKB = 256

// SetPerfBufferKB sets the per-CPU perf ring size used by Start. Values
// <= 0 select DefaultPerfBufferKB. The kernel rounds the size up to a
// power-of-two number of pages.
func (t *BPFTracer) SetPerfBufferKB(kb int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.perfBufferBytes = kb * 1024
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

	// Close perf readers
	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}
	if t.execReader != nil {
		t.execReader.Close()
		t.execReader = nil
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
			// SSL_write_ex has the same entry args (ssl, buf, size) so reuses the write probe.
			// SSL_read_ex returns 1/0 (not byte count) so needs dedicated probes
			// that read the actual count from the 4th param (size_t *readbytes).
			// Optional because older OpenSSL may not export these symbols.
			{"SSL_write_ex", "uprobe_ssl_write", false, true},
			{"SSL_read_ex", "uprobe_ssl_read_ex", false, true},
			{"SSL_read_ex", "uretprobe_ssl_read_ex", true, true},
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
	case ProbeModeGoTLS:
		// Analyze the binary and attach in one call.
		analysis, err := analyzeGoTLSBinary(libraryPath)
		if err != nil || !analysis.hasTLS {
			return fmt.Errorf("binary %s does not have Go TLS symbols", libraryPath)
		}
		return t.AttachGoTLSUprobes(libraryPath, analysis.offsets)
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

// AttachGoTLSUprobes attaches Go crypto/tls uprobes at pre-computed file
// offsets, so stripped binaries (no ELF symbol table) work. Uretprobes
// crash Go programs (goroutine stack copying corrupts the trampoline), so
// regular uprobes go on each RET instruction of crypto/tls.(*Conn).Read
// instead.
func (t *BPFTracer) AttachGoTLSUprobes(binaryPath string, offs GoTLSOffsets) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.collection == nil {
		return errors.New("tracer not loaded")
	}

	if err := validateLibraryPath(binaryPath); err != nil {
		return fmt.Errorf("invalid binary path: %w", err)
	}

	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to open binary %s: %w", binaryPath, err)
	}

	// Entry probes for Write and Read.
	entryProbes := []struct {
		symbol, program string
		offset          uint64
	}{
		{goTLSWrite, "uprobe_go_tls_write", offs.Write},
		{goTLSRead, "uprobe_go_tls_read", offs.Read},
	}
	for _, p := range entryProbes {
		prog, ok := t.collection.Programs[p.program]
		if !ok {
			return fmt.Errorf("program %s not found", p.program)
		}
		l, err := ex.Uprobe(p.symbol, prog, &link.UprobeOptions{Address: p.offset})
		if err != nil {
			return fmt.Errorf("failed to attach uprobe %s: %w", p.symbol, err)
		}
		t.links = append(t.links, l)
	}

	// Return probes at each RET instruction in Read.
	retProg, ok := t.collection.Programs["uretprobe_go_tls_read"]
	if !ok {
		return errors.New("uretprobe_go_tls_read program not found")
	}
	for _, ret := range offs.ReadRets {
		l, err := ex.Uprobe(goTLSRead, retProg, &link.UprobeOptions{Address: offs.Read, Offset: ret})
		if err != nil {
			continue
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
	perCPU := t.perfBufferBytes
	if perCPU <= 0 {
		perCPU = DefaultPerfBufferKB * 1024
	}
	reader, err := perf.NewReader(eventsMap, perCPU)
	if err != nil {
		t.mu.Unlock()
		return fmt.Errorf("failed to create perf reader: %w", err)
	}

	// Clean up per-thread tracking state when threads exit (non-fatal if
	// the tracepoint is unavailable; the LRU maps still bound the state).
	if prog, ok := t.collection.Programs["tracepoint_exit"]; ok {
		if tp, err := link.Tracepoint("sched", "sched_process_exit", prog, nil); err != nil {
			fmt.Fprintf(os.Stderr, "warning: thread-exit cleanup unavailable: %v\n", err)
		} else {
			t.links = append(t.links, tp)
		}
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

// readEvents reads events from the perf buffer until the reader is closed.
// reader.Read blocks; closing it during Stop() is what unblocks the call
// and returns perf.ErrClosed, so shutdown exits cleanly. Any other error
// logs once and backs off briefly so a wedged ring can't busy-spin a CPU.
func (t *BPFTracer) readEvents() {
	defer t.wg.Done()
	const readErrBackoff = 100 * time.Millisecond

	// ReadInto reuses one sample buffer; parseRawEvent copies out of it.
	var record perf.Record
	for {
		err := t.reader.ReadInto(&record)
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "perf read error: %v\n", err)
			select {
			case <-t.stopCh:
				return
			case <-time.After(readErrBackoff):
			}
			continue
		}

		if record.LostSamples > 0 {
			t.mu.Lock()
			t.eventsDrop += record.LostSamples
			cb := t.onDrop
			t.mu.Unlock()
			if cb != nil {
				cb("perf_lost", record.LostSamples)
			}
			continue
		}

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

// rawEventWireSize is the number of meaningful bytes in a perf sample:
// struct event_t up to the end of early_resp (the C struct's tail padding
// is not needed).
var rawEventWireSize = int(unsafe.Offsetof(RawEvent{}.EarlyResp)) + len(RawEvent{}.EarlyResp)

// parseRawEvent decodes a perf sample into a RawEvent. It reads fields at
// their fixed offsets rather than via binary.Read, whose per-element
// reflection over the 1.8 KB payload cost ~25µs per event on the
// perf-reader goroutine and caused ring overflows at around 13k requests
// per second.
func parseRawEvent(data []byte) (*RawEvent, error) {
	if len(data) < rawEventWireSize {
		return nil, errors.New("event data too short")
	}

	var e RawEvent
	le := binary.LittleEndian
	e.TimestampUs = le.Uint64(data[unsafe.Offsetof(e.TimestampUs):])
	e.LatencyUs = le.Uint64(data[unsafe.Offsetof(e.LatencyUs):])
	e.PID = le.Uint32(data[unsafe.Offsetof(e.PID):])
	e.TID = le.Uint32(data[unsafe.Offsetof(e.TID):])
	e.FD = le.Uint32(data[unsafe.Offsetof(e.FD):])
	copy(e.Comm[:], data[unsafe.Offsetof(e.Comm):])
	e.ReqSize = le.Uint32(data[unsafe.Offsetof(e.ReqSize):])
	e.RespSize = le.Uint32(data[unsafe.Offsetof(e.RespSize):])
	e.ActualRespBytes = le.Uint32(data[unsafe.Offsetof(e.ActualRespBytes):])
	e.IsPartial = data[unsafe.Offsetof(e.IsPartial)]
	e.ClientType = data[unsafe.Offsetof(e.ClientType)]
	e.EarlyLen = data[unsafe.Offsetof(e.EarlyLen)]
	copy(e.Data[:], data[unsafe.Offsetof(e.Data):])
	copy(e.RespData[:], data[unsafe.Offsetof(e.RespData):])
	copy(e.EarlyResp[:], data[unsafe.Offsetof(e.EarlyResp):])
	return &e, nil
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
	if t.execReader != nil {
		t.execReader.Close()
		t.execReader = nil
	}
	t.mu.Unlock()

	// Wait for reader goroutines to finish
	t.wg.Wait()
}

// WatchExec attaches a tracepoint on sched_process_exec and calls the
// callback with the PID of each newly exec'd process. This lets the
// pipeline discover Go TLS binaries the instant they start.
func (t *BPFTracer) WatchExec(callback func(pid uint32)) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.collection == nil {
		return errors.New("tracer not loaded")
	}

	prog, ok := t.collection.Programs["tracepoint_exec"]
	if !ok {
		return errors.New("tracepoint_exec program not found")
	}

	execMap, ok := t.collection.Maps["exec_events"]
	if !ok {
		return errors.New("exec_events map not found")
	}

	tp, err := link.Tracepoint("sched", "sched_process_exec", prog, nil)
	if err != nil {
		return fmt.Errorf("failed to attach exec tracepoint: %w", err)
	}
	t.links = append(t.links, tp)

	reader, err := perf.NewReader(execMap, os.Getpagesize()*4)
	if err != nil {
		return fmt.Errorf("failed to create exec perf reader: %w", err)
	}
	t.execReader = reader

	t.wg.Add(1)
	go t.readExecEvents(reader, callback)

	return nil
}

// readExecEvents reads exec notifications from the perf buffer. Same
// shutdown model as readEvents — Close() on the reader returns
// perf.ErrClosed and exits the loop cleanly. Non-close errors log once
// and back off so a wedged ring can't busy-spin a CPU.
func (t *BPFTracer) readExecEvents(reader *perf.Reader, callback func(pid uint32)) {
	defer t.wg.Done()
	const readErrBackoff = 100 * time.Millisecond

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "exec perf read error: %v\n", err)
			select {
			case <-t.stopCh:
				return
			case <-time.After(readErrBackoff):
			}
			continue
		}

		if len(record.RawSample) < 4 {
			continue
		}

		pid := binary.LittleEndian.Uint32(record.RawSample[:4])
		callback(pid)
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

// SetDropCallback registers a callback invoked on every perf-ring loss.
func (t *BPFTracer) SetDropCallback(cb func(reason string, count uint64)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onDrop = cb
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

// commToString converts a null-terminated comm buffer to a string.
func commToString(comm []byte) string {
	for i, b := range comm {
		if b == 0 {
			return string(comm[:i])
		}
	}
	return string(comm)
}
