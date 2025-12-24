// Package ebpf provides eBPF program loading and management for S3 traffic tracing.
package ebpf

import (
	"errors"
	"sync"
	"time"
)

// MockTracer is a mock implementation of the Tracer interface for testing.
type MockTracer struct {
	mu sync.RWMutex

	loaded     bool
	running    bool
	targetPID  uint32
	minLatency uint64
	probes     []string
	callback   EventCallback
	loadErr    error
	uprobeErr  error

	attachTime    time.Time
	eventsRecv    uint64
	eventsDrop    uint64
	lastEventTime time.Time
}

// NewMockTracer creates a new mock tracer.
func NewMockTracer() *MockTracer {
	return &MockTracer{
		probes: make([]string, 0),
	}
}

// Load loads the mock BPF program.
func (m *MockTracer) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.loadErr != nil {
		return m.loadErr
	}

	m.loaded = true
	return nil
}

// Close unloads the mock BPF program.
func (m *MockTracer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.loaded = false
	m.running = false
	m.probes = make([]string, 0)
	return nil
}

// AttachKprobes attaches mock kprobes.
func (m *MockTracer) AttachKprobes() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.loaded {
		return errors.New("tracer not loaded")
	}

	m.probes = append(m.probes, "sys_read", "sys_write")
	m.attachTime = time.Now()
	return nil
}

// AttachUprobes attaches mock uprobes.
func (m *MockTracer) AttachUprobes(libraryPath string, mode ProbeMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.loaded {
		return errors.New("tracer not loaded")
	}

	if m.uprobeErr != nil {
		return m.uprobeErr
	}

	switch mode {
	case ProbeModeOpenSSL:
		m.probes = append(m.probes, "SSL_read", "SSL_write")
	case ProbeModeGnuTLS:
		m.probes = append(m.probes, "gnutls_record_recv", "gnutls_record_send")
	case ProbeModeNSS:
		m.probes = append(m.probes, "PR_Read", "PR_Write")
	}

	m.attachTime = time.Now()
	return nil
}

// DetachAll detaches all mock probes.
func (m *MockTracer) DetachAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.probes = make([]string, 0)
	return nil
}

// Start starts the mock event loop.
func (m *MockTracer) Start(callback EventCallback) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.running = true
	m.callback = callback
	return nil
}

// Stop stops the mock event loop.
func (m *MockTracer) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.running = false
	m.callback = nil
}

// Stats returns mock probe statistics.
func (m *MockTracer) Stats() ProbeStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return ProbeStats{
		EventsReceived: m.eventsRecv,
		EventsDropped:  m.eventsDrop,
		AttachTime:     m.attachTime,
		LastEventTime:  m.lastEventTime,
		ActiveProbes:   len(m.probes),
	}
}

// SetTargetPID sets the target PID filter.
func (m *MockTracer) SetTargetPID(pid uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.targetPID = pid
}

// SetMinLatency sets the minimum latency filter.
func (m *MockTracer) SetMinLatency(latencyUs uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.minLatency = latencyUs
}

// IsLoaded returns whether the tracer is loaded.
func (m *MockTracer) IsLoaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.loaded
}

// TargetPID returns the target PID.
func (m *MockTracer) TargetPID() uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.targetPID
}

// MinLatency returns the minimum latency.
func (m *MockTracer) MinLatency() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.minLatency
}

// AttachedProbes returns the list of attached probes.
func (m *MockTracer) AttachedProbes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, len(m.probes))
	copy(result, m.probes)
	return result
}

// InjectEvent injects a mock event into the callback.
func (m *MockTracer) InjectEvent(event *RawEvent) {
	m.mu.RLock()
	running := m.running
	callback := m.callback
	targetPID := m.targetPID
	minLatency := m.minLatency
	m.mu.RUnlock()

	if !running || callback == nil {
		return
	}

	// Apply PID filter
	if targetPID != 0 && event.PID != targetPID {
		return
	}

	// Apply latency filter
	if event.LatencyUs < minLatency {
		return
	}

	m.mu.Lock()
	m.eventsRecv++
	m.lastEventTime = time.Now()
	m.mu.Unlock()

	callback(event)
}

// SetLoadError sets an error to return from Load.
func (m *MockTracer) SetLoadError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.loadErr = err
}

// SetUprobeError sets an error to return from AttachUprobes.
func (m *MockTracer) SetUprobeError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.uprobeErr = err
}

// MockLibraryFinder is a mock implementation of LibraryFinder.
type MockLibraryFinder struct {
	mu sync.RWMutex

	opensslPath string
	opensslErr  error
	gnutlsPath  string
	gnutlsErr   error
	nssPath     string
	nssErr      error
}

// NewMockLibraryFinder creates a new mock library finder.
func NewMockLibraryFinder() *MockLibraryFinder {
	return &MockLibraryFinder{}
}

// FindOpenSSL returns the mock OpenSSL path.
func (m *MockLibraryFinder) FindOpenSSL() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.opensslErr != nil {
		return "", m.opensslErr
	}
	return m.opensslPath, nil
}

// FindGnuTLS returns the mock GnuTLS path.
func (m *MockLibraryFinder) FindGnuTLS() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.gnutlsErr != nil {
		return "", m.gnutlsErr
	}
	return m.gnutlsPath, nil
}

// FindNSS returns the mock NSS path.
func (m *MockLibraryFinder) FindNSS() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.nssErr != nil {
		return "", m.nssErr
	}
	return m.nssPath, nil
}

// FindAll returns all mock libraries.
func (m *MockLibraryFinder) FindAll() map[ProbeMode]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[ProbeMode]string)

	if m.opensslErr == nil && m.opensslPath != "" {
		result[ProbeModeOpenSSL] = m.opensslPath
	}
	if m.gnutlsErr == nil && m.gnutlsPath != "" {
		result[ProbeModeGnuTLS] = m.gnutlsPath
	}
	if m.nssErr == nil && m.nssPath != "" {
		result[ProbeModeNSS] = m.nssPath
	}

	return result
}

// SetOpenSSLPath sets the mock OpenSSL path.
func (m *MockLibraryFinder) SetOpenSSLPath(path string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.opensslPath = path
	m.opensslErr = err
}

// SetGnuTLSPath sets the mock GnuTLS path.
func (m *MockLibraryFinder) SetGnuTLSPath(path string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.gnutlsPath = path
	m.gnutlsErr = err
}

// SetNSSPath sets the mock NSS path.
func (m *MockLibraryFinder) SetNSSPath(path string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nssPath = path
	m.nssErr = err
}
