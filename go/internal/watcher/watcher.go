// Package watcher provides process watching and target matching functionality.
package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/s3slower/s3slower/internal/config"
)

// ReadExeBasename reads the executable basename for a given PID.
// Returns empty string and error if the process doesn't exist or is inaccessible.
func ReadExeBasename(pid int) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(exePath)
	if err != nil {
		return "", err
	}
	return filepath.Base(target), nil
}

// ReadCmdline reads the command line for a given PID.
// Returns empty string and error if the process doesn't exist or is inaccessible.
func ReadCmdline(pid int) (string, error) {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return "", err
	}

	// Replace null bytes with spaces
	result := strings.Builder{}
	for _, b := range data {
		if b == 0 {
			result.WriteByte(' ')
		} else {
			result.WriteByte(b)
		}
	}

	return result.String(), nil
}

// ClassifyPID determines if a PID matches any target configuration.
// Returns the matching target or nil if no match.
func ClassifyPID(pid int, comm string, targets []config.TargetConfig) *config.TargetConfig {
	for i := range targets {
		target := &targets[i]

		switch target.MatchType {
		case config.MatchTypeComm:
			if comm == target.MatchValue {
				return target
			}

		case config.MatchTypeExeBasename:
			// First try exact comm match
			if comm == target.MatchValue {
				return target
			}
			// Then try exe basename
			exe, err := ReadExeBasename(pid)
			if err == nil && exe == target.MatchValue {
				return target
			}

		case config.MatchTypeCmdlineSubstring:
			cmdline, err := ReadCmdline(pid)
			if err == nil && strings.Contains(cmdline, target.MatchValue) {
				return target
			}
		}
	}

	return nil
}

// AttachCallback is called when a matching process is found.
type AttachCallback func(pid int, comm string, target *config.TargetConfig)

// TargetWatcher monitors for new processes matching target configurations.
type TargetWatcher struct {
	targets        []config.TargetConfig
	attachCallback AttachCallback
	attached       map[int]bool
	mu             sync.RWMutex
	running        bool
	stopCh         chan struct{}
}

// NewTargetWatcher creates a new TargetWatcher.
func NewTargetWatcher(targets []config.TargetConfig, callback AttachCallback) *TargetWatcher {
	return &TargetWatcher{
		targets:        targets,
		attachCallback: callback,
		attached:       make(map[int]bool),
		stopCh:         make(chan struct{}),
	}
}

// Start begins watching for matching processes.
func (w *TargetWatcher) Start() error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}

	w.running = true
	w.stopCh = make(chan struct{})
	w.mu.Unlock()

	// Do an initial scan
	w.scanProcesses()

	// Start background scanner
	go w.runScanner()

	return nil
}

// runScanner periodically scans /proc for new processes.
func (w *TargetWatcher) runScanner() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.scanProcesses()
		}
	}
}

// scanProcesses scans /proc for processes matching targets.
func (w *TargetWatcher) scanProcesses() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID (numeric)
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Read comm (process name)
		comm, err := w.readComm(pid)
		if err != nil {
			continue
		}

		// Check if this process matches any target
		w.OnExec(pid, comm)
	}
}

// readComm reads the comm (process name) for a PID.
func (w *TargetWatcher) readComm(pid int) (string, error) {
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(commPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// Stop stops the watcher.
func (w *TargetWatcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return
	}

	w.running = false
	close(w.stopCh)
}

// IsAttached returns whether a PID is already attached.
func (w *TargetWatcher) IsAttached(pid int) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.attached[pid]
}

// OnExec handles an exec event for a new process.
func (w *TargetWatcher) OnExec(pid int, comm string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Skip if already attached
	if w.attached[pid] {
		return
	}

	// Try to match against targets
	target := ClassifyPID(pid, comm, w.targets)
	if target == nil {
		return
	}

	// Mark as attached and call callback
	w.attached[pid] = true
	if w.attachCallback != nil {
		w.attachCallback(pid, comm, target)
	}
}

// GetAttached returns a copy of attached PIDs.
func (w *TargetWatcher) GetAttached() map[int]bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make(map[int]bool, len(w.attached))
	for k, v := range w.attached {
		result[k] = v
	}
	return result
}

// UpdateTargets updates the target configurations (for hot-reload).
func (w *TargetWatcher) UpdateTargets(targets []config.TargetConfig) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.targets = targets
}

// CleanupExited removes PIDs that no longer exist.
func (w *TargetWatcher) CleanupExited() {
	w.mu.Lock()
	defer w.mu.Unlock()

	for pid := range w.attached {
		// Check if process still exists
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			delete(w.attached, pid)
		}
	}
}

// DetachCallback is called when a process exits.
type DetachCallback func(pid int)

// SetDetachCallback sets a callback for when processes exit.
func (w *TargetWatcher) SetDetachCallback(callback DetachCallback) {
	// Could be implemented if needed for cleanup
}

// KnownS3Clients lists known S3 client process names.
var KnownS3Clients = []string{
	"aws",      // AWS CLI
	"python",   // boto3
	"python3",  // boto3
	"curl",     // curl
	"mc",       // MinIO client
	"warp",     // MinIO warp benchmark
	"elbencho", // Elbencho benchmark
	"s3cmd",    // s3cmd
}

// IsKnownS3Client checks if a process name is a known S3 client.
func IsKnownS3Client(comm string) bool {
	for _, known := range KnownS3Clients {
		if comm == known {
			return true
		}
	}
	return false
}

// ClientType represents a detected client type.
type ClientType int

const (
	ClientUnknown  ClientType = 0
	ClientWarp     ClientType = 1
	ClientElbencho ClientType = 2
	ClientBoto3    ClientType = 3
	ClientS3cmd    ClientType = 4
	ClientAWSCLI   ClientType = 5
	ClientMC       ClientType = 6
	ClientCurl     ClientType = 7
)

// DetectClientType determines the client type from process name.
func DetectClientType(comm string) ClientType {
	switch comm {
	case "warp":
		return ClientWarp
	case "elbencho":
		return ClientElbencho
	case "python", "python3":
		return ClientBoto3 // Assume Python is boto3
	case "s3cmd":
		return ClientS3cmd
	case "aws":
		return ClientAWSCLI
	case "mc":
		return ClientMC
	case "curl":
		return ClientCurl
	default:
		return ClientUnknown
	}
}

// ClientTypeName returns a human-readable name for the client type.
func ClientTypeName(ct ClientType) string {
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
		return "aws-cli"
	case ClientMC:
		return "mc"
	case ClientCurl:
		return "curl"
	default:
		return "unknown"
	}
}
