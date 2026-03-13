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
	detachCallback DetachCallback
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
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			delete(w.attached, pid)
			if w.detachCallback != nil {
				w.detachCallback(pid)
			}
		}
	}
}

// DetachCallback is called when a process exits.
type DetachCallback func(pid int)

// SetDetachCallback sets a callback for when processes exit.
func (w *TargetWatcher) SetDetachCallback(callback DetachCallback) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.detachCallback = callback
}

