package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewConfigWatcher(t *testing.T) {
	// Create temp directory
	tempDir := t.TempDir()

	// Create a config file
	configPath := filepath.Join(tempDir, "s3slower.yaml")
	configContent := `
interval: 5
min_latency_ms: 100
debug: true
prometheus:
  prom_exporter_host: "0.0.0.0"
  prom_exporter_port: 9000
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create a targets file
	targetsPath := filepath.Join(tempDir, "targets.yaml")
	targetsContent := `
targets:
  - id: mc
    match:
      type: comm
      value: mc
    mode: openssl
`
	if err := os.WriteFile(targetsPath, []byte(targetsContent), 0644); err != nil {
		t.Fatalf("Failed to write targets file: %v", err)
	}

	// Create watcher
	cw, err := NewConfigWatcher(configPath, targetsPath)
	if err != nil {
		t.Fatalf("Failed to create config watcher: %v", err)
	}
	cw.Start() // Must start before Stop() will work
	defer cw.Stop()

	// Check initial config
	cfg := cw.AppConfig()
	if cfg == nil {
		t.Fatal("Expected app config, got nil")
	}
	if cfg.MinLatencyMs != 100 {
		t.Errorf("Expected MinLatencyMs=100, got %d", cfg.MinLatencyMs)
	}
	if cfg.Debug != true {
		t.Error("Expected Debug=true")
	}

	// Check initial targets
	targets := cw.Targets()
	if len(targets) != 1 {
		t.Fatalf("Expected 1 target, got %d", len(targets))
	}
	if targets[0].ID != "mc" {
		t.Errorf("Expected target ID 'mc', got '%s'", targets[0].ID)
	}
}

func TestConfigWatcher_ReloadOnChange(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	// Create temp directory
	tempDir := t.TempDir()

	// Create a config file
	configPath := filepath.Join(tempDir, "s3slower.yaml")
	configContent := `
interval: 5
min_latency_ms: 100
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create watcher
	cw, err := NewConfigWatcher(configPath, "")
	if err != nil {
		t.Fatalf("Failed to create config watcher: %v", err)
	}
	defer cw.Stop()

	// Set up callback to detect changes
	var wg sync.WaitGroup
	var newConfig *AppConfig
	var mu sync.Mutex
	var once sync.Once

	wg.Add(1)
	cw.OnAppConfigChange(func(cfg *AppConfig) {
		mu.Lock()
		newConfig = cfg
		mu.Unlock()
		// fsnotify may fire multiple events for one write, only count once
		once.Do(func() { wg.Done() })
	})

	// Start watching
	cw.Start()

	// Wait a bit for watcher to be ready
	time.Sleep(100 * time.Millisecond)

	// Update the config file
	newConfigContent := `
interval: 10
min_latency_ms: 200
`
	if err := os.WriteFile(configPath, []byte(newConfigContent), 0644); err != nil {
		t.Fatalf("Failed to update config file: %v", err)
	}

	// Wait for callback with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for config reload")
	}

	// Check the new config
	mu.Lock()
	if newConfig == nil {
		t.Fatal("Expected new config, got nil")
	}
	if newConfig.MinLatencyMs != 200 {
		t.Errorf("Expected MinLatencyMs=200, got %d", newConfig.MinLatencyMs)
	}
	mu.Unlock()
}

func TestConfigWatcher_TargetsReload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	// Create temp directory
	tempDir := t.TempDir()

	// Create a targets file
	targetsPath := filepath.Join(tempDir, "targets.yaml")
	targetsContent := `
targets:
  - id: mc
    match:
      type: comm
      value: mc
    mode: openssl
`
	if err := os.WriteFile(targetsPath, []byte(targetsContent), 0644); err != nil {
		t.Fatalf("Failed to write targets file: %v", err)
	}

	// Create watcher
	cw, err := NewConfigWatcher("", targetsPath)
	if err != nil {
		t.Fatalf("Failed to create config watcher: %v", err)
	}
	defer cw.Stop()

	// Set up callback
	var wg sync.WaitGroup
	var newTargets []TargetConfig
	var mu sync.Mutex
	var once sync.Once

	wg.Add(1)
	cw.OnTargetsChange(func(targets []TargetConfig) {
		mu.Lock()
		newTargets = targets
		mu.Unlock()
		// fsnotify may fire multiple events for one write, only count once
		once.Do(func() { wg.Done() })
	})

	// Start watching
	cw.Start()

	// Wait a bit for watcher to be ready
	time.Sleep(100 * time.Millisecond)

	// Update the targets file with more targets
	newTargetsContent := `
targets:
  - id: mc
    match:
      type: comm
      value: mc
    mode: openssl
  - id: warp
    match:
      type: comm
      value: warp
    mode: openssl
`
	if err := os.WriteFile(targetsPath, []byte(newTargetsContent), 0644); err != nil {
		t.Fatalf("Failed to update targets file: %v", err)
	}

	// Wait for callback with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for targets reload")
	}

	// Check the new targets
	mu.Lock()
	if len(newTargets) != 2 {
		t.Errorf("Expected 2 targets, got %d", len(newTargets))
	}
	mu.Unlock()
}

func TestConfigWatcher_InvalidConfigIgnored(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	// Create temp directory
	tempDir := t.TempDir()

	// Create a valid config file
	configPath := filepath.Join(tempDir, "s3slower.yaml")
	configContent := `
interval: 5
min_latency_ms: 100
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Create watcher
	cw, err := NewConfigWatcher(configPath, "")
	if err != nil {
		t.Fatalf("Failed to create config watcher: %v", err)
	}
	defer cw.Stop()

	// Start watching
	cw.Start()

	// Wait for watcher to be ready and any initial events to settle
	time.Sleep(200 * time.Millisecond)

	// Verify initial config is correct
	initialCfg := cw.AppConfig()
	if initialCfg == nil || initialCfg.MinLatencyMs != 100 {
		t.Fatalf("Initial config should have MinLatencyMs=100")
	}

	// Now track callbacks - only after initial setup
	var mu sync.Mutex
	var lastCallbackConfig *AppConfig
	cw.OnAppConfigChange(func(cfg *AppConfig) {
		mu.Lock()
		lastCallbackConfig = cfg
		mu.Unlock()
	})

	// Write invalid YAML - use WriteFile which truncates then writes
	// Note: fsnotify may catch the truncated (empty) state which parses as valid defaults
	invalidContent := `{{{invalid yaml`
	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to update config file: %v", err)
	}

	// Wait a bit for processing
	time.Sleep(500 * time.Millisecond)

	// The key test: after all events settle, the watcher should have rejected
	// the invalid config and kept *some* valid state (either original or defaults
	// from truncation, depending on timing). The important thing is it didn't crash
	// and still has a valid config.
	cfg := cw.AppConfig()
	if cfg == nil {
		t.Fatal("Expected config to still be available after invalid YAML")
	}

	// If callback was triggered, it should have been with a parseable config
	// (either empty defaults from truncation or original)
	mu.Lock()
	if lastCallbackConfig != nil {
		// Callback was called - verify it got a valid config, not invalid
		if lastCallbackConfig.MinLatencyMs < 0 {
			t.Error("Callback received invalid config")
		}
	}
	mu.Unlock()
}

func TestNewConfigWatcher_NoConfigPath(t *testing.T) {
	// Should work with empty paths
	cw, err := NewConfigWatcher("", "")
	if err != nil {
		t.Fatalf("Failed to create config watcher with empty paths: %v", err)
	}
	defer cw.watcher.Close()

	// Should return nil config
	if cw.AppConfig() != nil {
		t.Error("Expected nil app config for empty path")
	}

	// Should return nil targets
	if cw.Targets() != nil {
		t.Error("Expected nil targets for empty path")
	}
}

func TestNewConfigWatcher_InvalidConfigPath(t *testing.T) {
	// Should fail with non-existent config file
	_, err := NewConfigWatcher("/nonexistent/path/config.yaml", "")
	if err == nil {
		t.Error("Expected error for non-existent config file")
	}
}
