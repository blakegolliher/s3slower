// Package config handles YAML configuration loading and validation.
package config

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// ConfigWatcher watches configuration files for changes and reloads them.
type ConfigWatcher struct {
	watcher     *fsnotify.Watcher
	configPath  string
	targetsPath string

	mu         sync.RWMutex
	appConfig  *AppConfig
	targets    []TargetConfig

	// Callback functions for when config changes
	onAppConfigChange func(*AppConfig)
	onTargetsChange   func([]TargetConfig)

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewConfigWatcher creates a new config watcher.
func NewConfigWatcher(configPath, targetsPath string) (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	cw := &ConfigWatcher{
		watcher:     watcher,
		configPath:  configPath,
		targetsPath: targetsPath,
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}

	// Load initial configs
	if configPath != "" {
		cfg, err := LoadAppConfig(configPath)
		if err != nil {
			watcher.Close()
			return nil, fmt.Errorf("failed to load app config: %w", err)
		}
		cw.appConfig = cfg

		// Watch the config file's directory
		dir := filepath.Dir(configPath)
		if err := watcher.Add(dir); err != nil {
			watcher.Close()
			return nil, fmt.Errorf("failed to watch config directory %s: %w", dir, err)
		}
	}

	if targetsPath != "" {
		targets, err := LoadTargets(targetsPath)
		if err != nil {
			watcher.Close()
			return nil, fmt.Errorf("failed to load targets: %w", err)
		}
		cw.targets = targets

		// Watch the targets file's directory (may be same as config dir)
		dir := filepath.Dir(targetsPath)
		if err := watcher.Add(dir); err != nil {
			// Ignore if already watching
			if err.Error() != "can't watch non-existent file" {
				// Try to add anyway, may already be watching
			}
		}
	}

	return cw, nil
}

// Start begins watching for file changes.
func (cw *ConfigWatcher) Start() {
	go cw.watch()
}

// Stop stops the watcher.
func (cw *ConfigWatcher) Stop() {
	close(cw.stopCh)
	<-cw.doneCh
	cw.watcher.Close()
}

// AppConfig returns the current app configuration.
func (cw *ConfigWatcher) AppConfig() *AppConfig {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	return cw.appConfig
}

// Targets returns the current target configurations.
func (cw *ConfigWatcher) Targets() []TargetConfig {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	return cw.targets
}

// OnAppConfigChange sets a callback for when the app config changes.
func (cw *ConfigWatcher) OnAppConfigChange(fn func(*AppConfig)) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.onAppConfigChange = fn
}

// OnTargetsChange sets a callback for when the targets config changes.
func (cw *ConfigWatcher) OnTargetsChange(fn func([]TargetConfig)) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.onTargetsChange = fn
}

// watch handles file system events.
func (cw *ConfigWatcher) watch() {
	defer close(cw.doneCh)

	for {
		select {
		case <-cw.stopCh:
			return

		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}

			// Check if this is a write or create event
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			absPath, _ := filepath.Abs(event.Name)
			configAbs, _ := filepath.Abs(cw.configPath)
			targetsAbs, _ := filepath.Abs(cw.targetsPath)

			// Check if the changed file is one we care about
			if absPath == configAbs {
				cw.reloadAppConfig()
			} else if absPath == targetsAbs {
				cw.reloadTargets()
			}

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			// Log error but continue watching
			fmt.Printf("Config watcher error: %v\n", err)
		}
	}
}

// reloadAppConfig reloads the application configuration.
func (cw *ConfigWatcher) reloadAppConfig() {
	if cw.configPath == "" {
		return
	}

	cfg, err := LoadAppConfig(cw.configPath)
	if err != nil {
		fmt.Printf("Failed to reload app config: %v\n", err)
		return
	}

	cw.mu.Lock()
	cw.appConfig = cfg
	callback := cw.onAppConfigChange
	cw.mu.Unlock()

	fmt.Printf("Reloaded app config from %s\n", cw.configPath)

	if callback != nil {
		callback(cfg)
	}
}

// reloadTargets reloads the targets configuration.
func (cw *ConfigWatcher) reloadTargets() {
	if cw.targetsPath == "" {
		return
	}

	targets, err := LoadTargets(cw.targetsPath)
	if err != nil {
		fmt.Printf("Failed to reload targets config: %v\n", err)
		return
	}

	cw.mu.Lock()
	cw.targets = targets
	callback := cw.onTargetsChange
	cw.mu.Unlock()

	fmt.Printf("Reloaded %d targets from %s\n", len(targets), cw.targetsPath)

	if callback != nil {
		callback(targets)
	}
}
