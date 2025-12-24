// Package config handles YAML configuration loading and validation.
package config

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// MatchType represents the type of process matching.
type MatchType string

const (
	MatchTypeComm             MatchType = "comm"
	MatchTypeExeBasename      MatchType = "exe_basename"
	MatchTypeCmdlineSubstring MatchType = "cmdline_substring"
)

// ValidMatchTypes is the set of valid match types.
var ValidMatchTypes = map[MatchType]bool{
	MatchTypeComm:             true,
	MatchTypeExeBasename:      true,
	MatchTypeCmdlineSubstring: true,
}

// ValidateMatchType checks if a match type is valid.
func ValidateMatchType(mt string) bool {
	return ValidMatchTypes[MatchType(mt)]
}

// ProbeMode represents the TLS library probe mode.
type ProbeMode string

const (
	ProbeModeAuto    ProbeMode = "auto"
	ProbeModeOpenSSL ProbeMode = "openssl"
	ProbeModeGnuTLS  ProbeMode = "gnutls"
	ProbeModeNSS     ProbeMode = "nss"
	ProbeModeHTTP    ProbeMode = "http"
)

// TargetConfig represents a single target configuration.
type TargetConfig struct {
	ID         string            `yaml:"id"`
	MatchType  MatchType         `yaml:"-"`
	MatchValue string            `yaml:"-"`
	Mode       ProbeMode         `yaml:"mode"`
	PromLabels map[string]string `yaml:"prom_labels,omitempty"`
}

// targetConfigYAML is the YAML representation of a target.
type targetConfigYAML struct {
	ID    string `yaml:"id"`
	Match struct {
		Type  string `yaml:"type"`
		Value string `yaml:"value"`
	} `yaml:"match"`
	Mode       string            `yaml:"mode"`
	PromLabels map[string]string `yaml:"prom_labels,omitempty"`
}

// targetsFileYAML is the YAML representation of a targets file.
type targetsFileYAML struct {
	Targets []targetConfigYAML `yaml:"targets"`
}

// LoadTargets loads target configurations from a YAML file.
func LoadTargets(path string) ([]TargetConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("empty config path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var file targetsFileYAML
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Handle case where file is not a proper structure
	if file.Targets == nil {
		// Try to see if it's a list at root level
		var raw interface{}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}

		// If it's a slice, it's invalid
		if _, ok := raw.([]interface{}); ok {
			return nil, fmt.Errorf("invalid config: expected object with 'targets' key, got list")
		}

		// If it's a map without targets key
		if m, ok := raw.(map[string]interface{}); ok {
			if _, hasTargets := m["targets"]; !hasTargets {
				return nil, fmt.Errorf("invalid config: missing 'targets' key")
			}
		}
	}

	targets := make([]TargetConfig, 0, len(file.Targets))
	for i, t := range file.Targets {
		if t.ID == "" {
			return nil, fmt.Errorf("target %d: missing 'id'", i)
		}

		if t.Match.Type == "" || t.Match.Value == "" {
			return nil, fmt.Errorf("target %s: missing 'match.type' or 'match.value'", t.ID)
		}

		if !ValidateMatchType(t.Match.Type) {
			return nil, fmt.Errorf("target %s: invalid match type '%s'", t.ID, t.Match.Type)
		}

		if t.Mode == "" {
			return nil, fmt.Errorf("target %s: missing 'mode'", t.ID)
		}

		// Convert label values to strings
		promLabels := make(map[string]string)
		for k, v := range t.PromLabels {
			promLabels[k] = fmt.Sprintf("%v", v)
		}

		targets = append(targets, TargetConfig{
			ID:         t.ID,
			MatchType:  MatchType(t.Match.Type),
			MatchValue: t.Match.Value,
			Mode:       ProbeMode(t.Mode),
			PromLabels: promLabels,
		})
	}

	return targets, nil
}

// CollectExtraLabelKeys collects all unique label keys from targets.
func CollectExtraLabelKeys(targets []TargetConfig) []string {
	keys := make(map[string]bool)
	for _, t := range targets {
		for k := range t.PromLabels {
			keys[k] = true
		}
	}

	result := make([]string, 0, len(keys))
	for k := range keys {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

// AppConfig represents the main application configuration.
type AppConfig struct {
	Interval     int              `yaml:"interval"`
	MinLatencyMs int              `yaml:"min_latency_ms"`
	PID          int              `yaml:"pid,omitempty"`
	Debug        bool             `yaml:"debug"`
	Prometheus   PrometheusConfig `yaml:"prometheus"`
	Screen       ScreenConfig     `yaml:"screen"`
}

// PrometheusConfig holds Prometheus exporter settings.
type PrometheusConfig struct {
	Host       string `yaml:"prom_exporter_host"`
	Port       int    `yaml:"prom_exporter_port"`
	BufferSize int    `yaml:"buffer_size"`
}

// ScreenConfig holds screen output settings.
type ScreenConfig struct {
	TableFormat  bool `yaml:"table_format"`
	MaxURLLength int  `yaml:"max_url_length"`
}

// LoadAppConfig loads application configuration from a YAML file.
func LoadAppConfig(path string) (*AppConfig, error) {
	if path == "" {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return config, nil
}

// DefaultConfig returns the default application configuration.
func DefaultConfig() *AppConfig {
	return &AppConfig{
		Interval:     5,
		MinLatencyMs: 0,
		Debug:        false,
		Prometheus: PrometheusConfig{
			Host:       "::",
			Port:       9000,
			BufferSize: 1000,
		},
		Screen: ScreenConfig{
			TableFormat:  true,
			MaxURLLength: 50,
		},
	}
}
