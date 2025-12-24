// Package config provides configuration loading and validation.
package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateMatchType tests the ValidateMatchType function.
func TestValidateMatchType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid match types
		{name: "valid_comm", input: "comm", expected: true},
		{name: "valid_exe_basename", input: "exe_basename", expected: true},
		{name: "valid_cmdline_substring", input: "cmdline_substring", expected: true},

		// Invalid match types
		{name: "invalid_type", input: "invalid", expected: false},
		{name: "empty_string", input: "", expected: false},
		{name: "case_sensitive_COMM", input: "COMM", expected: false},
		{name: "case_sensitive_Comm", input: "Comm", expected: false},
		{name: "partial_match", input: "com", expected: false},
		{name: "whitespace", input: " comm ", expected: false},
		{name: "typo", input: "comn", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateMatchType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestTargetConfig tests the TargetConfig struct.
func TestTargetConfig(t *testing.T) {
	t.Run("create_basic", func(t *testing.T) {
		config := TargetConfig{
			ID:         "test-target",
			MatchType:  MatchTypeComm,
			MatchValue: "python3",
			Mode:       ProbeModeOpenSSL,
		}

		assert.Equal(t, "test-target", config.ID)
		assert.Equal(t, MatchTypeComm, config.MatchType)
		assert.Equal(t, "python3", config.MatchValue)
		assert.Equal(t, ProbeModeOpenSSL, config.Mode)
		assert.Empty(t, config.PromLabels)
	})

	t.Run("create_with_labels", func(t *testing.T) {
		config := TargetConfig{
			ID:         "boto3",
			MatchType:  MatchTypeCmdlineSubstring,
			MatchValue: "boto3",
			Mode:       ProbeModeOpenSSL,
			PromLabels: map[string]string{"client": "boto3", "env": "production"},
		}

		assert.Equal(t, map[string]string{"client": "boto3", "env": "production"}, config.PromLabels)
	})

	t.Run("default_labels_empty", func(t *testing.T) {
		config := TargetConfig{
			ID:         "test",
			MatchType:  MatchTypeComm,
			MatchValue: "test",
			Mode:       ProbeModeHTTP,
		}

		assert.Empty(t, config.PromLabels)
		assert.Nil(t, config.PromLabels)
	})
}

// TestLoadTargets tests the LoadTargets function.
func TestLoadTargets(t *testing.T) {
	t.Run("load_valid_config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "targets.yml")

		content := `
targets:
  - id: aws-cli
    match:
      type: comm
      value: aws
    mode: openssl
    prom_labels:
      client: aws-cli
      env: test

  - id: boto3
    match:
      type: cmdline_substring
      value: boto3
    mode: openssl
    prom_labels:
      client: boto3

  - id: curl
    match:
      type: exe_basename
      value: curl
    mode: http
`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		targets, err := LoadTargets(configPath)
		require.NoError(t, err)
		require.Len(t, targets, 3)

		// Check first target (aws-cli)
		assert.Equal(t, "aws-cli", targets[0].ID)
		assert.Equal(t, MatchTypeComm, targets[0].MatchType)
		assert.Equal(t, "aws", targets[0].MatchValue)
		assert.Equal(t, ProbeModeOpenSSL, targets[0].Mode)
		assert.Equal(t, map[string]string{"client": "aws-cli", "env": "test"}, targets[0].PromLabels)

		// Check second target (boto3)
		assert.Equal(t, "boto3", targets[1].ID)
		assert.Equal(t, MatchTypeCmdlineSubstring, targets[1].MatchType)
		assert.Equal(t, "boto3", targets[1].MatchValue)

		// Check third target (curl)
		assert.Equal(t, "curl", targets[2].ID)
		assert.Equal(t, MatchTypeExeBasename, targets[2].MatchType)
		assert.Equal(t, "curl", targets[2].MatchValue)
		assert.Equal(t, ProbeModeHTTP, targets[2].Mode)
	})

	t.Run("file_not_found", func(t *testing.T) {
		_, err := LoadTargets("/nonexistent/path/config.yml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read config file")
	})

	t.Run("empty_path", func(t *testing.T) {
		_, err := LoadTargets("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty config path")
	})

	t.Run("invalid_yaml_structure_list", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid.yml")

		content := `- item1
- item2
`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		_, err := LoadTargets(configPath)
		assert.Error(t, err)
		// YAML parsing fails for list at root level
		assert.Contains(t, err.Error(), "failed to parse YAML")
	})

	t.Run("missing_targets_key", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "no_targets.yml")

		content := `other_key: value`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		_, err := LoadTargets(configPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'targets' key")
	})

	t.Run("missing_id", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "missing_id.yml")

		content := `
targets:
  - match:
      type: comm
      value: test
    mode: openssl
`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		_, err := LoadTargets(configPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'id'")
	})

	t.Run("missing_match", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "missing_match.yml")

		content := `
targets:
  - id: test
    mode: openssl
`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		_, err := LoadTargets(configPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'match.type' or 'match.value'")
	})

	t.Run("missing_mode", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "missing_mode.yml")

		content := `
targets:
  - id: test
    match:
      type: comm
      value: test
`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		_, err := LoadTargets(configPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'mode'")
	})

	t.Run("invalid_match_type", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid_match_type.yml")

		content := `
targets:
  - id: test
    match:
      type: invalid_type
      value: test
    mode: openssl
`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		_, err := LoadTargets(configPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid match type")
	})

	t.Run("empty_targets_list", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "empty_targets.yml")

		content := `targets: []`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		targets, err := LoadTargets(configPath)
		require.NoError(t, err)
		assert.Empty(t, targets)
	})

	t.Run("prom_labels_various_types", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "various_labels.yml")

		content := `
targets:
  - id: test
    match:
      type: comm
      value: test
    mode: openssl
    prom_labels:
      string_val: hello
      int_val: 42
      bool_val: true
`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		targets, err := LoadTargets(configPath)
		require.NoError(t, err)
		require.Len(t, targets, 1)

		assert.Equal(t, "hello", targets[0].PromLabels["string_val"])
		assert.Equal(t, "42", targets[0].PromLabels["int_val"])
		assert.Equal(t, "true", targets[0].PromLabels["bool_val"])
	})
}

// TestCollectExtraLabelKeys tests the CollectExtraLabelKeys function.
func TestCollectExtraLabelKeys(t *testing.T) {
	t.Run("empty_targets", func(t *testing.T) {
		result := CollectExtraLabelKeys(nil)
		assert.Empty(t, result)
	})

	t.Run("no_labels", func(t *testing.T) {
		targets := []TargetConfig{
			{ID: "t1", MatchType: MatchTypeComm, MatchValue: "a", Mode: ProbeModeOpenSSL},
			{ID: "t2", MatchType: MatchTypeComm, MatchValue: "b", Mode: ProbeModeHTTP},
		}

		result := CollectExtraLabelKeys(targets)
		assert.Empty(t, result)
	})

	t.Run("single_target_single_label", func(t *testing.T) {
		targets := []TargetConfig{
			{
				ID:         "t1",
				MatchType:  MatchTypeComm,
				MatchValue: "a",
				Mode:       ProbeModeOpenSSL,
				PromLabels: map[string]string{"client": "boto3"},
			},
		}

		result := CollectExtraLabelKeys(targets)
		assert.Equal(t, []string{"client"}, result)
	})

	t.Run("multiple_targets_overlapping_labels", func(t *testing.T) {
		targets := []TargetConfig{
			{
				ID:         "t1",
				MatchType:  MatchTypeComm,
				MatchValue: "a",
				Mode:       ProbeModeOpenSSL,
				PromLabels: map[string]string{"client": "boto3", "env": "prod"},
			},
			{
				ID:         "t2",
				MatchType:  MatchTypeComm,
				MatchValue: "b",
				Mode:       ProbeModeOpenSSL,
				PromLabels: map[string]string{"client": "aws-cli", "region": "us-west-2"},
			},
		}

		result := CollectExtraLabelKeys(targets)
		// Should be sorted and deduplicated
		assert.Equal(t, []string{"client", "env", "region"}, result)
	})

	t.Run("sorted_output", func(t *testing.T) {
		targets := []TargetConfig{
			{
				ID:         "t1",
				MatchType:  MatchTypeComm,
				MatchValue: "a",
				Mode:       ProbeModeOpenSSL,
				PromLabels: map[string]string{"zebra": "z", "apple": "a", "mango": "m"},
			},
		}

		result := CollectExtraLabelKeys(targets)
		assert.Equal(t, []string{"apple", "mango", "zebra"}, result)
	})
}

// TestLoadAppConfig tests the LoadAppConfig function.
func TestLoadAppConfig(t *testing.T) {
	t.Run("default_config_when_empty_path", func(t *testing.T) {
		config, err := LoadAppConfig("")
		require.NoError(t, err)

		assert.Equal(t, 5, config.Interval)
		assert.Equal(t, 0, config.MinLatencyMs)
		assert.False(t, config.Debug)
		assert.Equal(t, "::", config.Prometheus.Host)
		assert.Equal(t, 9000, config.Prometheus.Port)
	})

	t.Run("load_custom_config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yml")

		content := `
interval: 10
min_latency_ms: 100
debug: true
prometheus:
  prom_exporter_host: "0.0.0.0"
  prom_exporter_port: 9090
  buffer_size: 2000
screen:
  table_format: false
  max_url_length: 100
`
		require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))

		config, err := LoadAppConfig(configPath)
		require.NoError(t, err)

		assert.Equal(t, 10, config.Interval)
		assert.Equal(t, 100, config.MinLatencyMs)
		assert.True(t, config.Debug)
		assert.Equal(t, "0.0.0.0", config.Prometheus.Host)
		assert.Equal(t, 9090, config.Prometheus.Port)
		assert.Equal(t, 2000, config.Prometheus.BufferSize)
		assert.False(t, config.Screen.TableFormat)
		assert.Equal(t, 100, config.Screen.MaxURLLength)
	})
}

// TestDefaultConfig tests the DefaultConfig function.
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, 5, config.Interval)
	assert.Equal(t, 0, config.MinLatencyMs)
	assert.Equal(t, 0, config.PID)
	assert.False(t, config.Debug)
	assert.Equal(t, "::", config.Prometheus.Host)
	assert.Equal(t, 9000, config.Prometheus.Port)
	assert.Equal(t, 1000, config.Prometheus.BufferSize)
	assert.True(t, config.Screen.TableFormat)
	assert.Equal(t, 50, config.Screen.MaxURLLength)
}
