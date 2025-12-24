// Package watcher provides process watching and target matching tests.
package watcher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/s3slower/s3slower/internal/config"
)

// TestReadExeBasename tests the ReadExeBasename function.
func TestReadExeBasename(t *testing.T) {
	// Use current process for testing
	pid := os.Getpid()

	t.Run("valid_exe_path", func(t *testing.T) {
		result, err := ReadExeBasename(pid)
		require.NoError(t, err)
		assert.NotEmpty(t, result)
		// Should end with "go" or the test binary name
	})

	t.Run("process_not_found", func(t *testing.T) {
		_, err := ReadExeBasename(99999999)
		assert.Error(t, err)
	})
}

// TestReadCmdline tests the ReadCmdline function.
func TestReadCmdline(t *testing.T) {
	// Use current process for testing
	pid := os.Getpid()

	t.Run("valid_cmdline", func(t *testing.T) {
		result, err := ReadCmdline(pid)
		require.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("process_not_found", func(t *testing.T) {
		_, err := ReadCmdline(99999999)
		assert.Error(t, err)
	})
}

// TestClassifyPID tests the ClassifyPID function.
func TestClassifyPID(t *testing.T) {
	sampleTargets := []config.TargetConfig{
		{
			ID:         "aws-cli",
			MatchType:  config.MatchTypeComm,
			MatchValue: "aws",
			Mode:       config.ProbeModeOpenSSL,
		},
		{
			ID:         "boto3",
			MatchType:  config.MatchTypeCmdlineSubstring,
			MatchValue: "boto3",
			Mode:       config.ProbeModeOpenSSL,
		},
		{
			ID:         "curl",
			MatchType:  config.MatchTypeExeBasename,
			MatchValue: "curl",
			Mode:       config.ProbeModeHTTP,
		},
	}

	t.Run("match_comm", func(t *testing.T) {
		result := ClassifyPID(12345, "aws", sampleTargets)

		require.NotNil(t, result)
		assert.Equal(t, "aws-cli", result.ID)
		assert.Equal(t, config.ProbeModeOpenSSL, result.Mode)
	})

	t.Run("match_comm_exact_only", func(t *testing.T) {
		// "aws-cli" != "aws", so no match
		result := ClassifyPID(12345, "aws-cli", sampleTargets)
		assert.Nil(t, result)
	})

	t.Run("no_match", func(t *testing.T) {
		result := ClassifyPID(12345, "unknown-process", sampleTargets)
		assert.Nil(t, result)
	})

	t.Run("empty_targets", func(t *testing.T) {
		result := ClassifyPID(12345, "aws", nil)
		assert.Nil(t, result)
	})

	t.Run("first_match_wins", func(t *testing.T) {
		targets := []config.TargetConfig{
			{ID: "first", MatchType: config.MatchTypeComm, MatchValue: "test", Mode: config.ProbeModeOpenSSL},
			{ID: "second", MatchType: config.MatchTypeComm, MatchValue: "test", Mode: config.ProbeModeHTTP},
		}

		result := ClassifyPID(12345, "test", targets)
		require.NotNil(t, result)
		assert.Equal(t, "first", result.ID)
	})

	t.Run("exe_basename_also_matches_comm", func(t *testing.T) {
		targets := []config.TargetConfig{
			{ID: "curl", MatchType: config.MatchTypeExeBasename, MatchValue: "curl", Mode: config.ProbeModeHTTP},
		}

		// When exe doesn't match but comm does (for exe_basename type)
		result := ClassifyPID(12345, "curl", targets)
		require.NotNil(t, result)
		assert.Equal(t, "curl", result.ID)
	})
}

// TestTargetWatcher tests the TargetWatcher struct.
func TestTargetWatcher(t *testing.T) {
	sampleTargets := []config.TargetConfig{
		{
			ID:         "test-target",
			MatchType:  config.MatchTypeComm,
			MatchValue: "testproc",
			Mode:       config.ProbeModeOpenSSL,
		},
	}

	t.Run("init", func(t *testing.T) {
		callCount := 0
		callback := func(pid int, comm string, target *config.TargetConfig) {
			callCount++
		}

		watcher := NewTargetWatcher(sampleTargets, callback)

		assert.Equal(t, sampleTargets, watcher.targets)
		assert.NotNil(t, watcher.attachCallback)
		assert.Empty(t, watcher.attached)
	})

	t.Run("start_idempotent", func(t *testing.T) {
		watcher := NewTargetWatcher(sampleTargets, nil)

		err := watcher.Start()
		require.NoError(t, err)

		err = watcher.Start()
		require.NoError(t, err)
	})

	t.Run("stop_without_start", func(t *testing.T) {
		watcher := NewTargetWatcher(sampleTargets, nil)
		// Should not panic
		watcher.Stop()
	})

	t.Run("on_exec_matching_pid", func(t *testing.T) {
		var callbackPID int
		var callbackComm string
		var callbackTarget *config.TargetConfig

		callback := func(pid int, comm string, target *config.TargetConfig) {
			callbackPID = pid
			callbackComm = comm
			callbackTarget = target
		}

		watcher := NewTargetWatcher(sampleTargets, callback)
		watcher.OnExec(12345, "testproc")

		assert.Equal(t, 12345, callbackPID)
		assert.Equal(t, "testproc", callbackComm)
		assert.NotNil(t, callbackTarget)
		assert.Equal(t, "test-target", callbackTarget.ID)
		assert.True(t, watcher.IsAttached(12345))
	})

	t.Run("on_exec_non_matching_pid", func(t *testing.T) {
		callCount := 0
		callback := func(pid int, comm string, target *config.TargetConfig) {
			callCount++
		}

		watcher := NewTargetWatcher(sampleTargets, callback)
		watcher.OnExec(12345, "unknownproc")

		assert.Equal(t, 0, callCount)
		assert.False(t, watcher.IsAttached(12345))
	})

	t.Run("on_exec_duplicate_pid", func(t *testing.T) {
		callCount := 0
		callback := func(pid int, comm string, target *config.TargetConfig) {
			callCount++
		}

		watcher := NewTargetWatcher(sampleTargets, callback)
		watcher.OnExec(12345, "testproc")
		watcher.OnExec(12345, "testproc")

		// Callback should only be called once
		assert.Equal(t, 1, callCount)
	})

	t.Run("get_attached", func(t *testing.T) {
		watcher := NewTargetWatcher(sampleTargets, nil)
		watcher.OnExec(12345, "testproc")
		watcher.OnExec(67890, "testproc")

		attached := watcher.GetAttached()
		assert.Len(t, attached, 2)
		assert.True(t, attached[12345])
		assert.True(t, attached[67890])
	})
}

// TestKnownS3Clients tests the known S3 clients list.
func TestKnownS3Clients(t *testing.T) {
	expectedClients := []string{"aws", "python", "python3", "curl", "mc", "warp", "elbencho", "s3cmd"}

	for _, client := range expectedClients {
		t.Run(client, func(t *testing.T) {
			assert.True(t, IsKnownS3Client(client))
		})
	}

	t.Run("unknown_client", func(t *testing.T) {
		assert.False(t, IsKnownS3Client("unknown"))
	})
}

// TestDetectClientType tests the DetectClientType function.
func TestDetectClientType(t *testing.T) {
	tests := []struct {
		comm     string
		expected ClientType
	}{
		{"warp", ClientWarp},
		{"elbencho", ClientElbencho},
		{"python", ClientBoto3},
		{"python3", ClientBoto3},
		{"s3cmd", ClientS3cmd},
		{"aws", ClientAWSCLI},
		{"mc", ClientMC},
		{"curl", ClientCurl},
		{"unknown", ClientUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.comm, func(t *testing.T) {
			result := DetectClientType(tt.comm)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestClientTypeName tests the ClientTypeName function.
func TestClientTypeName(t *testing.T) {
	tests := []struct {
		ct       ClientType
		expected string
	}{
		{ClientWarp, "warp"},
		{ClientElbencho, "elbencho"},
		{ClientBoto3, "boto3"},
		{ClientS3cmd, "s3cmd"},
		{ClientAWSCLI, "aws-cli"},
		{ClientMC, "mc"},
		{ClientCurl, "curl"},
		{ClientUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := ClientTypeName(tt.ct)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMockProcDir tests process reading with mock /proc.
func TestMockProcDir(t *testing.T) {
	// Create mock /proc structure
	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc", "12345")
	require.NoError(t, os.MkdirAll(procDir, 0755))

	// Create mock cmdline
	cmdline := []byte("python3\x00-c\x00import boto3\x00")
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "cmdline"), cmdline, 0644))

	// Note: We can't easily test ReadExeBasename with mocks since it uses os.Readlink
	// which requires an actual symlink. The real tests use the current process.
}
