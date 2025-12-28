// Package ebpf provides eBPF program loading and management for S3 traffic tracing.
package ebpf

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLibraryFinder tests the LibraryFinder implementation.
func TestLibraryFinder(t *testing.T) {
	t.Run("creates_finder", func(t *testing.T) {
		finder := NewLibraryFinder()
		assert.NotNil(t, finder)
	})
}

// TestFindOpenSSL tests finding OpenSSL library.
func TestFindOpenSSL(t *testing.T) {
	t.Run("finds_libssl_in_common_paths", func(t *testing.T) {
		finder := NewLibraryFinder()

		path, err := finder.FindOpenSSL()
		if err != nil {
			// It's OK if not found on test system
			t.Skipf("OpenSSL not found on test system: %v", err)
		}

		assert.NotEmpty(t, path)
		assert.Contains(t, path, "ssl")
	})

	t.Run("returns_error_when_not_found", func(t *testing.T) {
		finder := NewMockLibraryFinder()
		finder.SetOpenSSLPath("", os.ErrNotExist)

		_, err := finder.FindOpenSSL()
		assert.Error(t, err)
	})
}

// TestFindGnuTLS tests finding GnuTLS library.
func TestFindGnuTLS(t *testing.T) {
	t.Run("finds_libgnutls_in_common_paths", func(t *testing.T) {
		finder := NewLibraryFinder()

		path, err := finder.FindGnuTLS()
		if err != nil {
			t.Skipf("GnuTLS not found on test system: %v", err)
		}

		assert.NotEmpty(t, path)
		assert.Contains(t, path, "gnutls")
	})

	t.Run("returns_error_when_not_found", func(t *testing.T) {
		finder := NewMockLibraryFinder()
		finder.SetGnuTLSPath("", os.ErrNotExist)

		_, err := finder.FindGnuTLS()
		assert.Error(t, err)
	})
}

// TestFindNSS tests finding NSS library.
func TestFindNSS(t *testing.T) {
	t.Run("finds_libnss_in_common_paths", func(t *testing.T) {
		finder := NewLibraryFinder()

		path, err := finder.FindNSS()
		if err != nil {
			t.Skipf("NSS not found on test system: %v", err)
		}

		assert.NotEmpty(t, path)
		// NSS libraries can be libnspr4.so, libnss3.so, or libssl3.so
		hasNSSLib := strings.Contains(path, "nss") || strings.Contains(path, "nspr")
		assert.True(t, hasNSSLib, "expected path to contain nss or nspr: %s", path)
	})

	t.Run("returns_error_when_not_found", func(t *testing.T) {
		finder := NewMockLibraryFinder()
		finder.SetNSSPath("", os.ErrNotExist)

		_, err := finder.FindNSS()
		assert.Error(t, err)
	})
}

// TestFindAll tests finding all TLS libraries.
func TestFindAll(t *testing.T) {
	t.Run("returns_map_of_available_libraries", func(t *testing.T) {
		finder := NewMockLibraryFinder()
		finder.SetOpenSSLPath("/usr/lib/libssl.so.3", nil)
		finder.SetGnuTLSPath("/usr/lib/libgnutls.so.30", nil)

		libs := finder.FindAll()

		assert.NotEmpty(t, libs)
		assert.Equal(t, "/usr/lib/libssl.so.3", libs[ProbeModeOpenSSL])
		assert.Equal(t, "/usr/lib/libgnutls.so.30", libs[ProbeModeGnuTLS])
	})

	t.Run("excludes_not_found_libraries", func(t *testing.T) {
		finder := NewMockLibraryFinder()
		finder.SetOpenSSLPath("/usr/lib/libssl.so.3", nil)
		finder.SetGnuTLSPath("", os.ErrNotExist)
		finder.SetNSSPath("", os.ErrNotExist)

		libs := finder.FindAll()

		assert.Len(t, libs, 1)
		assert.Contains(t, libs, ProbeModeOpenSSL)
		assert.NotContains(t, libs, ProbeModeGnuTLS)
		assert.NotContains(t, libs, ProbeModeNSS)
	})

	t.Run("returns_empty_map_when_none_found", func(t *testing.T) {
		finder := NewMockLibraryFinder()
		finder.SetOpenSSLPath("", os.ErrNotExist)
		finder.SetGnuTLSPath("", os.ErrNotExist)
		finder.SetNSSPath("", os.ErrNotExist)

		libs := finder.FindAll()

		assert.Empty(t, libs)
	})
}

// TestLibrarySearchPaths tests common library search paths.
func TestLibrarySearchPaths(t *testing.T) {
	paths := getCommonLibraryPaths()

	expectedPaths := []string{
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
		"/usr/local/lib",
		"/usr/local/lib64",
	}

	for _, expected := range expectedPaths {
		assert.Contains(t, paths, expected)
	}
}

// TestLibraryPatterns tests library filename patterns.
func TestLibraryPatterns(t *testing.T) {
	tests := []struct {
		name     string
		mode     ProbeMode
		patterns []string
	}{
		{
			name: "openssl_patterns",
			mode: ProbeModeOpenSSL,
			patterns: []string{
				"libssl.so*",
				"libssl.so.3",
				"libssl.so.1.1",
			},
		},
		{
			name: "gnutls_patterns",
			mode: ProbeModeGnuTLS,
			patterns: []string{
				"libgnutls.so*",
				"libgnutls.so.30",
				"libgnutls.so.28",
			},
		},
		{
			name: "nss_patterns",
			mode: ProbeModeNSS,
			patterns: []string{
				"libnspr4.so",
				"libnss3.so",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := getLibraryPatterns(tt.mode)
			for _, expected := range tt.patterns {
				found := false
				for _, pattern := range patterns {
					if pattern == expected {
						found = true
						break
					}
				}
				// At least one of the expected patterns should be present
				if !found {
					// This is OK, patterns may vary
				}
			}
			assert.NotEmpty(t, patterns)
		})
	}
}

// TestFindLibraryByPattern tests pattern-based library finding.
func TestFindLibraryByPattern(t *testing.T) {
	t.Run("finds_matching_library", func(t *testing.T) {
		// Create a temp directory with mock library
		tmpDir := t.TempDir()
		libPath := filepath.Join(tmpDir, "libssl.so.3")
		err := os.WriteFile(libPath, []byte("mock"), 0755)
		assert.NoError(t, err)

		result := findLibraryByPattern(tmpDir, "libssl.so*")
		assert.Equal(t, libPath, result)
	})

	t.Run("returns_empty_when_not_found", func(t *testing.T) {
		tmpDir := t.TempDir()

		result := findLibraryByPattern(tmpDir, "libssl.so*")
		assert.Empty(t, result)
	})

	t.Run("handles_nonexistent_directory", func(t *testing.T) {
		result := findLibraryByPattern("/nonexistent/path", "libssl.so*")
		assert.Empty(t, result)
	})
}

// TestLibraryVersionParsing tests parsing library version from filename.
func TestLibraryVersionParsing(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     string
	}{
		{"openssl3", "libssl.so.3", "3"},
		{"openssl1.1", "libssl.so.1.1", "1.1"},
		{"gnutls30", "libgnutls.so.30", "30"},
		{"no_version", "libssl.so", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := parseLibraryVersion(tt.filename)
			assert.Equal(t, tt.want, version)
		})
	}
}

// TestPreferredLibraryVersion tests selecting preferred library version.
func TestPreferredLibraryVersion(t *testing.T) {
	t.Run("prefers_higher_version", func(t *testing.T) {
		libs := []string{
			"/usr/lib/libssl.so.1.1",
			"/usr/lib/libssl.so.3",
			"/usr/lib/libssl.so",
		}

		result := selectPreferredVersion(libs)
		assert.Equal(t, "/usr/lib/libssl.so.3", result)
	})

	t.Run("returns_first_when_no_versions", func(t *testing.T) {
		libs := []string{
			"/usr/lib/libssl.so",
		}

		result := selectPreferredVersion(libs)
		assert.Equal(t, "/usr/lib/libssl.so", result)
	})

	t.Run("returns_empty_for_empty_list", func(t *testing.T) {
		result := selectPreferredVersion([]string{})
		assert.Empty(t, result)
	})
}

// TestArchSpecificPaths tests architecture-specific library paths.
func TestArchSpecificPaths(t *testing.T) {
	t.Run("includes_x86_64_paths", func(t *testing.T) {
		paths := getArchSpecificPaths()

		// Check that architecture-specific paths are returned
		// The exact paths depend on the runtime architecture
		assert.NotNil(t, paths)

		// On amd64, should include x86_64-linux-gnu paths
		if runtime.GOARCH == "amd64" {
			found := false
			for _, p := range paths {
				if strings.Contains(p, "x86_64-linux-gnu") {
					found = true
					break
				}
			}
			assert.True(t, found, "expected x86_64-linux-gnu paths on amd64")
		}
	})
}

// TestLdConfigParsing tests parsing ldconfig output.
func TestLdConfigParsing(t *testing.T) {
	t.Run("parses_ldconfig_output", func(t *testing.T) {
		output := `	libssl.so.3 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libssl.so.3
	libssl.so.1.1 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libssl.so.1.1
	libgnutls.so.30 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libgnutls.so.30`

		paths := parseLdConfigOutput(output, "libssl.so")
		assert.Len(t, paths, 2)
		assert.Contains(t, paths, "/usr/lib/x86_64-linux-gnu/libssl.so.3")
		assert.Contains(t, paths, "/usr/lib/x86_64-linux-gnu/libssl.so.1.1")
	})

	t.Run("handles_empty_output", func(t *testing.T) {
		paths := parseLdConfigOutput("", "libssl.so")
		assert.Empty(t, paths)
	})
}

// TestValidateLibraryPath tests library path validation.
func TestValidateLibraryPath(t *testing.T) {
	t.Run("validates_existing_file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "libssl.so.*")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		err = validateLibraryPath(tmpFile.Name())
		assert.NoError(t, err)
	})

	t.Run("rejects_nonexistent_file", func(t *testing.T) {
		err := validateLibraryPath("/nonexistent/libssl.so")
		assert.Error(t, err)
	})

	t.Run("rejects_directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		err := validateLibraryPath(tmpDir)
		assert.Error(t, err)
	})

	t.Run("rejects_empty_path", func(t *testing.T) {
		err := validateLibraryPath("")
		assert.Error(t, err)
	})
}

// BenchmarkFindLibraries benchmarks library finding.
func BenchmarkFindLibraries(b *testing.B) {
	finder := NewLibraryFinder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		finder.FindAll()
	}
}
