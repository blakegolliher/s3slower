// Package ebpf provides eBPF program loading and management for S3 traffic tracing.
package ebpf

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// DefaultLibraryFinder implements LibraryFinder for finding TLS libraries.
type DefaultLibraryFinder struct{}

// NewLibraryFinder creates a new library finder.
func NewLibraryFinder() *DefaultLibraryFinder {
	return &DefaultLibraryFinder{}
}

// FindOpenSSL returns the path to libssl.so.
func (f *DefaultLibraryFinder) FindOpenSSL() (string, error) {
	return findLibrary(ProbeModeOpenSSL)
}

// FindGnuTLS returns the path to libgnutls.so.
func (f *DefaultLibraryFinder) FindGnuTLS() (string, error) {
	return findLibrary(ProbeModeGnuTLS)
}

// FindNSS returns the path to libnspr4.so.
func (f *DefaultLibraryFinder) FindNSS() (string, error) {
	return findLibrary(ProbeModeNSS)
}

// FindAll returns all available TLS libraries.
func (f *DefaultLibraryFinder) FindAll() map[ProbeMode]string {
	result := make(map[ProbeMode]string)

	if path, err := f.FindOpenSSL(); err == nil {
		result[ProbeModeOpenSSL] = path
	}
	if path, err := f.FindGnuTLS(); err == nil {
		result[ProbeModeGnuTLS] = path
	}
	if path, err := f.FindNSS(); err == nil {
		result[ProbeModeNSS] = path
	}

	return result
}

// findLibrary finds a TLS library by mode.
func findLibrary(mode ProbeMode) (string, error) {
	patterns := getLibraryPatterns(mode)
	if len(patterns) == 0 {
		return "", errors.New("unknown library mode")
	}

	// Try ldconfig first (fastest)
	if paths := findViaLdconfig(patterns[0]); len(paths) > 0 {
		return selectPreferredVersion(paths), nil
	}

	// Search common paths
	searchPaths := getCommonLibraryPaths()
	searchPaths = append(searchPaths, getArchSpecificPaths()...)

	var found []string
	for _, dir := range searchPaths {
		for _, pattern := range patterns {
			if path := findLibraryByPattern(dir, pattern); path != "" {
				found = append(found, path)
			}
		}
	}

	if len(found) == 0 {
		return "", errors.New("library not found: " + string(mode))
	}

	return selectPreferredVersion(found), nil
}

// getLibraryPatterns returns search patterns for a TLS library mode.
func getLibraryPatterns(mode ProbeMode) []string {
	switch mode {
	case ProbeModeOpenSSL:
		return []string{
			"libssl.so.3",
			"libssl.so.1.1",
			"libssl.so.1.0.0",
			"libssl.so*",
		}
	case ProbeModeGnuTLS:
		return []string{
			"libgnutls.so.30",
			"libgnutls.so.28",
			"libgnutls.so*",
		}
	case ProbeModeNSS:
		return []string{
			"libnspr4.so",
			"libnss3.so",
			"libssl3.so",
		}
	default:
		return nil
	}
}

// getCommonLibraryPaths returns common library search paths.
func getCommonLibraryPaths() []string {
	return []string{
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
		"/usr/local/lib",
		"/usr/local/lib64",
	}
}

// getArchSpecificPaths returns architecture-specific library paths.
func getArchSpecificPaths() []string {
	arch := runtime.GOARCH

	var paths []string

	switch arch {
	case "amd64":
		paths = append(paths,
			"/usr/lib/x86_64-linux-gnu",
			"/lib/x86_64-linux-gnu",
		)
	case "arm64":
		paths = append(paths,
			"/usr/lib/aarch64-linux-gnu",
			"/lib/aarch64-linux-gnu",
		)
	case "386":
		paths = append(paths,
			"/usr/lib/i386-linux-gnu",
			"/lib/i386-linux-gnu",
		)
	}

	// Also add multiarch paths
	paths = append(paths,
		"/usr/lib/"+arch+"-linux-gnu",
		"/lib/"+arch+"-linux-gnu",
	)

	return paths
}

// findLibraryByPattern finds a library in a directory matching a pattern.
func findLibraryByPattern(dir, pattern string) string {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil || len(matches) == 0 {
		return ""
	}

	// Return the first match (patterns are ordered by preference)
	return matches[0]
}

// findViaLdconfig uses ldconfig to find library paths.
func findViaLdconfig(libName string) []string {
	// Try to run ldconfig -p
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	return parseLdConfigOutput(string(output), libName)
}

// parseLdConfigOutput parses ldconfig -p output to find library paths.
func parseLdConfigOutput(output, libName string) []string {
	var paths []string

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Format: "	libssl.so.3 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libssl.so.3"
		if !strings.Contains(line, libName) {
			continue
		}

		parts := strings.Split(line, "=>")
		if len(parts) != 2 {
			continue
		}

		path := strings.TrimSpace(parts[1])
		if path != "" {
			paths = append(paths, path)
		}
	}

	return paths
}

// parseLibraryVersion extracts version from library filename.
func parseLibraryVersion(filename string) string {
	// Pattern: libXXX.so.VERSION
	re := regexp.MustCompile(`\.so\.(.+)$`)
	matches := re.FindStringSubmatch(filename)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// selectPreferredVersion selects the preferred library version from a list.
func selectPreferredVersion(paths []string) string {
	if len(paths) == 0 {
		return ""
	}

	if len(paths) == 1 {
		return paths[0]
	}

	// Sort by version (higher versions first)
	sort.Slice(paths, func(i, j int) bool {
		vi := parseLibraryVersion(filepath.Base(paths[i]))
		vj := parseLibraryVersion(filepath.Base(paths[j]))

		// Parse major version numbers for comparison
		mi := parseMajorVersion(vi)
		mj := parseMajorVersion(vj)

		return mi > mj
	})

	return paths[0]
}

// parseMajorVersion extracts the major version number.
func parseMajorVersion(version string) int {
	if version == "" {
		return 0
	}

	// Split on dots and take first part
	parts := strings.Split(version, ".")
	if len(parts) == 0 {
		return 0
	}

	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}

	return n
}

// validateLibraryPath validates that a library path exists and is a file.
func validateLibraryPath(path string) error {
	if path == "" {
		return errors.New("empty library path")
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return errors.New("path is a directory, not a file")
	}

	return nil
}
