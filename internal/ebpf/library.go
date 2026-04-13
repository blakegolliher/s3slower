// Package ebpf provides eBPF program loading and management for S3 traffic tracing.
package ebpf

import (
	"debug/elf"
	"errors"
	"fmt"
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

// FindS2N returns the path to an s2n-tls library (AWS CRT or system libs2n).
func (f *DefaultLibraryFinder) FindS2N() (string, error) {
	// AWS CLI v2 bundles s2n inside _awscrt.abi3.so
	awsCRTPaths := []string{
		"/usr/local/aws-cli/v2/current/dist/_awscrt.abi3.so",
	}

	// Check versioned AWS CLI installs
	if matches, err := filepath.Glob("/usr/local/aws-cli/v2/*/dist/_awscrt.abi3.so"); err == nil {
		awsCRTPaths = append(awsCRTPaths, matches...)
	}

	// Check pip-installed awscrt
	pipPatterns := []string{
		"/usr/lib/python*/site-packages/awscrt/_awscrt.abi3.so",
		"/usr/lib64/python*/site-packages/awscrt/_awscrt.abi3.so",
		"/usr/local/lib/python*/site-packages/awscrt/_awscrt.abi3.so",
		"/usr/local/lib/python*/dist-packages/awscrt/_awscrt.abi3.so",
	}
	for _, pattern := range pipPatterns {
		if matches, err := filepath.Glob(pattern); err == nil {
			awsCRTPaths = append(awsCRTPaths, matches...)
		}
	}

	for _, path := range awsCRTPaths {
		if hasS2NSymbols(path) {
			return path, nil
		}
	}

	// Check for system libs2n.so
	if paths := findViaLdconfig("libs2n"); len(paths) > 0 {
		return paths[0], nil
	}

	for _, dir := range getCommonLibraryPaths() {
		if path := findLibraryByPattern(dir, "libs2n.so*"); path != "" {
			return path, nil
		}
	}

	return "", errors.New("s2n-tls library not found")
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
	if path, err := f.FindS2N(); err == nil {
		result[ProbeModeS2N] = path
	}

	return result
}

// knownGoS3Binaries lists S3 client tools written in Go that use crypto/tls.
var knownGoS3Binaries = []string{
	"mc",
	"warp",
	"s3-benchmark",
}

// FindGoTLS returns paths to Go binaries that use crypto/tls.
// Each Go binary needs its own uprobe attachment since Go statically links
// crypto/tls (it's not a shared library).
func (f *DefaultLibraryFinder) FindGoTLS() []string {
	var results []string
	seen := make(map[string]bool)

	// Check known Go-based S3 tools
	for _, name := range knownGoS3Binaries {
		path := findExecutable(name)
		if path == "" {
			continue
		}
		if hasGoTLSSymbols(path) {
			results = append(results, path)
			seen[path] = true
		}
	}

	// Scan /proc for running Go processes that use crypto/tls
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return results
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only look at numeric (PID) directories
		if len(entry.Name()) == 0 || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		exePath := filepath.Join("/proc", entry.Name(), "exe")
		resolved, err := os.Readlink(exePath)
		if err != nil {
			continue
		}
		if seen[resolved] {
			continue
		}
		if hasGoTLSSymbols(resolved) {
			results = append(results, resolved)
			seen[resolved] = true
		}
	}

	return results
}

// goTLSAnalysis holds the results of analyzing a Go binary for crypto/tls.
type goTLSAnalysis struct {
	isGo       bool
	hasTLS     bool
	retOffsets []uint64
}

// analyzeGoTLSBinary opens an ELF binary once and determines whether it
// is a Go binary using crypto/tls, and if so, finds the RET instruction
// offsets in crypto/tls.(*Conn).Read for uprobe-at-RET attachment.
// This replaces the separate isGoBinary + hasGoTLSSymbols + findRetOffsets
// calls, cutting discovery time from ~40ms (3 ELF opens + objdump fork)
// to ~5ms (single ELF open + in-process decode).
func analyzeGoTLSBinary(path string) (*goTLSAnalysis, error) {
	f, err := elf.Open(path)
	if err != nil {
		return &goTLSAnalysis{}, nil
	}
	defer f.Close()

	// Fast check: .gopclntab is present in all Go binaries.
	if f.Section(".gopclntab") == nil {
		return &goTLSAnalysis{}, nil
	}

	syms, err := f.Symbols()
	if err != nil {
		return &goTLSAnalysis{isGo: true}, nil
	}

	// Scan for crypto/tls symbols and record Read's address/size.
	var hasWrite, hasRead bool
	var readAddr, readSize uint64
	for _, s := range syms {
		switch s.Name {
		case "crypto/tls.(*Conn).Write":
			hasWrite = true
		case "crypto/tls.(*Conn).Read":
			hasRead = true
			readAddr = s.Value
			readSize = s.Size
		}
		if hasWrite && hasRead {
			break
		}
	}

	if !hasWrite || !hasRead {
		return &goTLSAnalysis{isGo: true}, nil
	}

	// If size is 0, estimate from next symbol.
	if readSize == 0 {
		nextAddr := uint64(0)
		for _, s := range syms {
			if s.Value > readAddr && (nextAddr == 0 || s.Value < nextAddr) {
				nextAddr = s.Value
			}
		}
		if nextAddr > readAddr {
			readSize = nextAddr - readAddr
		} else {
			return nil, fmt.Errorf("cannot determine size of crypto/tls.(*Conn).Read")
		}
	}

	// Read just the function bytes from .text (not the whole section).
	text := f.Section(".text")
	if text == nil {
		return nil, fmt.Errorf(".text section not found")
	}
	if readAddr < text.Addr {
		return nil, fmt.Errorf("symbol address before .text start")
	}
	funcOffset := int64(readAddr - text.Addr)
	code := make([]byte, readSize)
	n, err := text.ReadAt(code, funcOffset)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("failed to read function bytes: %w", err)
	}
	code = code[:n]

	// Walk the instruction stream to find actual RET (0xC3) instructions.
	var retOffsets []uint64
	pos := 0
	for pos < len(code) {
		insnLen := x86InsnLen(code[pos:])
		if insnLen == 0 {
			break // unknown instruction, stop decoding
		}
		if code[pos] == 0xC3 {
			retOffsets = append(retOffsets, uint64(pos))
		}
		pos += insnLen
	}

	if len(retOffsets) == 0 {
		return nil, fmt.Errorf("no RET instructions found in crypto/tls.(*Conn).Read")
	}

	return &goTLSAnalysis{
		isGo:       true,
		hasTLS:     true,
		retOffsets: retOffsets,
	}, nil
}

// hasGoTLSSymbols checks whether an ELF binary contains Go crypto/tls
// symbols (crypto/tls.(*Conn).Write and Read), indicating a Go program
// that uses the built-in TLS package.
func hasGoTLSSymbols(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		return false
	}

	var hasWrite, hasRead bool
	for _, s := range syms {
		if s.Name == "crypto/tls.(*Conn).Write" && s.Value != 0 {
			hasWrite = true
		}
		if s.Name == "crypto/tls.(*Conn).Read" && s.Value != 0 {
			hasRead = true
		}
		if hasWrite && hasRead {
			return true
		}
	}
	return false
}

// knownStaticBinaries lists S3 client tools that are commonly statically linked.
var knownStaticBinaries = []string{
	"elbencho",
	"warp",
	"mc",
}

// extraSearchDirs are checked in addition to PATH when looking for
// statically-linked binaries.  sudo typically strips /usr/local/* from PATH.
var extraSearchDirs = []string{
	"/usr/local/bin",
	"/usr/local/sbin",
	"/opt/bin",
}

// FindStaticBinaries returns paths to executables and shared libraries that
// contain SSL_write/SSL_read symbols. These need their own uprobe attachment
// since they don't use the system's shared libssl.
func (f *DefaultLibraryFinder) FindStaticBinaries() []string {
	var results []string

	for _, name := range knownStaticBinaries {
		path := findExecutable(name)
		if path == "" {
			continue
		}
		if hasStaticSSLSymbols(path) {
			results = append(results, path)
		}
	}

	// Find bundled Python SSL modules (e.g. AWS CLI v2 ships its own OpenSSL
	// inside _ssl.cpython-*.so, which doesn't link the system libssl.so).
	results = append(results, findBundledSSLModules()...)

	return results
}

// bundledSSLSearchPaths are directories known to bundle their own OpenSSL
// inside a Python _ssl extension module.
var bundledSSLSearchPaths = []string{
	"/usr/local/aws-cli/v2/*/dist/lib-dynload",
}

// findBundledSSLModules finds Python _ssl modules that statically embed OpenSSL.
func findBundledSSLModules() []string {
	var results []string
	for _, pattern := range bundledSSLSearchPaths {
		dirs, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, dir := range dirs {
			matches, err := filepath.Glob(filepath.Join(dir, "_ssl.cpython-*.so"))
			if err != nil {
				continue
			}
			for _, path := range matches {
				if hasStaticSSLSymbols(path) {
					results = append(results, path)
				}
			}
		}
	}
	return results
}

// findExecutable searches PATH and common extra directories for a binary.
func findExecutable(name string) string {
	// Try PATH first
	if path, err := exec.LookPath(name); err == nil {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			return resolved
		}
		return path
	}

	// Fall back to extra directories (handles restricted sudo PATH)
	for _, dir := range extraSearchDirs {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		if info.Mode()&0111 != 0 { // executable
			if resolved, err := filepath.EvalSymlinks(path); err == nil {
				return resolved
			}
			return path
		}
	}

	return ""
}

// hasStaticSSLSymbols checks whether an ELF binary contains SSL_write and
// SSL_read as defined (non-UND) symbols, indicating a statically-linked
// OpenSSL. We only need the symbol table, not debug info.
func hasStaticSSLSymbols(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		return false
	}

	var hasWrite, hasRead bool
	for _, s := range syms {
		if s.Name == "SSL_write" && s.Value != 0 {
			hasWrite = true
		}
		if s.Name == "SSL_read" && s.Value != 0 {
			hasRead = true
		}
		if hasWrite && hasRead {
			return true
		}
	}
	return false
}

// hasS2NSymbols checks whether an ELF binary contains s2n_send and s2n_recv
// as defined symbols, indicating embedded s2n-tls (e.g. AWS CRT).
func hasS2NSymbols(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	// Check dynamic symbols first (shared libraries)
	dynsyms, err := f.DynamicSymbols()
	if err == nil {
		var hasSend, hasRecv bool
		for _, s := range dynsyms {
			if s.Name == "s2n_send" && s.Value != 0 {
				hasSend = true
			}
			if s.Name == "s2n_recv" && s.Value != 0 {
				hasRecv = true
			}
			if hasSend && hasRecv {
				return true
			}
		}
	}

	// Fall back to regular symbol table
	syms, err := f.Symbols()
	if err != nil {
		return false
	}
	var hasSend, hasRecv bool
	for _, s := range syms {
		if s.Name == "s2n_send" && s.Value != 0 {
			hasSend = true
		}
		if s.Name == "s2n_recv" && s.Value != 0 {
			hasRecv = true
		}
		if hasSend && hasRecv {
			return true
		}
	}
	return false
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
