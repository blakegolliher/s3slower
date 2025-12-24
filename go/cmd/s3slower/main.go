// Package main provides the s3slower CLI application.
//
// S3Slower is an eBPF-based monitoring tool that traces S3 client-side latency
// without requiring SDK instrumentation. It monitors HTTP/S3 traffic from any
// S3 client application and exports metrics via Prometheus or displays them
// on the terminal.
//
// Usage:
//
//	s3slower run              # Run in foreground, display to terminal
//	s3slower run --prometheus # Run with Prometheus exporter
//	s3slower attach --pid PID # Attach to specific process
//	systemctl start s3slower  # Run as background service
package main

import (
	"fmt"
	"os"

	"github.com/s3slower/s3slower/internal/cmd"
)

// Version information, set at build time via ldflags
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	rootCmd := cmd.NewRootCommand(version, commit, buildDate)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
