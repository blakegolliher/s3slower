// Package cmd provides the CLI commands for s3slower.
package cmd

import (
	"github.com/spf13/cobra"
)

// NewRootCommand creates the root command for s3slower.
func NewRootCommand(version, commit, buildDate string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "s3slower",
		Short: "S3 latency tracer using eBPF",
		Long: `S3Slower is an eBPF-based monitoring tool that traces S3 client-side
latency without requiring SDK instrumentation. It monitors HTTP/S3 traffic
from any S3 client application and exports metrics via Prometheus or
displays them on the terminal.

Examples:
  # Run with terminal output
  s3slower run

  # Run with Prometheus exporter on port 9000
  s3slower run --prometheus --port 9000

  # Attach to specific process
  s3slower attach --pid 12345

  # Filter by minimum latency
  s3slower run --min-latency 100ms`,
		Version: version,
	}

	// Add subcommands
	cmd.AddCommand(newRunCommand())
	cmd.AddCommand(newAttachCommand())
	cmd.AddCommand(newVersionCommand(version, commit, buildDate))

	return cmd
}

func newVersionCommand(version, commit, buildDate string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("s3slower %s\n", version)
			cmd.Printf("  commit:  %s\n", commit)
			cmd.Printf("  built:   %s\n", buildDate)
		},
	}
}

func newRunCommand() *cobra.Command {
	var (
		configFile  string
		prometheus  bool
		port        int
		host        string
		minLatency  string
		interval    int
		watchPids   []string
		debug       bool
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run s3slower tracer",
		Long: `Run the s3slower tracer in foreground mode.

By default, output is displayed on the terminal. Use --prometheus to
start the Prometheus metrics exporter instead.

When running as a systemd service, the --prometheus flag should be used
to enable metrics collection.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: Implement run command
			cmd.Println("s3slower tracer starting...")
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "C", "", "Path to config file")
	cmd.Flags().BoolVar(&prometheus, "prometheus", false, "Enable Prometheus exporter")
	cmd.Flags().IntVarP(&port, "port", "p", 9000, "Prometheus exporter port")
	cmd.Flags().StringVar(&host, "host", "::", "Prometheus exporter host")
	cmd.Flags().StringVar(&minLatency, "min-latency", "0", "Minimum latency to report")
	cmd.Flags().IntVarP(&interval, "interval", "i", 5, "Collection interval in seconds")
	cmd.Flags().StringSliceVar(&watchPids, "watch", nil, "Process names to watch (e.g., mc,warp)")
	cmd.Flags().BoolVar(&debug, "debug", false, "Enable debug output")

	return cmd
}

func newAttachCommand() *cobra.Command {
	var (
		pid    int
		mode   string
		follow bool
	)

	cmd := &cobra.Command{
		Use:   "attach",
		Short: "Attach to a specific process",
		Long: `Attach the tracer to a specific process by PID.

This is useful for debugging or monitoring a single application.
The tracer will automatically detect the TLS library used.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if pid == 0 {
				return cmd.Help()
			}
			// TODO: Implement attach command
			cmd.Printf("Attaching to PID %d with mode %s...\n", pid, mode)
			return nil
		},
	}

	cmd.Flags().IntVar(&pid, "pid", 0, "Process ID to attach to")
	cmd.Flags().StringVar(&mode, "mode", "auto", "Probe mode: auto, openssl, gnutls, nss, http")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow child processes")

	return cmd
}
