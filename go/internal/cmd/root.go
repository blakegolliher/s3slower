// Package cmd provides the CLI commands for s3slower.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/s3slower/s3slower/internal/runner"
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
  s3slower run --min-latency 100`,
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
		configFile   string
		prometheus   bool
		port         int
		host         string
		minLatency   uint64
		mode         string
		watchProcs   []string
		logDir       string
		logMaxSizeMB int
		noLog        bool
		debug        bool
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run s3slower tracer",
		Long: `Run the s3slower tracer in foreground mode.

By default, output is displayed on the terminal and logged to /var/log/s3slower/.
Use --prometheus to also start the Prometheus metrics exporter.

When running as a systemd service, the --prometheus flag should be used
to enable metrics collection.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := runner.DefaultConfig()

			// Apply flags
			cfg.Mode = mode
			cfg.MinLatencyMs = minLatency
			cfg.EnablePrometheus = prometheus
			cfg.PrometheusPort = port
			cfg.PrometheusHost = host
			cfg.WatchProcesses = watchProcs
			cfg.Debug = debug

			// Logging settings
			if noLog {
				cfg.EnableLogging = false
			} else {
				cfg.EnableLogging = true
				if logDir != "" {
					cfg.LogDir = logDir
				}
				if logMaxSizeMB > 0 {
					cfg.LogMaxSizeMB = logMaxSizeMB
				}
			}

			// Create and run
			r, err := runner.New(cfg)
			if err != nil {
				return fmt.Errorf("failed to create runner: %w", err)
			}
			defer r.Close()

			ctx := context.Background()
			return r.Run(ctx)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "C", "", "Path to config file")
	cmd.Flags().BoolVar(&prometheus, "prometheus", false, "Enable Prometheus exporter")
	cmd.Flags().IntVarP(&port, "port", "p", 9000, "Prometheus exporter port")
	cmd.Flags().StringVar(&host, "host", "::", "Prometheus exporter host")
	cmd.Flags().Uint64Var(&minLatency, "min-latency", 0, "Minimum latency in ms to report")
	cmd.Flags().StringVar(&mode, "mode", "auto", "Probe mode: auto, http, openssl, gnutls, nss")
	cmd.Flags().StringSliceVar(&watchProcs, "watch", nil, "Process names to watch (e.g., mc,warp)")
	cmd.Flags().StringVar(&logDir, "log-dir", "/var/log/s3slower", "Log directory")
	cmd.Flags().IntVar(&logMaxSizeMB, "log-max-size", 100, "Max log size in MB before rotation")
	cmd.Flags().BoolVar(&noLog, "no-log", false, "Disable file logging")
	cmd.Flags().BoolVar(&debug, "debug", false, "Enable debug output")

	return cmd
}

func newAttachCommand() *cobra.Command {
	var (
		pid        int
		mode       string
		minLatency uint64
		logDir     string
		noLog      bool
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

			cfg := runner.DefaultConfig()
			cfg.Mode = mode
			cfg.TargetPID = uint32(pid)
			cfg.MinLatencyMs = minLatency
			cfg.EnablePrometheus = false

			if noLog {
				cfg.EnableLogging = false
			} else if logDir != "" {
				cfg.LogDir = logDir
			}

			r, err := runner.New(cfg)
			if err != nil {
				return fmt.Errorf("failed to create runner: %w", err)
			}
			defer r.Close()

			ctx := context.Background()
			return r.Run(ctx)
		},
	}

	cmd.Flags().IntVar(&pid, "pid", 0, "Process ID to attach to")
	cmd.Flags().StringVar(&mode, "mode", "auto", "Probe mode: auto, openssl, gnutls, nss, http")
	cmd.Flags().Uint64Var(&minLatency, "min-latency", 0, "Minimum latency in ms to report")
	cmd.Flags().StringVar(&logDir, "log-dir", "/var/log/s3slower", "Log directory")
	cmd.Flags().BoolVar(&noLog, "no-log", false, "Disable file logging")

	return cmd
}

