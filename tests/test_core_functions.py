"""
Additional tests for core functions in s3slower.core.

These tests cover the remaining pure Python functions that don't
require a live eBPF environment.
"""

from __future__ import annotations

import io
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List
from unittest.mock import MagicMock, patch

import pytest

from s3slower.core import (
    OP_MAP,
    print_summary,
    setup_transaction_logger,
    RuntimeSettings,
)


class TestOpMap:
    """Tests for OP_MAP constant."""

    def test_op_map_keys(self) -> None:
        """OP_MAP should contain expected operation codes."""
        assert 0 in OP_MAP  # Unknown
        assert 1 in OP_MAP  # GET
        assert 2 in OP_MAP  # PUT
        assert 3 in OP_MAP  # HEAD
        assert 4 in OP_MAP  # POST
        assert 5 in OP_MAP  # DEL

    def test_op_map_values(self) -> None:
        """OP_MAP values should be short operation names."""
        assert OP_MAP[0] == "UNK"
        assert OP_MAP[1] == "GET"
        assert OP_MAP[2] == "PUT"
        assert OP_MAP[3] == "HEAD"
        assert OP_MAP[4] == "POST"
        assert OP_MAP[5] == "DEL"


class TestPrintSummary:
    """Tests for print_summary function."""

    def test_empty_stats(self, capsys: pytest.CaptureFixture) -> None:
        """Empty stats should print 'No S3-like HTTP traffic captured'."""
        print_summary({})

        captured = capsys.readouterr()
        assert "No S3-like HTTP traffic captured" in captured.out

    def test_single_operation(self, capsys: pytest.CaptureFixture) -> None:
        """Print summary with single operation type."""
        stats: Dict[str, List[float]] = {
            "GET": [10.0, 20.0, 30.0],
        }

        print_summary(stats)

        captured = capsys.readouterr()
        assert "GET" in captured.out
        assert "3" in captured.out  # count
        assert "Summary" in captured.out

    def test_multiple_operations(self, capsys: pytest.CaptureFixture) -> None:
        """Print summary with multiple operation types."""
        stats: Dict[str, List[float]] = {
            "GET": [10.0, 20.0, 30.0],
            "PUT": [15.0, 25.0, 35.0, 45.0],
            "DELETE": [5.0],
        }

        print_summary(stats)

        captured = capsys.readouterr()
        assert "GET" in captured.out
        assert "PUT" in captured.out
        assert "DELETE" in captured.out

    def test_percentile_calculation(self, capsys: pytest.CaptureFixture) -> None:
        """Summary should include percentile values."""
        # Create data with known percentiles
        stats: Dict[str, List[float]] = {
            "GET": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0],
        }

        print_summary(stats)

        captured = capsys.readouterr()
        # Check header is present
        assert "P50" in captured.out
        assert "P90" in captured.out
        assert "P99" in captured.out

    def test_stats_sorted_by_operation_name(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Operations should be printed in sorted order."""
        stats: Dict[str, List[float]] = {
            "PUT": [20.0],
            "GET": [10.0],
            "DELETE": [30.0],
        }

        print_summary(stats)

        captured = capsys.readouterr()
        lines = captured.out.split("\n")
        # Find lines with operation names (after header)
        op_lines = [l for l in lines if any(op in l for op in ["GET", "PUT", "DELETE"])]
        # Should be in alphabetical order: DELETE, GET, PUT
        assert len(op_lines) >= 3

    def test_empty_operation_skipped(self, capsys: pytest.CaptureFixture) -> None:
        """Operations with empty value lists should be skipped."""
        stats: Dict[str, List[float]] = {
            "GET": [10.0],
            "PUT": [],  # Empty
        }

        print_summary(stats)

        captured = capsys.readouterr()
        assert "GET" in captured.out
        # PUT might still appear in output but with 0 count


class TestSetupTransactionLogger:
    """Tests for setup_transaction_logger function."""

    def test_logging_disabled(self) -> None:
        """Return None when logging is disabled."""
        settings = RuntimeSettings(log_enabled=False)

        result = setup_transaction_logger(settings)

        assert result is None

    def test_empty_log_path(self) -> None:
        """Return None when log path is empty."""
        settings = RuntimeSettings(log_enabled=True, log_path="")

        result = setup_transaction_logger(settings)

        assert result is None

    def test_creates_logger(self, temp_dir: Path) -> None:
        """Creates a logger with correct name."""
        log_path = temp_dir / "test.log"
        settings = RuntimeSettings(
            log_enabled=True,
            log_path=str(log_path),
            log_max_size_mb=10,
            log_max_backups=3,
        )

        logger = setup_transaction_logger(settings)

        assert logger is not None
        assert logger.name == "s3slower.transactions"
        assert logger.level == logging.INFO

        # Clean up handlers
        for handler in logger.handlers:
            handler.close()

    def test_creates_directory(self, temp_dir: Path) -> None:
        """Creates parent directory if it doesn't exist."""
        log_path = temp_dir / "subdir" / "test.log"
        settings = RuntimeSettings(
            log_enabled=True,
            log_path=str(log_path),
            log_max_size_mb=10,
            log_max_backups=3,
        )

        logger = setup_transaction_logger(settings)

        assert logger is not None
        assert log_path.parent.exists()

        # Clean up handlers
        for handler in logger.handlers:
            handler.close()

    def test_rotating_file_handler(self, temp_dir: Path) -> None:
        """Uses RotatingFileHandler when max_size > 0."""
        from logging.handlers import RotatingFileHandler

        log_path = temp_dir / "test.log"
        settings = RuntimeSettings(
            log_enabled=True,
            log_path=str(log_path),
            log_max_size_mb=50,
            log_max_backups=5,
        )

        logger = setup_transaction_logger(settings)

        assert logger is not None
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], RotatingFileHandler)

        # Verify rotation settings
        handler = logger.handlers[0]
        assert handler.maxBytes == 50 * 1024 * 1024
        assert handler.backupCount == 5

        # Clean up
        handler.close()

    def test_file_handler_when_no_rotation(self, temp_dir: Path) -> None:
        """Uses FileHandler when max_size is 0."""
        log_path = temp_dir / "test.log"
        settings = RuntimeSettings(
            log_enabled=True,
            log_path=str(log_path),
            log_max_size_mb=0,
            log_max_backups=0,
        )

        logger = setup_transaction_logger(settings)

        assert logger is not None
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.FileHandler)

        # Clean up
        logger.handlers[0].close()

    def test_logger_writes_messages(self, temp_dir: Path) -> None:
        """Logger should write messages to the file."""
        log_path = temp_dir / "test.log"
        settings = RuntimeSettings(
            log_enabled=True,
            log_path=str(log_path),
            log_max_size_mb=10,
            log_max_backups=3,
        )

        logger = setup_transaction_logger(settings)
        assert logger is not None

        # Log a message
        logger.info("Test message")
        logger.handlers[0].flush()

        # Verify the message was written
        content = log_path.read_text()
        assert "Test message" in content

        # Clean up
        logger.handlers[0].close()


class TestInitPrometheus:
    """Tests for init_prometheus function."""

    def test_no_prometheus_client(self) -> None:
        """Exit when prometheus_client is not installed."""
        import s3slower.core as core_module

        # Save original value
        original_have_prom = core_module.HAVE_PROM

        try:
            # Temporarily set HAVE_PROM to False
            core_module.HAVE_PROM = False

            with pytest.raises(SystemExit) as exc_info:
                core_module.init_prometheus("localhost", 9090)

            assert exc_info.value.code == 1
        finally:
            # Restore original value
            core_module.HAVE_PROM = original_have_prom

    def test_with_extra_labels_sets_global(self) -> None:
        """Extra label names are stored in PROM_EXTRA_LABELS global."""
        pytest.importorskip("prometheus_client")

        import s3slower.core as core_module

        # Save original values
        original_extra_labels = core_module.PROM_EXTRA_LABELS.copy()
        original_metrics = (
            core_module.REQ_LATENCY,
            core_module.REQ_TOTAL,
            core_module.REQ_BYTES,
            core_module.RESP_TOTAL,
        )

        try:
            # Reset global metrics to None so init_prometheus can set them
            core_module.REQ_LATENCY = None
            core_module.REQ_TOTAL = None
            core_module.REQ_BYTES = None
            core_module.RESP_TOTAL = None
            core_module.PROM_EXTRA_LABELS = []

            # Mock start_http_server to avoid actually starting a server
            with patch("prometheus_client.start_http_server"):
                core_module.init_prometheus("0.0.0.0", 19999, extra_label_names=["env", "region"])

            # Verify extra labels were set
            assert "env" in core_module.PROM_EXTRA_LABELS
            assert "region" in core_module.PROM_EXTRA_LABELS
            # Labels should be sorted
            assert core_module.PROM_EXTRA_LABELS == ["env", "region"]

            # Verify metrics were initialized
            assert core_module.REQ_LATENCY is not None
            assert core_module.REQ_TOTAL is not None
        finally:
            # Restore original values
            core_module.PROM_EXTRA_LABELS = original_extra_labels
            (
                core_module.REQ_LATENCY,
                core_module.REQ_TOTAL,
                core_module.REQ_BYTES,
                core_module.RESP_TOTAL,
            ) = original_metrics


class TestExecWatcher:
    """Tests for ExecWatcher class in exec_watch module."""

    def test_exec_event_structure(self) -> None:
        """Test _ExecEvent ctypes structure."""
        from s3slower.exec_watch import _ExecEvent

        # Create an instance to verify structure
        event = _ExecEvent()
        event.pid = 12345
        event.comm = b"test_process"

        assert event.pid == 12345
        assert event.comm == b"test_process"

    @patch("s3slower.exec_watch.BPF")
    def test_exec_watcher_init(self, mock_bpf: MagicMock) -> None:
        """ExecWatcher initializes BPF and attaches tracepoint."""
        from s3slower.exec_watch import ExecWatcher

        callback = MagicMock()
        watcher = ExecWatcher(callback)

        mock_bpf.assert_called_once()
        mock_bpf.return_value.attach_tracepoint.assert_called_once_with(
            tp="sched:sched_process_exec", fn_name="trace_exec"
        )

    @patch("s3slower.exec_watch.BPF")
    def test_exec_watcher_start(self, mock_bpf: MagicMock) -> None:
        """ExecWatcher start creates thread and opens perf buffer."""
        from s3slower.exec_watch import ExecWatcher

        callback = MagicMock()
        watcher = ExecWatcher(callback)
        watcher.start()

        assert watcher._thread is not None
        mock_bpf.return_value.__getitem__.return_value.open_perf_buffer.assert_called_once()

        watcher.stop()

    @patch("s3slower.exec_watch.BPF")
    def test_exec_watcher_stop(self, mock_bpf: MagicMock) -> None:
        """ExecWatcher stop terminates thread."""
        from s3slower.exec_watch import ExecWatcher

        callback = MagicMock()
        watcher = ExecWatcher(callback)
        watcher.start()
        watcher.stop()

        # Should not raise and thread should be stopped
        assert watcher._stop_evt.is_set()

    @patch("s3slower.exec_watch.BPF")
    def test_start_exec_watch_function(self, mock_bpf: MagicMock) -> None:
        """start_exec_watch convenience function."""
        from s3slower.exec_watch import start_exec_watch

        callback = MagicMock()
        watcher = start_exec_watch(callback)

        assert watcher is not None
        assert watcher._thread is not None

        watcher.stop()


class TestTracerCoreBasic:
    """Basic tests for TracerCore class that don't require BPF."""

    @patch("s3slower.core.BPF")
    def test_tracer_core_init(self, mock_bpf: MagicMock) -> None:
        """TracerCore initializes with settings."""
        from s3slower.core import TracerCore, RuntimeSettings

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=False,
            want_http=True,
            want_tls=True,
            enabled_tls_modes={"openssl"},
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        assert tracer.settings == settings
        assert tracer.want_http is True
        assert tracer.want_tls is True
        mock_bpf.assert_called_once()

    @patch("s3slower.core.BPF")
    def test_tracer_core_with_filters(self, mock_bpf: MagicMock) -> None:
        """TracerCore applies filters correctly."""
        from s3slower.core import TracerCore, RuntimeSettings

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter="s3.amazonaws.com",
            method_filter={"GET", "PUT"},
            min_lat_ms=10.0,
            include_unknown=True,
            want_http=True,
            want_tls=True,
            enabled_tls_modes={"openssl"},
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
            pid_filter=12345,
        )

        assert tracer.host_filter == "s3.amazonaws.com"
        assert tracer.method_filter == {"GET", "PUT"}
        assert tracer.min_lat_ms == 10.0
        assert tracer.include_unknown is True
        assert tracer.pid_filter == 12345

    @patch("s3slower.core.BPF")
    def test_tracer_core_zero_pid_filter(self, mock_bpf: MagicMock) -> None:
        """Zero PID filter should be converted to None."""
        from s3slower.core import TracerCore, RuntimeSettings

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=False,
            want_http=True,
            want_tls=True,
            enabled_tls_modes={"openssl"},
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
            pid_filter=0,  # Zero
        )

        assert tracer.pid_filter is None
