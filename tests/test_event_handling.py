"""
Tests for event handling in s3slower.core.

These tests verify the behavior of the TracerCore event handling
methods with mocked BPF events.
"""

from __future__ import annotations

import ctypes as ct
import threading
from unittest.mock import MagicMock, patch

import pytest


class TestTracerCoreEventHandling:
    """Tests for TracerCore._handle_event method."""

    @pytest.fixture
    def mock_event(self) -> MagicMock:
        """Create a mock event structure."""
        from s3slower.core import Event

        # Create a real Event instance
        event = Event()
        event.ts = 1703462400000000000
        event.delta = 15000000  # 15ms in ns
        event.pid = 12345
        event.tid = 12345
        event.op = 1  # GET
        event.comm = b"python3\x00\x00\x00\x00\x00\x00\x00\x00"
        event.req_hdr = (
            b"GET /mybucket/mykey.txt HTTP/1.1\r\n"
            b"Host: s3.amazonaws.com\r\n"
            b"Content-Length: 0\r\n\r\n"
        ).ljust(256, b"\x00")
        event.resp_hdr = b"HTTP/1.1 200 OK\r\n\r\n".ljust(256, b"\x00")

        return event

    @patch("s3slower.core.BPF")
    def test_handle_event_basic(
        self, mock_bpf_class: MagicMock, mock_event: MagicMock, capsys: pytest.CaptureFixture
    ) -> None:
        """Basic event handling prints output."""
        from s3slower.core import Event, RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        # Convert mock_event to bytes
        event_bytes = bytes(mock_event)

        tracer._handle_event(0, event_bytes, len(event_bytes))

        captured = capsys.readouterr()
        # Should print the event details
        assert "python3" in captured.out or "GET" in captured.out or "mybucket" in captured.out

    @patch("s3slower.core.BPF")
    def test_handle_event_pid_filter(
        self, mock_bpf_class: MagicMock, mock_event: MagicMock, capsys: pytest.CaptureFixture
    ) -> None:
        """Event from non-matching PID is filtered."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
            pid_filter=99999,  # Different from mock_event.pid (12345)
        )

        event_bytes = bytes(mock_event)
        tracer._handle_event(0, event_bytes, len(event_bytes))

        captured = capsys.readouterr()
        # Should not print anything for non-matching PID
        assert captured.out == "" or "mybucket" not in captured.out

    @patch("s3slower.core.BPF")
    def test_handle_event_method_filter(
        self, mock_bpf_class: MagicMock, capsys: pytest.CaptureFixture
    ) -> None:
        """Event with non-matching method is filtered."""
        from s3slower.core import Event, RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter={"PUT"},  # Only allow PUT
            min_lat_ms=0.0,
            include_unknown=False,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        # Create GET event
        event = Event()
        event.ts = 1703462400000000000
        event.delta = 15000000
        event.pid = 12345
        event.tid = 12345
        event.op = 1  # GET
        event.comm = b"python3\x00\x00\x00\x00\x00\x00\x00\x00"
        event.req_hdr = b"GET /mybucket/key HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n".ljust(
            256, b"\x00"
        )
        event.resp_hdr = b"HTTP/1.1 200 OK\r\n\r\n".ljust(256, b"\x00")

        event_bytes = bytes(event)
        tracer._handle_event(0, event_bytes, len(event_bytes))

        captured = capsys.readouterr()
        # GET should be filtered out
        assert "GET" not in captured.out or captured.out == ""

    @patch("s3slower.core.BPF")
    def test_handle_event_host_filter(
        self, mock_bpf_class: MagicMock, capsys: pytest.CaptureFixture
    ) -> None:
        """Event with non-matching host is filtered."""
        from s3slower.core import Event, RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter="minio",  # Only allow minio hosts
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        # Create event with s3.amazonaws.com host
        event = Event()
        event.ts = 1703462400000000000
        event.delta = 15000000
        event.pid = 12345
        event.tid = 12345
        event.op = 1
        event.comm = b"python3\x00\x00\x00\x00\x00\x00\x00\x00"
        event.req_hdr = b"GET / HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n".ljust(256, b"\x00")
        event.resp_hdr = b"HTTP/1.1 200 OK\r\n\r\n".ljust(256, b"\x00")

        event_bytes = bytes(event)
        tracer._handle_event(0, event_bytes, len(event_bytes))

        captured = capsys.readouterr()
        # s3.amazonaws.com should be filtered out
        assert captured.out == "" or "amazonaws" not in captured.out

    @patch("s3slower.core.BPF")
    def test_handle_event_min_latency_filter(
        self, mock_bpf_class: MagicMock, capsys: pytest.CaptureFixture
    ) -> None:
        """Event with latency below minimum is filtered."""
        from s3slower.core import Event, RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=100.0,  # Only show events >= 100ms
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        # Create event with 15ms latency
        event = Event()
        event.ts = 1703462400000000000
        event.delta = 15000000  # 15ms
        event.pid = 12345
        event.tid = 12345
        event.op = 1
        event.comm = b"python3\x00\x00\x00\x00\x00\x00\x00\x00"
        event.req_hdr = b"GET / HTTP/1.1\r\nHost: s3.amazonaws.com\r\n\r\n".ljust(256, b"\x00")
        event.resp_hdr = b"HTTP/1.1 200 OK\r\n\r\n".ljust(256, b"\x00")

        event_bytes = bytes(event)
        tracer._handle_event(0, event_bytes, len(event_bytes))

        captured = capsys.readouterr()
        # 15ms < 100ms, should be filtered out
        assert captured.out == ""

    @patch("s3slower.core.BPF")
    def test_handle_event_updates_stats(
        self, mock_bpf_class: MagicMock, mock_event: MagicMock
    ) -> None:
        """Event updates internal statistics."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        event_bytes = bytes(mock_event)
        tracer._handle_event(0, event_bytes, len(event_bytes))

        # Stats should be updated
        assert len(tracer.stats) > 0
        assert "ALL" in tracer.stats
        assert len(tracer.stats["ALL"]) == 1

    @patch("s3slower.core.BPF")
    def test_handle_event_with_metrics_sink(
        self, mock_bpf_class: MagicMock, mock_event: MagicMock
    ) -> None:
        """Event is recorded to metrics sink."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf
        mock_metrics_sink = MagicMock()

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=mock_metrics_sink,
            transaction_logger=None,
        )

        event_bytes = bytes(mock_event)
        tracer._handle_event(0, event_bytes, len(event_bytes))

        mock_metrics_sink.record.assert_called_once()

    @patch("s3slower.core.BPF")
    def test_handle_event_with_transaction_logger(
        self, mock_bpf_class: MagicMock, mock_event: MagicMock
    ) -> None:
        """Event is logged to transaction logger."""
        from s3slower.core import RuntimeSettings, TracerCore
        import logging

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf
        mock_logger = MagicMock(spec=logging.Logger)

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=mock_logger,
        )

        event_bytes = bytes(mock_event)
        tracer._handle_event(0, event_bytes, len(event_bytes))

        mock_logger.info.assert_called_once()


class TestTracerCoreRun:
    """Tests for TracerCore.run method."""

    @patch("s3slower.core.BPF")
    def test_run_opens_perf_buffer(self, mock_bpf_class: MagicMock) -> None:
        """Run opens perf buffer and polls."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        stop_event = threading.Event()
        stop_event.set()  # Set immediately so run exits

        tracer.run(stop_event)

        # Should have opened perf buffer
        mock_bpf.__getitem__.return_value.open_perf_buffer.assert_called_once()

    @patch("s3slower.core.BPF")
    def test_run_respects_stop_event(self, mock_bpf_class: MagicMock) -> None:
        """Run exits when stop event is set."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        stop_event = threading.Event()

        def set_stop_after_first_poll(*args, **kwargs):
            stop_event.set()

        mock_bpf.perf_buffer_poll.side_effect = set_stop_after_first_poll

        # Should exit after first poll
        tracer.run(stop_event)

        assert stop_event.is_set()


class TestTracerCoreHelperMethods:
    """Tests for TracerCore helper methods."""

    @patch("s3slower.core.BPF")
    def test_truncate_for_display_short_string(self, mock_bpf_class: MagicMock) -> None:
        """Short strings are not truncated."""
        from s3slower.core import TracerCore

        result = TracerCore._truncate_for_display("short", 20)
        assert result == "short"

    @patch("s3slower.core.BPF")
    def test_truncate_for_display_exact_length(self, mock_bpf_class: MagicMock) -> None:
        """Strings at exactly max width are not truncated."""
        from s3slower.core import TracerCore

        result = TracerCore._truncate_for_display("12345678901234567890", 20)
        assert result == "12345678901234567890"

    @patch("s3slower.core.BPF")
    def test_truncate_for_display_long_string(self, mock_bpf_class: MagicMock) -> None:
        """Long strings are truncated with suffix."""
        from s3slower.core import TracerCore

        result = TracerCore._truncate_for_display("this-is-a-very-long-bucket-name", 20)
        assert len(result) == 20
        assert result.endswith("..")

    @patch("s3slower.core.BPF")
    def test_passes_method_filter_no_filter(self, mock_bpf_class: MagicMock) -> None:
        """No filter means all methods pass."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf_class.return_value = MagicMock()
        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        assert tracer._passes_method_filter("GET") is True
        assert tracer._passes_method_filter("PUT") is True
        assert tracer._passes_method_filter("") is True

    @patch("s3slower.core.BPF")
    def test_passes_method_filter_with_filter(self, mock_bpf_class: MagicMock) -> None:
        """Filter restricts to specified methods."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf_class.return_value = MagicMock()
        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter={"GET", "PUT"},
            min_lat_ms=0.0,
            include_unknown=False,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        assert tracer._passes_method_filter("GET") is True
        assert tracer._passes_method_filter("PUT") is True
        assert tracer._passes_method_filter("DELETE") is False
        assert tracer._passes_method_filter("") is False  # Empty method, include_unknown=False

    @patch("s3slower.core.BPF")
    def test_passes_method_filter_case_insensitive(self, mock_bpf_class: MagicMock) -> None:
        """Method filter is case-insensitive."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf_class.return_value = MagicMock()
        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter={"GET"},
            min_lat_ms=0.0,
            include_unknown=False,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        assert tracer._passes_method_filter("get") is True
        assert tracer._passes_method_filter("Get") is True
        assert tracer._passes_method_filter("GET") is True

    @patch("s3slower.core.BPF")
    def test_passes_host_filter_no_filter(self, mock_bpf_class: MagicMock) -> None:
        """No filter means all hosts pass."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf_class.return_value = MagicMock()
        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        assert tracer._passes_host_filter("s3.amazonaws.com") is True
        assert tracer._passes_host_filter("minio.local") is True
        assert tracer._passes_host_filter("") is True

    @patch("s3slower.core.BPF")
    def test_passes_host_filter_with_filter(self, mock_bpf_class: MagicMock) -> None:
        """Filter restricts to hosts containing substring."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf_class.return_value = MagicMock()
        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter="minio",
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        assert tracer._passes_host_filter("minio.local") is True
        assert tracer._passes_host_filter("minio-cluster.local") is True
        assert tracer._passes_host_filter("s3.amazonaws.com") is False
        assert tracer._passes_host_filter("") is False

    @patch("s3slower.core.BPF")
    def test_passes_host_filter_case_insensitive(self, mock_bpf_class: MagicMock) -> None:
        """Host filter is case-insensitive."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf_class.return_value = MagicMock()
        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter="minio",
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=True,
            want_http=True,
            want_tls=False,
            enabled_tls_modes=set(),
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        assert tracer._passes_host_filter("MINIO.local") is True
        assert tracer._passes_host_filter("Minio.Local") is True

    def test_classify_method_bucket_simple(self) -> None:
        """Simple HTTP methods are classified correctly."""
        from s3slower.core import TracerCore

        assert TracerCore._classify_method_bucket("GET", "/bucket/key", "UNK") == "GET"
        assert TracerCore._classify_method_bucket("PUT", "/bucket/key", "UNK") == "PUT"
        assert TracerCore._classify_method_bucket("DELETE", "/bucket/key", "UNK") == "DELETE"
        assert TracerCore._classify_method_bucket("HEAD", "/bucket/key", "UNK") == "HEAD"

    def test_classify_method_bucket_fallback(self) -> None:
        """Empty method uses fallback."""
        from s3slower.core import TracerCore

        assert TracerCore._classify_method_bucket("", "/bucket/key", "GET") == "GET"
        assert TracerCore._classify_method_bucket("", "/bucket/key", "UNK") == "UNK"

    def test_classify_method_bucket_mpu_create(self) -> None:
        """POST with ?uploads is classified as MPU_CREATE."""
        from s3slower.core import TracerCore

        result = TracerCore._classify_method_bucket("POST", "/bucket/key?uploads", "UNK")
        assert result == "MPU_CREATE"

    def test_classify_method_bucket_mpu_complete(self) -> None:
        """POST with ?uploadId= is classified as MPU_COMPLETE."""
        from s3slower.core import TracerCore

        result = TracerCore._classify_method_bucket(
            "POST", "/bucket/key?uploadId=abc123", "UNK"
        )
        assert result == "MPU_COMPLETE"

    def test_classify_method_bucket_mpu_part(self) -> None:
        """PUT with ?uploadId= stays as PUT (part upload)."""
        from s3slower.core import TracerCore

        result = TracerCore._classify_method_bucket(
            "PUT", "/bucket/key?partNumber=1&uploadId=abc123", "UNK"
        )
        assert result == "PUT"

    def test_classify_method_bucket_regular_post(self) -> None:
        """Regular POST without MPU markers stays as POST."""
        from s3slower.core import TracerCore

        result = TracerCore._classify_method_bucket("POST", "/bucket/key", "UNK")
        assert result == "POST"

    def test_classify_method_bucket_case_insensitive(self) -> None:
        """Method classification is case-insensitive."""
        from s3slower.core import TracerCore

        assert TracerCore._classify_method_bucket("post", "/bucket/key?uploads", "UNK") == "MPU_CREATE"
        assert TracerCore._classify_method_bucket("Post", "/bucket/key?uploads", "UNK") == "MPU_CREATE"
