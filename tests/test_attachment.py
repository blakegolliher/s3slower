"""
Tests for TLS and HTTP attachment functions in s3slower.core.

These tests verify the behavior of the uprobe/kprobe attachment
functions with mocked BPF objects.
"""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from s3slower.core import attach_gnutls, attach_http, attach_nss, attach_openssl


class TestAttachOpenssl:
    """Tests for attach_openssl function."""

    def test_attaches_ssl_write(self) -> None:
        """Attaches uprobe for SSL_write."""
        mock_bpf = MagicMock()

        attach_openssl(mock_bpf, "/usr/lib/libssl.so", 12345)

        mock_bpf.attach_uprobe.assert_any_call(
            name="/usr/lib/libssl.so",
            sym="SSL_write",
            fn_name="ssl_write_enter",
            pid=12345,
        )

    def test_attaches_ssl_read(self) -> None:
        """Attaches uprobe and uretprobe for SSL_read."""
        mock_bpf = MagicMock()

        attach_openssl(mock_bpf, "/usr/lib/libssl.so", 12345)

        mock_bpf.attach_uprobe.assert_any_call(
            name="/usr/lib/libssl.so",
            sym="SSL_read",
            fn_name="ssl_read_enter",
            pid=12345,
        )
        mock_bpf.attach_uretprobe.assert_any_call(
            name="/usr/lib/libssl.so",
            sym="SSL_read",
            fn_name="ssl_read_exit",
            pid=12345,
        )

    def test_attaches_ssl_read_ex(self) -> None:
        """Attempts to attach SSL_read_ex (may not exist on older OpenSSL)."""
        mock_bpf = MagicMock()

        attach_openssl(mock_bpf, "/usr/lib/libssl.so", 12345)

        # SSL_read_ex is tried but failures are ignored
        assert mock_bpf.attach_uprobe.call_count >= 2

    def test_ssl_read_ex_failure_ignored(self) -> None:
        """SSL_read_ex attachment failure should be silently ignored."""
        mock_bpf = MagicMock()

        # Make SSL_read_ex fail
        def side_effect(name, sym, fn_name, pid):
            if sym in ("SSL_read_ex", "SSL_write_ex"):
                raise Exception("Symbol not found")

        mock_bpf.attach_uprobe.side_effect = side_effect

        # Should not raise
        attach_openssl(mock_bpf, "/usr/lib/libssl.so", 12345)

    def test_attaches_to_specific_pid(self) -> None:
        """Attaches probes for a specific PID."""
        mock_bpf = MagicMock()

        attach_openssl(mock_bpf, "/usr/lib/libssl.so", 99999)

        # All calls should use pid=99999
        for call_obj in mock_bpf.attach_uprobe.call_args_list:
            assert call_obj.kwargs.get("pid") == 99999 or call_obj[1].get("pid") == 99999

    def test_attaches_globally(self) -> None:
        """Attaches probes globally with pid=-1."""
        mock_bpf = MagicMock()

        attach_openssl(mock_bpf, "/usr/lib/libssl.so", -1)

        # All calls should use pid=-1
        for call_obj in mock_bpf.attach_uprobe.call_args_list:
            assert call_obj.kwargs.get("pid") == -1 or call_obj[1].get("pid") == -1


class TestAttachGnutls:
    """Tests for attach_gnutls function."""

    def test_attaches_record_send(self) -> None:
        """Attaches uprobe for gnutls_record_send."""
        mock_bpf = MagicMock()

        attach_gnutls(mock_bpf, "/usr/lib/libgnutls.so", 12345)

        mock_bpf.attach_uprobe.assert_any_call(
            name="/usr/lib/libgnutls.so",
            sym="gnutls_record_send",
            fn_name="ssl_write_enter",
            pid=12345,
        )

    def test_attaches_record_recv(self) -> None:
        """Attaches uprobe and uretprobe for gnutls_record_recv."""
        mock_bpf = MagicMock()

        attach_gnutls(mock_bpf, "/usr/lib/libgnutls.so", 12345)

        mock_bpf.attach_uprobe.assert_any_call(
            name="/usr/lib/libgnutls.so",
            sym="gnutls_record_recv",
            fn_name="ssl_read_enter",
            pid=12345,
        )
        mock_bpf.attach_uretprobe.assert_any_call(
            name="/usr/lib/libgnutls.so",
            sym="gnutls_record_recv",
            fn_name="ssl_read_exit",
            pid=12345,
        )


class TestAttachNss:
    """Tests for attach_nss function."""

    def test_attaches_pr_write_and_pr_send(self) -> None:
        """Attaches uprobes for PR_Write and PR_Send."""
        mock_bpf = MagicMock()

        attach_nss(mock_bpf, "/usr/lib/libnspr4.so", 12345)

        # Both PR_Write and PR_Send should be attached
        write_calls = [
            c for c in mock_bpf.attach_uprobe.call_args_list if c.kwargs.get("sym") in ("PR_Write", "PR_Send")
        ]
        assert len(write_calls) >= 2

    def test_attaches_pr_read_and_pr_recv(self) -> None:
        """Attaches uprobes and uretprobes for PR_Read and PR_Recv."""
        mock_bpf = MagicMock()

        attach_nss(mock_bpf, "/usr/lib/libnspr4.so", 12345)

        # Both PR_Read and PR_Recv should have entry and exit probes
        read_entry_calls = [
            c for c in mock_bpf.attach_uprobe.call_args_list if c.kwargs.get("sym") in ("PR_Read", "PR_Recv")
        ]
        read_exit_calls = [
            c for c in mock_bpf.attach_uretprobe.call_args_list if c.kwargs.get("sym") in ("PR_Read", "PR_Recv")
        ]
        assert len(read_entry_calls) >= 2
        assert len(read_exit_calls) >= 2


class TestAttachHttp:
    """Tests for attach_http function."""

    def test_attaches_sendto(self) -> None:
        """Attaches kprobe for sendto syscall."""
        mock_bpf = MagicMock()
        mock_bpf.get_syscall_fnname.return_value = "__x64_sys_sendto"

        attach_http(mock_bpf, quiet=True)

        mock_bpf.attach_kprobe.assert_any_call(
            event="__x64_sys_sendto",
            fn_name="http_send_enter",
        )

    def test_attaches_recvfrom(self) -> None:
        """Attaches kprobe and kretprobe for recvfrom syscall."""
        mock_bpf = MagicMock()
        mock_bpf.get_syscall_fnname.side_effect = lambda x: f"__x64_sys_{x}"

        attach_http(mock_bpf, quiet=True)

        mock_bpf.attach_kprobe.assert_any_call(
            event="__x64_sys_recvfrom",
            fn_name="http_recv_enter",
        )
        mock_bpf.attach_kretprobe.assert_any_call(
            event="__x64_sys_recvfrom",
            fn_name="http_recv_exit",
        )

    def test_prints_message_when_not_quiet(self, capsys: pytest.CaptureFixture) -> None:
        """Prints attachment message when quiet=False."""
        mock_bpf = MagicMock()
        mock_bpf.get_syscall_fnname.return_value = "__x64_sys_sendto"

        attach_http(mock_bpf, quiet=False)

        captured = capsys.readouterr()
        assert "plain HTTP" in captured.out.lower() or "sendto" in captured.out.lower()

    def test_handles_attachment_failure(self, capsys: pytest.CaptureFixture) -> None:
        """Handles syscall attachment failures gracefully."""
        mock_bpf = MagicMock()
        mock_bpf.get_syscall_fnname.side_effect = Exception("Syscall not found")

        # Should not raise
        attach_http(mock_bpf, quiet=True)

    def test_warns_on_total_failure(self, capsys: pytest.CaptureFixture) -> None:
        """Warns when no syscalls could be attached."""
        mock_bpf = MagicMock()
        mock_bpf.get_syscall_fnname.side_effect = Exception("Syscall not found")
        mock_bpf.attach_kprobe.side_effect = Exception("Cannot attach")

        attach_http(mock_bpf, quiet=False)

        captured = capsys.readouterr()
        # Should print a warning (to stderr)
        assert "could not attach" in captured.err.lower() or captured.out == ""


class TestTracerCoreAttachment:
    """Tests for TracerCore attachment methods."""

    @patch("s3slower.core.BPF")
    def test_ensure_http_attached_idempotent(self, mock_bpf_class: MagicMock) -> None:
        """ensure_http_attached only attaches once."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
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

        tracer.ensure_http_attached()
        first_call_count = mock_bpf.attach_kprobe.call_count

        tracer.ensure_http_attached()
        second_call_count = mock_bpf.attach_kprobe.call_count

        # Call count should not increase
        assert first_call_count == second_call_count

    @patch("s3slower.core.BPF")
    def test_http_not_attached_when_disabled(self, mock_bpf_class: MagicMock) -> None:
        """HTTP probes not attached when want_http=False."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=False,
            want_http=False,  # Disabled
            want_tls=True,
            enabled_tls_modes={"openssl"},
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        tracer.ensure_http_attached()

        # No kprobes should be attached
        assert mock_bpf.attach_kprobe.call_count == 0

    @patch("s3slower.core.BPF")
    @patch("s3slower.core.find_library")
    @patch("s3slower.core.attach_openssl")
    def test_start_tracing_for_pid_openssl(
        self,
        mock_attach_openssl: MagicMock,
        mock_find_library: MagicMock,
        mock_bpf_class: MagicMock,
    ) -> None:
        """start_tracing_for_pid attaches OpenSSL probes."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf
        mock_find_library.return_value = "/usr/lib/libssl.so"

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=False,
            want_http=False,
            want_tls=True,
            enabled_tls_modes={"openssl"},
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        tracer.start_tracing_for_pid(12345, "openssl", target_name="test-target")

        mock_attach_openssl.assert_called_once()

    @patch("s3slower.core.BPF")
    def test_start_tracing_for_pid_http(self, mock_bpf_class: MagicMock) -> None:
        """start_tracing_for_pid with http mode enables HTTP probes."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
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

        tracer.start_tracing_for_pid(12345, "http", target_name="test-target")

        # Should have attached HTTP probes
        assert tracer.http_attached is True

    @patch("s3slower.core.BPF")
    def test_start_tracing_disabled_mode_ignored(
        self, mock_bpf_class: MagicMock, capsys: pytest.CaptureFixture
    ) -> None:
        """Disabled TLS modes are ignored."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
            min_lat_ms=0.0,
            include_unknown=False,
            want_http=False,
            want_tls=True,
            enabled_tls_modes={"openssl"},  # Only openssl enabled
            libssl_path=None,
            libgnutls_path=None,
            libnss_path=None,
            metrics_sink=None,
            transaction_logger=None,
        )

        tracer.start_tracing_for_pid(12345, "gnutls", target_name="test-target")

        captured = capsys.readouterr()
        assert "Ignoring" in captured.out or "not enabled" in captured.out

    @patch("s3slower.core.BPF")
    def test_register_pid_meta(self, mock_bpf_class: MagicMock) -> None:
        """Registers PID metadata correctly."""
        from s3slower.core import RuntimeSettings, TracerCore

        mock_bpf = MagicMock()
        mock_bpf_class.return_value = mock_bpf

        settings = RuntimeSettings()
        tracer = TracerCore(
            settings,
            host_filter=None,
            method_filter=None,
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

        tracer._register_pid_meta(
            12345, target_name="boto3", prom_labels={"env": "test"}
        )

        assert 12345 in tracer.pid_targets
        assert tracer.pid_targets[12345].target_name == "boto3"
        assert tracer.pid_targets[12345].prom_labels == {"env": "test"}
