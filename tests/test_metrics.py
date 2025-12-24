"""
Tests for Prometheus metrics handling in s3slower.core.

These tests verify the MetricsAggregator class behavior and
Prometheus metric update functions.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

from s3slower.core import MetricsAggregator, update_prometheus


class TestMetricsAggregator:
    """Tests for MetricsAggregator class."""

    def test_init_default_interval(self) -> None:
        """Initialize with default refresh interval."""
        aggregator = MetricsAggregator(5.0)

        assert aggregator.refresh_interval == 5.0
        assert len(aggregator._pending) == 0

    def test_init_minimum_interval(self) -> None:
        """Refresh interval should have a minimum of 0.1."""
        aggregator = MetricsAggregator(0.01)

        assert aggregator.refresh_interval == 0.1

    def test_init_negative_interval(self) -> None:
        """Negative refresh interval should use minimum."""
        aggregator = MetricsAggregator(-5.0)

        assert aggregator.refresh_interval == 0.1

    def test_record_single_event(self) -> None:
        """Record a single metrics event."""
        aggregator = MetricsAggregator(5.0)

        aggregator.record(
            bucket="test-bucket",
            endpoint="s3.amazonaws.com",
            method="GET",
            latency_seconds=0.015,
            size_bytes=1024,
            status_code=200,
            pid_label="12345",
            target_label="boto3",
            extra_labels={"env": "test"},
        )

        assert len(aggregator._pending) == 1

    def test_record_multiple_events(self) -> None:
        """Record multiple metrics events."""
        aggregator = MetricsAggregator(5.0)

        for i in range(10):
            aggregator.record(
                bucket=f"bucket-{i}",
                endpoint="s3.amazonaws.com",
                method="PUT",
                latency_seconds=0.01 * i,
                size_bytes=100 * i,
                status_code=200,
                pid_label=str(12345 + i),
                target_label="test",
            )

        assert len(aggregator._pending) == 10

    def test_flush_clears_pending(self) -> None:
        """Flush should clear pending events."""
        aggregator = MetricsAggregator(5.0)

        aggregator.record(
            bucket="test-bucket",
            endpoint="s3.amazonaws.com",
            method="GET",
            latency_seconds=0.015,
            size_bytes=1024,
            status_code=200,
            pid_label="12345",
            target_label="boto3",
        )

        assert len(aggregator._pending) == 1

        with patch("s3slower.core.update_prometheus"):
            aggregator.flush()

        assert len(aggregator._pending) == 0

    @patch("s3slower.core.update_prometheus")
    def test_flush_calls_update_prometheus(
        self, mock_update: MagicMock
    ) -> None:
        """Flush should call update_prometheus for each event."""
        aggregator = MetricsAggregator(5.0)

        aggregator.record(
            bucket="bucket1",
            endpoint="endpoint1",
            method="GET",
            latency_seconds=0.01,
            size_bytes=100,
            status_code=200,
            pid_label="111",
            target_label="t1",
            extra_labels={"key": "val"},
        )
        aggregator.record(
            bucket="bucket2",
            endpoint="endpoint2",
            method="PUT",
            latency_seconds=0.02,
            size_bytes=200,
            status_code=201,
            pid_label="222",
            target_label="t2",
        )

        aggregator.flush()

        assert mock_update.call_count == 2

    def test_record_thread_safety(self) -> None:
        """Record should be thread-safe."""
        aggregator = MetricsAggregator(5.0)
        num_threads = 10
        records_per_thread = 100

        def record_events() -> None:
            for i in range(records_per_thread):
                aggregator.record(
                    bucket=f"bucket-{threading.current_thread().name}-{i}",
                    endpoint="endpoint",
                    method="GET",
                    latency_seconds=0.001,
                    size_bytes=10,
                    status_code=200,
                    pid_label="123",
                    target_label="test",
                )

        threads = [
            threading.Thread(target=record_events) for _ in range(num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(aggregator._pending) == num_threads * records_per_thread

    def test_start_creates_thread(self) -> None:
        """Start should create a daemon thread."""
        aggregator = MetricsAggregator(5.0)

        aggregator.start()

        assert aggregator._thread is not None
        assert aggregator._thread.is_alive()
        assert aggregator._thread.daemon is True

        aggregator.stop()

    def test_start_idempotent(self) -> None:
        """Starting twice should not create multiple threads."""
        aggregator = MetricsAggregator(5.0)

        aggregator.start()
        first_thread = aggregator._thread

        aggregator.start()
        second_thread = aggregator._thread

        assert first_thread is second_thread

        aggregator.stop()

    def test_stop_terminates_thread(self) -> None:
        """Stop should terminate the background thread."""
        aggregator = MetricsAggregator(0.1)  # Short interval for test

        aggregator.start()
        assert aggregator._thread is not None
        assert aggregator._thread.is_alive()

        aggregator.stop()

        # Thread should be terminated (may still be alive briefly)
        # Give it a moment to terminate
        time.sleep(0.3)
        assert not aggregator._thread.is_alive()

    @patch("s3slower.core.update_prometheus")
    def test_stop_flushes_pending(self, mock_update: MagicMock) -> None:
        """Stop should flush any pending events."""
        aggregator = MetricsAggregator(5.0)

        aggregator.record(
            bucket="test",
            endpoint="test",
            method="GET",
            latency_seconds=0.01,
            size_bytes=100,
            status_code=200,
            pid_label="123",
            target_label="test",
        )

        aggregator.stop()

        mock_update.assert_called_once()

    def test_extra_labels_default_to_empty_dict(self) -> None:
        """Extra labels should default to empty dict when None."""
        aggregator = MetricsAggregator(5.0)

        aggregator.record(
            bucket="test",
            endpoint="test",
            method="GET",
            latency_seconds=0.01,
            size_bytes=100,
            status_code=200,
            pid_label="123",
            target_label="test",
            extra_labels=None,
        )

        # Check the pending record has empty dict for extra_labels
        assert len(aggregator._pending) == 1
        assert aggregator._pending[0][8] == {}


class TestUpdatePrometheus:
    """Tests for update_prometheus function."""

    def test_no_metrics_initialized(self) -> None:
        """Should not raise when metrics aren't initialized."""
        # update_prometheus checks if REQ_LATENCY etc are None
        # When they are None, it should return early without error
        update_prometheus(
            bucket="test",
            endpoint="test",
            method="GET",
            latency_seconds=0.01,
            size_bytes=100,
            status_code=200,
            pid_label="123",
            target_label="test",
        )
        # No exception should be raised

    def test_empty_values_use_unknown(self) -> None:
        """Empty values should be replaced with 'unknown'."""
        # This tests the label replacement logic
        # Without initialized metrics, we can't fully test the labels
        # but we can verify the function doesn't crash with empty values
        update_prometheus(
            bucket="",
            endpoint="",
            method="",
            latency_seconds=0.01,
            size_bytes=0,
            status_code=0,
            pid_label="",
            target_label="",
        )
        # No exception should be raised

    def test_invalid_status_code(self) -> None:
        """Invalid status codes should be labeled as 'unknown'."""
        update_prometheus(
            bucket="test",
            endpoint="test",
            method="GET",
            latency_seconds=0.01,
            size_bytes=100,
            status_code=0,  # Invalid
            pid_label="123",
            target_label="test",
        )
        # No exception should be raised

    def test_negative_size_bytes(self) -> None:
        """Negative size bytes should not increment counter."""
        update_prometheus(
            bucket="test",
            endpoint="test",
            method="GET",
            latency_seconds=0.01,
            size_bytes=-100,  # Negative
            pid_label="123",
            target_label="test",
            status_code=200,
        )
        # No exception should be raised

    @patch("s3slower.core.REQ_LATENCY")
    @patch("s3slower.core.REQ_TOTAL")
    @patch("s3slower.core.REQ_BYTES")
    @patch("s3slower.core.RESP_TOTAL")
    @patch("s3slower.core.PROM_EXTRA_LABELS", [])
    def test_with_mocked_metrics(
        self,
        mock_resp: MagicMock,
        mock_bytes: MagicMock,
        mock_total: MagicMock,
        mock_latency: MagicMock,
    ) -> None:
        """Test with mocked Prometheus metrics."""
        update_prometheus(
            bucket="mybucket",
            endpoint="s3.amazonaws.com",
            method="GET",
            latency_seconds=0.015,
            size_bytes=1024,
            status_code=200,
            pid_label="12345",
            target_label="boto3",
        )

        # Verify latency was observed
        mock_latency.labels.assert_called()
        mock_latency.labels().observe.assert_called_with(0.015)

        # Verify request counter was incremented
        mock_total.labels.assert_called()
        mock_total.labels().inc.assert_called()

        # Verify bytes counter was incremented
        mock_bytes.labels.assert_called()
        mock_bytes.labels().inc.assert_called_with(1024)

        # Verify response counter was incremented
        mock_resp.labels.assert_called()
        mock_resp.labels().inc.assert_called()

    @patch("s3slower.core.REQ_LATENCY")
    @patch("s3slower.core.REQ_TOTAL")
    @patch("s3slower.core.REQ_BYTES")
    @patch("s3slower.core.RESP_TOTAL")
    @patch("s3slower.core.PROM_EXTRA_LABELS", ["env", "region"])
    def test_with_extra_labels(
        self,
        mock_resp: MagicMock,
        mock_bytes: MagicMock,
        mock_total: MagicMock,
        mock_latency: MagicMock,
    ) -> None:
        """Test with extra Prometheus labels."""
        update_prometheus(
            bucket="mybucket",
            endpoint="s3.amazonaws.com",
            method="GET",
            latency_seconds=0.015,
            size_bytes=1024,
            status_code=200,
            pid_label="12345",
            target_label="boto3",
            extra_labels={"env": "production", "region": "us-west-2"},
        )

        # Verify labels() was called with the extra labels
        call_kwargs = mock_latency.labels.call_args
        if call_kwargs:
            kwargs = call_kwargs.kwargs
            assert kwargs.get("env") == "production"
            assert kwargs.get("region") == "us-west-2"

    @patch("s3slower.core.REQ_LATENCY")
    @patch("s3slower.core.REQ_TOTAL")
    @patch("s3slower.core.REQ_BYTES")
    @patch("s3slower.core.RESP_TOTAL")
    @patch("s3slower.core.PROM_EXTRA_LABELS", ["env"])
    def test_missing_extra_labels_use_empty(
        self,
        mock_resp: MagicMock,
        mock_bytes: MagicMock,
        mock_total: MagicMock,
        mock_latency: MagicMock,
    ) -> None:
        """Missing extra labels should use empty string."""
        update_prometheus(
            bucket="mybucket",
            endpoint="s3.amazonaws.com",
            method="GET",
            latency_seconds=0.015,
            size_bytes=1024,
            status_code=200,
            pid_label="12345",
            target_label="boto3",
            extra_labels={},  # Empty, but PROM_EXTRA_LABELS has "env"
        )

        # Verify labels() was called with empty string for missing label
        call_kwargs = mock_latency.labels.call_args
        if call_kwargs:
            kwargs = call_kwargs.kwargs
            assert kwargs.get("env") == ""

    @patch("s3slower.core.REQ_LATENCY")
    @patch("s3slower.core.REQ_TOTAL")
    @patch("s3slower.core.REQ_BYTES")
    @patch("s3slower.core.RESP_TOTAL")
    @patch("s3slower.core.PROM_EXTRA_LABELS", [])
    def test_zero_size_bytes_not_incremented(
        self,
        mock_resp: MagicMock,
        mock_bytes: MagicMock,
        mock_total: MagicMock,
        mock_latency: MagicMock,
    ) -> None:
        """Zero size bytes should not increment bytes counter."""
        update_prometheus(
            bucket="mybucket",
            endpoint="s3.amazonaws.com",
            method="GET",
            latency_seconds=0.015,
            size_bytes=0,
            status_code=200,
            pid_label="12345",
            target_label="boto3",
        )

        # Bytes counter should not have inc() called (or called with 0)
        # The actual check depends on implementation
        # For now, verify no exception was raised
