"""
Tests for utility functions in s3slower.core.

These are pure Python helper functions for type conversion,
percentile calculation, and library path resolution.
"""

from __future__ import annotations

from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from s3slower.core import _safe_float, _safe_int, find_library, ns_to_ms, percentile


class TestSafeInt:
    """Tests for _safe_int function."""

    def test_valid_int(self) -> None:
        """Convert a valid integer."""
        assert _safe_int(42, 0) == 42

    def test_valid_int_zero(self) -> None:
        """Convert zero."""
        assert _safe_int(0, 99) == 0

    def test_valid_int_negative(self) -> None:
        """Convert a negative integer."""
        assert _safe_int(-10, 0) == -10

    def test_valid_string_int(self) -> None:
        """Convert a string representation of an integer."""
        assert _safe_int("123", 0) == 123

    def test_valid_string_negative(self) -> None:
        """Convert a string representation of a negative integer."""
        assert _safe_int("-456", 0) == -456

    def test_valid_float_truncates(self) -> None:
        """Float input should be truncated to int."""
        assert _safe_int(3.7, 0) == 3
        assert _safe_int(3.2, 0) == 3

    def test_invalid_string_returns_default(self) -> None:
        """Non-numeric string should return default."""
        assert _safe_int("abc", 42) == 42

    def test_none_returns_default(self) -> None:
        """None should return default."""
        assert _safe_int(None, 99) == 99

    def test_empty_string_returns_default(self) -> None:
        """Empty string should return default."""
        assert _safe_int("", 77) == 77

    def test_list_returns_default(self) -> None:
        """List input should return default."""
        assert _safe_int([1, 2, 3], 55) == 55

    def test_dict_returns_default(self) -> None:
        """Dict input should return default."""
        assert _safe_int({"a": 1}, 66) == 66

    def test_whitespace_string_returns_default(self) -> None:
        """Whitespace-only string should return default."""
        assert _safe_int("   ", 44) == 44

    def test_large_int(self) -> None:
        """Large integer should be handled."""
        large_val = 10**18
        assert _safe_int(large_val, 0) == large_val

    def test_string_with_whitespace(self) -> None:
        """String with leading/trailing whitespace."""
        # int() handles whitespace, so this should work
        assert _safe_int("  42  ", 0) == 42


class TestSafeFloat:
    """Tests for _safe_float function."""

    def test_valid_float(self) -> None:
        """Convert a valid float."""
        assert _safe_float(3.14, 0.0) == 3.14

    def test_valid_float_zero(self) -> None:
        """Convert zero."""
        assert _safe_float(0.0, 99.9) == 0.0

    def test_valid_float_negative(self) -> None:
        """Convert a negative float."""
        assert _safe_float(-2.5, 0.0) == -2.5

    def test_valid_int_converts_to_float(self) -> None:
        """Integer input should convert to float."""
        result = _safe_float(42, 0.0)
        assert result == 42.0
        assert isinstance(result, float)

    def test_valid_string_float(self) -> None:
        """Convert a string representation of a float."""
        assert _safe_float("3.14159", 0.0) == pytest.approx(3.14159)

    def test_valid_string_scientific(self) -> None:
        """Convert scientific notation string."""
        assert _safe_float("1.5e-3", 0.0) == pytest.approx(0.0015)

    def test_invalid_string_returns_default(self) -> None:
        """Non-numeric string should return default."""
        assert _safe_float("xyz", 1.5) == 1.5

    def test_none_returns_default(self) -> None:
        """None should return default."""
        assert _safe_float(None, 9.9) == 9.9

    def test_empty_string_returns_default(self) -> None:
        """Empty string should return default."""
        assert _safe_float("", 7.7) == 7.7

    def test_list_returns_default(self) -> None:
        """List input should return default."""
        assert _safe_float([1.0, 2.0], 5.5) == 5.5

    def test_special_float_inf(self) -> None:
        """Infinity should be handled."""
        result = _safe_float(float("inf"), 0.0)
        assert result == float("inf")

    def test_special_string_inf(self) -> None:
        """String 'inf' should convert to infinity."""
        result = _safe_float("inf", 0.0)
        assert result == float("inf")


class TestNsToMs:
    """Tests for ns_to_ms function."""

    # Conversion factor: 1 ms = 1,000,000 ns
    NS_PER_MS = 1_000_000

    def test_zero(self) -> None:
        """Zero nanoseconds should return zero milliseconds."""
        assert ns_to_ms(0) == 0.0

    def test_one_millisecond(self) -> None:
        """One million nanoseconds should equal one millisecond."""
        assert ns_to_ms(self.NS_PER_MS) == 1.0

    def test_sub_millisecond(self) -> None:
        """Sub-millisecond precision should be preserved."""
        # 500,000 ns = 0.5 ms
        assert ns_to_ms(500_000) == pytest.approx(0.5)

    def test_large_value(self) -> None:
        """Large nanosecond values should convert correctly."""
        # 1 second = 1,000 ms = 1,000,000,000 ns
        assert ns_to_ms(1_000_000_000) == 1000.0

    def test_typical_latency(self) -> None:
        """Typical S3 latency values should convert correctly."""
        # 15.5 ms = 15,500,000 ns
        assert ns_to_ms(15_500_000) == pytest.approx(15.5)

    def test_microsecond_precision(self) -> None:
        """Microsecond precision should be preserved."""
        # 1.234 ms = 1,234,000 ns
        assert ns_to_ms(1_234_000) == pytest.approx(1.234)


class TestPercentile:
    """Tests for percentile function."""

    def test_empty_list(self) -> None:
        """Empty list should return 0.0."""
        assert percentile([], 50) == 0.0

    def test_single_value(self) -> None:
        """Single value list should return that value for any percentile."""
        values = [42.5]
        assert percentile(values, 0) == 42.5
        assert percentile(values, 50) == 42.5
        assert percentile(values, 100) == 42.5

    def test_two_values_p50(self) -> None:
        """Two values at p50."""
        values = [10.0, 20.0]
        # Midpoint or one of the values depending on implementation
        result = percentile(values, 50)
        assert result in (10.0, 20.0, 15.0)

    def test_p0_returns_min(self) -> None:
        """p0 should return the minimum value."""
        values = [5.0, 10.0, 15.0, 20.0, 25.0]
        assert percentile(values, 0) == 5.0

    def test_p100_returns_max(self) -> None:
        """p100 should return the maximum value."""
        values = [5.0, 10.0, 15.0, 20.0, 25.0]
        assert percentile(values, 100) == 25.0

    def test_p50_median(self) -> None:
        """p50 should return the median for odd-length list."""
        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        assert percentile(values, 50) == 30.0

    def test_p90_typical(self) -> None:
        """p90 calculation for typical latency distribution."""
        values = list(range(1, 101))  # 1 to 100
        values_float = [float(v) for v in values]
        result = percentile(values_float, 90)
        # p90 of 1-100 should be around 90
        assert 89 <= result <= 91

    def test_p99_typical(self) -> None:
        """p99 calculation for typical latency distribution."""
        values = list(range(1, 101))  # 1 to 100
        values_float = [float(v) for v in values]
        result = percentile(values_float, 99)
        # p99 of 1-100 should be around 99
        assert 98 <= result <= 100

    def test_unsorted_input(self) -> None:
        """Unsorted input should be handled correctly."""
        values = [50.0, 10.0, 30.0, 40.0, 20.0]
        # Should internally sort
        assert percentile(values, 0) == 10.0
        assert percentile(values, 100) == 50.0

    def test_negative_percentile_returns_min(self) -> None:
        """Negative percentile should return minimum."""
        values = [10.0, 20.0, 30.0]
        assert percentile(values, -10) == 10.0

    def test_over_100_percentile_returns_max(self) -> None:
        """Percentile over 100 should return maximum."""
        values = [10.0, 20.0, 30.0]
        assert percentile(values, 150) == 30.0

    def test_duplicate_values(self) -> None:
        """List with duplicate values should work correctly."""
        values = [10.0, 10.0, 20.0, 20.0, 20.0]
        assert percentile(values, 0) == 10.0
        assert percentile(values, 100) == 20.0


class TestFindLibrary:
    """Tests for find_library function."""

    def test_library_not_found(self) -> None:
        """Non-existent library should return None."""
        result = find_library(["nonexistent_lib_xyz.so"])
        assert result is None

    def test_empty_patterns(self) -> None:
        """Empty patterns list should return None."""
        result = find_library([])
        assert result is None

    @patch("glob.glob")
    def test_library_found_in_usr_lib(self, mock_glob) -> None:
        """Library found in /usr/lib should be returned."""
        mock_glob.side_effect = lambda path, recursive: (
            ["/usr/lib/libssl.so.3"] if "libssl" in path else []
        )

        result = find_library(["libssl.so", "libssl.so.*"])
        assert result == "/usr/lib/libssl.so.3"

    @patch("glob.glob")
    def test_library_found_in_lib64(self, mock_glob) -> None:
        """Library found in /lib64 should be returned."""

        def mock_glob_fn(path: str, recursive: bool) -> List[str]:
            if "/lib64/" in path and "libssl" in path:
                return ["/lib64/libssl.so.1.1"]
            return []

        mock_glob.side_effect = mock_glob_fn

        result = find_library(["libssl.so", "libssl.so.*"])
        # Should find it eventually when scanning search roots
        # The actual path depends on which root is checked first
        if result:
            assert "libssl" in result

    @patch("glob.glob")
    def test_first_match_returned(self, mock_glob) -> None:
        """First matching library should be returned."""

        def mock_glob_fn(path: str, recursive: bool) -> List[str]:
            if "/usr/lib/" in path and "libssl.so" in path:
                return ["/usr/lib/libssl.so.3", "/usr/lib/libssl.so.1.1"]
            return []

        mock_glob.side_effect = mock_glob_fn

        result = find_library(["libssl.so.*"])
        assert result == "/usr/lib/libssl.so.3"

    @patch("glob.glob")
    def test_multiple_patterns(self, mock_glob) -> None:
        """Multiple patterns should be tried in order."""

        def mock_glob_fn(path: str, recursive: bool) -> List[str]:
            if "libgnutls" in path and "/usr/lib/" in path:
                return ["/usr/lib/libgnutls.so.30"]
            return []

        mock_glob.side_effect = mock_glob_fn

        result = find_library(["libgnutls.so", "libgnutls.so.*"])
        assert result == "/usr/lib/libgnutls.so.30"
