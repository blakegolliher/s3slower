"""
Tests for the s3slower correlation script.

The correlation script validates that S3 operations captured by traffic
generators are correctly traced by s3slower.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

import pytest

# Add scripts directory to path for importing
scripts_dir = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from s3slower_correlate import (
    MultipartCheck,
    OpRecord,
    TraceRecord,
    build_multipart_checks,
    correlate,
    key_in_path,
    op_matches_trace,
    parse_ops_log,
    parse_trace_log,
    prefix_in_path,
)


class TestOpRecord:
    """Tests for OpRecord dataclass."""

    def test_create_op_record(self) -> None:
        """Create a basic OpRecord."""
        record = OpRecord(
            index=0,
            epoch=1703462400,
            protocol="https",
            op_name="PUT_OBJECT",
            http_method="PUT",
            bucket="test-bucket",
            target="test-key.txt",
        )

        assert record.index == 0
        assert record.epoch == 1703462400
        assert record.protocol == "https"
        assert record.op_name == "PUT_OBJECT"
        assert record.http_method == "PUT"
        assert record.bucket == "test-bucket"
        assert record.target == "test-key.txt"


class TestTraceRecord:
    """Tests for TraceRecord dataclass."""

    def test_create_trace_record(self) -> None:
        """Create a basic TraceRecord."""
        record = TraceRecord(
            index=0,
            ts_ns=1703462400123456789,
            time_str="12:00:00",
            pid=1234,
            comm="python3",
            target="boto3",
            method_bucket="PUT",
            lat_ms=15.234,
            status="200",
            bucket="test-bucket",
            endpoint="s3.amazonaws.com",
            path="/test-bucket/test-key.txt",
        )

        assert record.index == 0
        assert record.pid == 1234
        assert record.method_bucket == "PUT"
        assert record.lat_ms == 15.234


class TestMultipartCheck:
    """Tests for MultipartCheck dataclass."""

    def test_ok_all_complete(self) -> None:
        """All components present."""
        check = MultipartCheck(
            bucket="test",
            key="large.bin",
            op_count=1,
            create_count=1,
            part_put_count=3,
            complete_count=1,
        )

        assert check.ok_create is True
        assert check.ok_parts is True
        assert check.ok_complete is True
        assert check.ok_all is True

    def test_ok_all_missing_create(self) -> None:
        """Missing create."""
        check = MultipartCheck(
            bucket="test",
            key="large.bin",
            op_count=1,
            create_count=0,
            part_put_count=3,
            complete_count=1,
        )

        assert check.ok_create is False
        assert check.ok_all is False

    def test_ok_all_missing_parts(self) -> None:
        """Missing parts."""
        check = MultipartCheck(
            bucket="test",
            key="large.bin",
            op_count=1,
            create_count=1,
            part_put_count=0,
            complete_count=1,
        )

        assert check.ok_parts is False
        assert check.ok_all is False

    def test_ok_all_missing_complete(self) -> None:
        """Missing complete."""
        check = MultipartCheck(
            bucket="test",
            key="large.bin",
            op_count=1,
            create_count=1,
            part_put_count=3,
            complete_count=0,
        )

        assert check.ok_complete is False
        assert check.ok_all is False


class TestKeyInPath:
    """Tests for key_in_path function."""

    def test_simple_match(self) -> None:
        """Simple key in path."""
        assert key_in_path("mykey.txt", "/bucket/mykey.txt") is True

    def test_nested_path_match(self) -> None:
        """Key in nested path."""
        assert key_in_path("mykey.txt", "/bucket/dir/subdir/mykey.txt") is True

    def test_no_match(self) -> None:
        """Key not in path."""
        assert key_in_path("mykey.txt", "/bucket/otherkey.txt") is False

    def test_url_encoded_match(self) -> None:
        """URL-encoded key matches."""
        assert key_in_path("my key.txt", "/bucket/my%20key.txt") is True

    def test_empty_key(self) -> None:
        """Empty key returns False."""
        assert key_in_path("", "/bucket/key") is False

    def test_empty_path(self) -> None:
        """Empty path returns False."""
        assert key_in_path("key", "") is False

    def test_partial_match(self) -> None:
        """Partial key match (substring)."""
        assert key_in_path("key", "/bucket/mykey.txt") is True

    def test_special_characters(self) -> None:
        """Key with special characters."""
        assert key_in_path("file+name.txt", "/bucket/file+name.txt") is True


class TestPrefixInPath:
    """Tests for prefix_in_path function."""

    def test_simple_prefix(self) -> None:
        """Simple prefix in path."""
        assert prefix_in_path("logs/", "/bucket/?prefix=logs/") is True

    def test_prefix_not_in_path(self) -> None:
        """Prefix not in path."""
        assert prefix_in_path("logs/", "/bucket/data/file.txt") is False

    def test_url_encoded_prefix(self) -> None:
        """URL-encoded prefix matches."""
        assert prefix_in_path("my dir/", "/bucket/?prefix=my%20dir/") is True

    def test_empty_prefix(self) -> None:
        """Empty prefix returns False."""
        assert prefix_in_path("", "/bucket/?prefix=logs/") is False

    def test_empty_path(self) -> None:
        """Empty path returns False."""
        assert prefix_in_path("logs/", "") is False


class TestOpMatchesTrace:
    """Tests for op_matches_trace function."""

    @pytest.fixture
    def put_op(self) -> OpRecord:
        """Create a PUT operation record."""
        return OpRecord(
            index=0,
            epoch=1703462400,
            protocol="https",
            op_name="PUT_OBJECT",
            http_method="PUT",
            bucket="test-bucket",
            target="test-key.txt",
        )

    @pytest.fixture
    def get_op(self) -> OpRecord:
        """Create a GET operation record."""
        return OpRecord(
            index=0,
            epoch=1703462400,
            protocol="https",
            op_name="GET_OBJECT",
            http_method="GET",
            bucket="test-bucket",
            target="test-key.txt",
        )

    @pytest.fixture
    def matching_trace(self) -> TraceRecord:
        """Create a matching trace record."""
        return TraceRecord(
            index=0,
            ts_ns=1703462400123456789,
            time_str="12:00:00",
            pid=1234,
            comm="python3",
            target="boto3",
            method_bucket="PUT",
            lat_ms=15.234,
            status="200",
            bucket="test-bucket",
            endpoint="s3.amazonaws.com",
            path="/test-bucket/test-key.txt",
        )

    def test_put_matches_put(
        self, put_op: OpRecord, matching_trace: TraceRecord
    ) -> None:
        """PUT operation matches PUT trace."""
        assert op_matches_trace(put_op, matching_trace, None) is True

    def test_get_matches_get(self, get_op: OpRecord) -> None:
        """GET operation matches GET trace."""
        trace = TraceRecord(
            index=0,
            ts_ns=1703462400123456789,
            time_str="12:00:00",
            pid=1234,
            comm="python3",
            target="",
            method_bucket="GET",
            lat_ms=10.0,
            status="200",
            bucket="test-bucket",
            endpoint="s3.amazonaws.com",
            path="/test-bucket/test-key.txt",
        )
        assert op_matches_trace(get_op, trace, None) is True

    def test_bucket_mismatch(
        self, put_op: OpRecord, matching_trace: TraceRecord
    ) -> None:
        """Bucket mismatch should not match."""
        matching_trace.bucket = "other-bucket"
        assert op_matches_trace(put_op, matching_trace, None) is False

    def test_method_mismatch(
        self, put_op: OpRecord, matching_trace: TraceRecord
    ) -> None:
        """Method mismatch should not match."""
        matching_trace.method_bucket = "GET"
        assert op_matches_trace(put_op, matching_trace, None) is False

    def test_key_not_in_path(
        self, put_op: OpRecord, matching_trace: TraceRecord
    ) -> None:
        """Key not in path should not match."""
        matching_trace.path = "/test-bucket/other-key.txt"
        assert op_matches_trace(put_op, matching_trace, None) is False

    def test_expected_target_matches(
        self, put_op: OpRecord, matching_trace: TraceRecord
    ) -> None:
        """Expected target should match trace target."""
        assert op_matches_trace(put_op, matching_trace, "boto3") is True

    def test_expected_target_mismatch(
        self, put_op: OpRecord, matching_trace: TraceRecord
    ) -> None:
        """Mismatched expected target should not match."""
        assert op_matches_trace(put_op, matching_trace, "aws-cli") is False

    def test_delete_matches_del(self) -> None:
        """DELETE operation matches DEL trace."""
        op = OpRecord(
            index=0,
            epoch=1703462400,
            protocol="https",
            op_name="DELETE_OBJECT",
            http_method="DELETE",
            bucket="test-bucket",
            target="test-key.txt",
        )
        trace = TraceRecord(
            index=0,
            ts_ns=1703462400123456789,
            time_str="12:00:00",
            pid=1234,
            comm="python3",
            target="",
            method_bucket="DEL",
            lat_ms=5.0,
            status="204",
            bucket="test-bucket",
            endpoint="s3.amazonaws.com",
            path="/test-bucket/test-key.txt",
        )
        assert op_matches_trace(op, trace, None) is True

    def test_list_prefix_matches(self) -> None:
        """LIST_PREFIX operation matches GET with list params."""
        op = OpRecord(
            index=0,
            epoch=1703462400,
            protocol="https",
            op_name="LIST_PREFIX",
            http_method="GET",
            bucket="test-bucket",
            target="myprefix/",
        )
        trace = TraceRecord(
            index=0,
            ts_ns=1703462400123456789,
            time_str="12:00:00",
            pid=1234,
            comm="python3",
            target="",
            method_bucket="GET",
            lat_ms=8.0,
            status="200",
            bucket="test-bucket",
            endpoint="s3.amazonaws.com",
            path="/test-bucket?list-type=2&prefix=myprefix/",
        )
        assert op_matches_trace(op, trace, None) is True

    def test_mpu_create_matches(self) -> None:
        """PUT_LARGE_MPU matches MPU_CREATE."""
        op = OpRecord(
            index=0,
            epoch=1703462400,
            protocol="https",
            op_name="PUT_LARGE_MPU",
            http_method="PUT",
            bucket="test-bucket",
            target="large-file.bin",
        )
        trace = TraceRecord(
            index=0,
            ts_ns=1703462400123456789,
            time_str="12:00:00",
            pid=1234,
            comm="python3",
            target="",
            method_bucket="MPU_CREATE",
            lat_ms=12.0,
            status="200",
            bucket="test-bucket",
            endpoint="s3.amazonaws.com",
            path="/test-bucket/large-file.bin?uploads",
        )
        assert op_matches_trace(op, trace, None) is True

    def test_mpu_complete_matches(self) -> None:
        """PUT_LARGE_MPU matches MPU_COMPLETE."""
        op = OpRecord(
            index=0,
            epoch=1703462400,
            protocol="https",
            op_name="PUT_LARGE_MPU",
            http_method="PUT",
            bucket="test-bucket",
            target="large-file.bin",
        )
        trace = TraceRecord(
            index=0,
            ts_ns=1703462400123456789,
            time_str="12:00:00",
            pid=1234,
            comm="python3",
            target="",
            method_bucket="MPU_COMPLETE",
            lat_ms=20.0,
            status="200",
            bucket="test-bucket",
            endpoint="s3.amazonaws.com",
            path="/test-bucket/large-file.bin?uploadId=abc123",
        )
        assert op_matches_trace(op, trace, None) is True


class TestParseOpsLog:
    """Tests for parse_ops_log function."""

    def test_parse_valid_log(self, sample_ops_log: Path) -> None:
        """Parse a valid operations log."""
        ops = parse_ops_log(str(sample_ops_log))

        assert len(ops) == 5
        assert ops[0].op_name == "PUT_OBJECT"
        assert ops[1].op_name == "GET_OBJECT"
        assert ops[2].op_name == "DELETE_OBJECT"
        assert ops[3].op_name == "LIST_PREFIX"
        assert ops[4].op_name == "PUT_LARGE_MPU"

    def test_skip_comments(self, temp_dir: Path) -> None:
        """Skip comment lines."""
        log_path = temp_dir / "ops.log"
        log_path.write_text(
            "# This is a comment\n"
            "1703462400\thttps\tPUT_OBJECT\tPUT\tbucket\tkey\n"
            "# Another comment\n"
        )

        ops = parse_ops_log(str(log_path))

        assert len(ops) == 1

    def test_skip_empty_lines(self, temp_dir: Path) -> None:
        """Skip empty lines."""
        log_path = temp_dir / "ops.log"
        log_path.write_text(
            "\n"
            "1703462400\thttps\tPUT_OBJECT\tPUT\tbucket\tkey\n"
            "\n"
            "\n"
        )

        ops = parse_ops_log(str(log_path))

        assert len(ops) == 1

    def test_skip_short_lines(self, temp_dir: Path) -> None:
        """Skip lines with too few fields."""
        log_path = temp_dir / "ops.log"
        log_path.write_text(
            "1703462400\thttps\tPUT_OBJECT\n"  # Too short
            "1703462400\thttps\tPUT_OBJECT\tPUT\tbucket\tkey\n"  # Valid
        )

        ops = parse_ops_log(str(log_path))

        assert len(ops) == 1

    def test_skip_invalid_epoch(self, temp_dir: Path) -> None:
        """Skip lines with invalid epoch."""
        log_path = temp_dir / "ops.log"
        log_path.write_text(
            "not-a-number\thttps\tPUT_OBJECT\tPUT\tbucket\tkey\n"
            "1703462400\thttps\tPUT_OBJECT\tPUT\tbucket\tkey\n"
        )

        ops = parse_ops_log(str(log_path))

        assert len(ops) == 1

    def test_file_not_found_exits(self, temp_dir: Path) -> None:
        """Missing file should exit with error."""
        with pytest.raises(SystemExit):
            parse_ops_log(str(temp_dir / "nonexistent.log"))

    def test_uppercase_method(self, temp_dir: Path) -> None:
        """HTTP method should be uppercased."""
        log_path = temp_dir / "ops.log"
        log_path.write_text("1703462400\thttps\tPUT_OBJECT\tput\tbucket\tkey\n")

        ops = parse_ops_log(str(log_path))

        assert ops[0].http_method == "PUT"


class TestParseTraceLog:
    """Tests for parse_trace_log function."""

    def test_parse_valid_log(self, sample_trace_log: Path) -> None:
        """Parse a valid trace log."""
        traces = parse_trace_log(str(sample_trace_log))

        assert len(traces) == 7
        assert traces[0].method_bucket == "PUT"
        assert traces[1].method_bucket == "GET"
        assert traces[2].method_bucket == "DELETE"

    def test_parse_new_format(self, temp_dir: Path) -> None:
        """Parse new format with target column."""
        log_path = temp_dir / "trace.log"
        log_path.write_text(
            "1703462400123456789\t12:00:00\t1234\tpython3\tboto3\tPUT\t15.234\t200\ttest-bucket\ts3.amazonaws.com\t/path\n"
        )

        traces = parse_trace_log(str(log_path))

        assert len(traces) == 1
        assert traces[0].target == "boto3"
        assert traces[0].method_bucket == "PUT"
        assert traces[0].lat_ms == 15.234

    def test_skip_comments(self, temp_dir: Path) -> None:
        """Skip comment lines."""
        log_path = temp_dir / "trace.log"
        log_path.write_text(
            "# Comment\n"
            "1703462400123456789\t12:00:00\t1234\tpython3\tboto3\tPUT\t15.234\t200\tbucket\tendpoint\t/path\n"
        )

        traces = parse_trace_log(str(log_path))

        assert len(traces) == 1

    def test_file_not_found_exits(self, temp_dir: Path) -> None:
        """Missing file should exit with error."""
        with pytest.raises(SystemExit):
            parse_trace_log(str(temp_dir / "nonexistent.log"))


class TestCorrelate:
    """Tests for correlate function."""

    def test_all_matched(self) -> None:
        """All operations matched."""
        ops = [
            OpRecord(0, 1703462400, "https", "PUT_OBJECT", "PUT", "bucket", "key1"),
            OpRecord(1, 1703462401, "https", "GET_OBJECT", "GET", "bucket", "key1"),
        ]
        traces = [
            TraceRecord(0, 1703462400000, "12:00:00", 1234, "py", "", "PUT", 10.0, "200", "bucket", "ep", "/bucket/key1"),
            TraceRecord(1, 1703462401000, "12:00:01", 1234, "py", "", "GET", 5.0, "200", "bucket", "ep", "/bucket/key1"),
        ]

        mapping, missing = correlate(ops, traces, None)

        assert len(mapping) == 2
        assert len(missing) == 0

    def test_some_missing(self) -> None:
        """Some operations not matched."""
        ops = [
            OpRecord(0, 1703462400, "https", "PUT_OBJECT", "PUT", "bucket", "key1"),
            OpRecord(1, 1703462401, "https", "GET_OBJECT", "GET", "bucket", "key2"),
        ]
        traces = [
            TraceRecord(0, 1703462400000, "12:00:00", 1234, "py", "", "PUT", 10.0, "200", "bucket", "ep", "/bucket/key1"),
        ]

        mapping, missing = correlate(ops, traces, None)

        assert len(mapping) == 1
        assert missing == [1]

    def test_greedy_matching(self) -> None:
        """Greedy matching uses first available trace."""
        ops = [
            OpRecord(0, 1703462400, "https", "PUT_OBJECT", "PUT", "bucket", "key"),
            OpRecord(1, 1703462401, "https", "PUT_OBJECT", "PUT", "bucket", "key"),
        ]
        traces = [
            TraceRecord(0, 1703462400000, "12:00:00", 1234, "py", "", "PUT", 10.0, "200", "bucket", "ep", "/bucket/key"),
            TraceRecord(1, 1703462401000, "12:00:01", 1234, "py", "", "PUT", 10.0, "200", "bucket", "ep", "/bucket/key"),
        ]

        mapping, missing = correlate(ops, traces, None)

        assert mapping[0] == 0  # First op matches first trace
        assert mapping[1] == 1  # Second op matches second trace


class TestBuildMultipartChecks:
    """Tests for build_multipart_checks function."""

    def test_complete_mpu(self) -> None:
        """Complete multipart upload pattern."""
        ops = [
            OpRecord(0, 1703462400, "https", "PUT_LARGE_MPU", "PUT", "bucket", "large.bin"),
        ]
        traces = [
            TraceRecord(0, 1703462400000, "12:00:00", 1234, "py", "", "MPU_CREATE", 12.0, "200", "bucket", "ep", "/bucket/large.bin?uploads"),
            TraceRecord(1, 1703462401000, "12:00:01", 1234, "py", "", "PUT", 50.0, "200", "bucket", "ep", "/bucket/large.bin?uploadId=abc&partNumber=1"),
            TraceRecord(2, 1703462402000, "12:00:02", 1234, "py", "", "MPU_COMPLETE", 20.0, "200", "bucket", "ep", "/bucket/large.bin?uploadId=abc"),
        ]

        checks = build_multipart_checks(ops, traces)

        assert len(checks) == 1
        assert checks[0].ok_all is True
        assert checks[0].create_count == 1
        assert checks[0].part_put_count == 1
        assert checks[0].complete_count == 1

    def test_no_mpu_ops(self) -> None:
        """No multipart upload operations."""
        ops = [
            OpRecord(0, 1703462400, "https", "PUT_OBJECT", "PUT", "bucket", "small.txt"),
        ]
        traces = []

        checks = build_multipart_checks(ops, traces)

        assert len(checks) == 0

    def test_incomplete_mpu(self) -> None:
        """Incomplete multipart upload (missing complete)."""
        ops = [
            OpRecord(0, 1703462400, "https", "PUT_LARGE_MPU", "PUT", "bucket", "large.bin"),
        ]
        traces = [
            TraceRecord(0, 1703462400000, "12:00:00", 1234, "py", "", "MPU_CREATE", 12.0, "200", "bucket", "ep", "/bucket/large.bin?uploads"),
            TraceRecord(1, 1703462401000, "12:00:01", 1234, "py", "", "PUT", 50.0, "200", "bucket", "ep", "/bucket/large.bin?uploadId=abc&partNumber=1"),
        ]

        checks = build_multipart_checks(ops, traces)

        assert len(checks) == 1
        assert checks[0].ok_all is False
        assert checks[0].ok_complete is False
