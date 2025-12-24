"""
Tests for process watching and target matching in s3slower.watcher.

These tests verify PID classification based on process metadata
(comm, exe basename, cmdline) against configured target rules.
"""

from __future__ import annotations

from typing import List, Optional
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from s3slower.config import TargetConfig
from s3slower.watcher import (
    TargetWatcher,
    _read_cmdline,
    _read_exe_basename,
    classify_pid,
)


class TestReadExeBasename:
    """Tests for _read_exe_basename function."""

    @patch("os.readlink")
    def test_valid_exe_path(self, mock_readlink: MagicMock) -> None:
        """Read basename of valid exe symlink."""
        mock_readlink.return_value = "/usr/bin/python3"

        result = _read_exe_basename(12345)

        assert result == "python3"
        mock_readlink.assert_called_once_with("/proc/12345/exe")

    @patch("os.readlink")
    def test_exe_with_version(self, mock_readlink: MagicMock) -> None:
        """Read basename of exe with version suffix."""
        mock_readlink.return_value = "/usr/bin/python3.11"

        result = _read_exe_basename(12345)

        assert result == "python3.11"

    @patch("os.readlink")
    def test_exe_in_nested_path(self, mock_readlink: MagicMock) -> None:
        """Read basename from deeply nested path."""
        mock_readlink.return_value = "/opt/company/product/bin/myapp"

        result = _read_exe_basename(12345)

        assert result == "myapp"

    @patch("os.readlink")
    def test_process_not_found(self, mock_readlink: MagicMock) -> None:
        """Return None when process doesn't exist."""
        mock_readlink.side_effect = OSError("No such file")

        result = _read_exe_basename(99999)

        assert result is None

    @patch("os.readlink")
    def test_permission_denied(self, mock_readlink: MagicMock) -> None:
        """Return None when permission is denied."""
        mock_readlink.side_effect = PermissionError("Permission denied")

        result = _read_exe_basename(1)

        assert result is None

    @patch("os.readlink")
    def test_deleted_binary(self, mock_readlink: MagicMock) -> None:
        """Handle deleted binary marker."""
        mock_readlink.return_value = "/usr/bin/myapp (deleted)"

        result = _read_exe_basename(12345)

        # basename includes the (deleted) suffix
        assert result == "myapp (deleted)"


class TestReadCmdline:
    """Tests for _read_cmdline function."""

    def test_valid_cmdline(self) -> None:
        """Read cmdline with null-separated arguments."""
        cmdline_data = b"python3\x00-c\x00import boto3; boto3.client('s3')\x00"

        with patch("builtins.open", mock_open(read_data=cmdline_data)):
            result = _read_cmdline(12345)

        assert result == "python3 -c import boto3; boto3.client('s3') "

    def test_simple_command(self) -> None:
        """Read simple command without arguments."""
        cmdline_data = b"curl\x00"

        with patch("builtins.open", mock_open(read_data=cmdline_data)):
            result = _read_cmdline(12345)

        assert result == "curl "

    def test_command_with_spaces_in_args(self) -> None:
        """Read command with spaces in arguments."""
        cmdline_data = b"aws\x00s3\x00cp\x00file with spaces.txt\x00s3://bucket/\x00"

        with patch("builtins.open", mock_open(read_data=cmdline_data)):
            result = _read_cmdline(12345)

        assert "file with spaces.txt" in result

    def test_process_not_found(self) -> None:
        """Return None when process doesn't exist."""
        with patch("builtins.open", side_effect=OSError("No such file")):
            result = _read_cmdline(99999)

        assert result is None

    def test_permission_denied(self) -> None:
        """Return None when permission is denied."""
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            result = _read_cmdline(1)

        assert result is None

    def test_empty_cmdline(self) -> None:
        """Handle empty cmdline (zombie process)."""
        with patch("builtins.open", mock_open(read_data=b"")):
            result = _read_cmdline(12345)

        assert result == ""

    def test_utf8_in_cmdline(self) -> None:
        """Handle UTF-8 characters in cmdline."""
        cmdline_data = "python3\x00файл.py\x00".encode("utf-8")

        with patch("builtins.open", mock_open(read_data=cmdline_data)):
            result = _read_cmdline(12345)

        assert "файл.py" in result

    def test_binary_garbage_in_cmdline(self) -> None:
        """Handle binary garbage gracefully."""
        cmdline_data = b"\xff\xfe\x00\x80\x90\x00"

        with patch("builtins.open", mock_open(read_data=cmdline_data)):
            result = _read_cmdline(12345)

        # Should return something (with replacement chars) rather than crash
        assert result is not None


class TestClassifyPid:
    """Tests for classify_pid function."""

    @pytest.fixture
    def sample_targets(self) -> List[TargetConfig]:
        """Create sample target configurations."""
        return [
            TargetConfig(
                id="aws-cli",
                match_type="comm",
                match_value="aws",
                mode="openssl",
            ),
            TargetConfig(
                id="boto3",
                match_type="cmdline_substring",
                match_value="boto3",
                mode="openssl",
            ),
            TargetConfig(
                id="curl",
                match_type="exe_basename",
                match_value="curl",
                mode="http",
            ),
        ]

    def test_match_comm(self, sample_targets: List[TargetConfig]) -> None:
        """Match process by comm name."""
        result = classify_pid(12345, "aws", sample_targets)

        assert result is not None
        assert result.id == "aws-cli"
        assert result.mode == "openssl"

    def test_match_comm_exact_only(self, sample_targets: List[TargetConfig]) -> None:
        """Comm match should be exact, not substring."""
        result = classify_pid(12345, "aws-cli", sample_targets)

        # "aws-cli" != "aws", so no match
        assert result is None

    @patch("s3slower.watcher._read_exe_basename")
    def test_match_exe_basename(
        self, mock_read_exe: MagicMock, sample_targets: List[TargetConfig]
    ) -> None:
        """Match process by executable basename."""
        mock_read_exe.return_value = "curl"

        result = classify_pid(12345, "curl", sample_targets)

        assert result is not None
        assert result.id == "curl"
        assert result.mode == "http"

    @patch("s3slower.watcher._read_exe_basename")
    def test_match_exe_basename_when_comm_differs(
        self, mock_read_exe: MagicMock, sample_targets: List[TargetConfig]
    ) -> None:
        """Match by exe_basename when comm is different."""
        mock_read_exe.return_value = "curl"

        # comm is "curl-loader" but exe is "curl"
        result = classify_pid(12345, "curl-loader", sample_targets)

        assert result is not None
        assert result.id == "curl"

    @patch("s3slower.watcher._read_cmdline")
    def test_match_cmdline_substring(
        self, mock_read_cmdline: MagicMock, sample_targets: List[TargetConfig]
    ) -> None:
        """Match process by cmdline substring."""
        mock_read_cmdline.return_value = "python3 -c import boto3; print('hello')"

        result = classify_pid(12345, "python3", sample_targets)

        assert result is not None
        assert result.id == "boto3"
        assert result.mode == "openssl"

    @patch("s3slower.watcher._read_cmdline")
    def test_no_match_cmdline_substring(
        self, mock_read_cmdline: MagicMock, sample_targets: List[TargetConfig]
    ) -> None:
        """No match when cmdline doesn't contain substring."""
        mock_read_cmdline.return_value = "python3 -c import requests"

        result = classify_pid(12345, "python3", sample_targets)

        assert result is None

    def test_no_match(self, sample_targets: List[TargetConfig]) -> None:
        """No match when process doesn't match any target."""
        result = classify_pid(12345, "unknown-process", sample_targets)

        assert result is None

    def test_empty_targets(self) -> None:
        """Empty targets list should never match."""
        result = classify_pid(12345, "aws", [])

        assert result is None

    def test_first_match_wins(self) -> None:
        """First matching target should be returned."""
        targets = [
            TargetConfig(id="first", match_type="comm", match_value="test", mode="openssl"),
            TargetConfig(id="second", match_type="comm", match_value="test", mode="http"),
        ]

        result = classify_pid(12345, "test", targets)

        assert result is not None
        assert result.id == "first"

    @patch("s3slower.watcher._read_exe_basename")
    def test_exe_read_fails(
        self, mock_read_exe: MagicMock, sample_targets: List[TargetConfig]
    ) -> None:
        """Handle failure to read exe gracefully."""
        mock_read_exe.return_value = None

        # Should still try other match types
        result = classify_pid(12345, "aws", sample_targets)

        # comm match should still work
        assert result is not None
        assert result.id == "aws-cli"

    @patch("s3slower.watcher._read_cmdline")
    def test_cmdline_read_fails(
        self, mock_read_cmdline: MagicMock, sample_targets: List[TargetConfig]
    ) -> None:
        """Handle failure to read cmdline gracefully."""
        mock_read_cmdline.return_value = None

        result = classify_pid(12345, "python3", sample_targets)

        # boto3 match requires cmdline, so no match
        assert result is None

    @patch("s3slower.watcher._read_exe_basename")
    def test_exe_basename_also_matches_comm(
        self, mock_read_exe: MagicMock
    ) -> None:
        """exe_basename target can match either exe or comm."""
        mock_read_exe.return_value = "other-exe"

        targets = [
            TargetConfig(
                id="curl",
                match_type="exe_basename",
                match_value="curl",
                mode="http",
            ),
        ]

        # When exe doesn't match but comm does (for exe_basename type)
        result = classify_pid(12345, "curl", targets)

        assert result is not None
        assert result.id == "curl"


class TestTargetWatcher:
    """Tests for TargetWatcher class."""

    @pytest.fixture
    def sample_targets(self) -> List[TargetConfig]:
        """Create sample target configurations."""
        return [
            TargetConfig(
                id="test-target",
                match_type="comm",
                match_value="testproc",
                mode="openssl",
            ),
        ]

    def test_init(self, sample_targets: List[TargetConfig]) -> None:
        """Initialize TargetWatcher."""
        callback = MagicMock()
        watcher = TargetWatcher(sample_targets, callback)

        assert watcher.targets == sample_targets
        assert watcher.attach_callback == callback
        assert watcher.attached == {}

    @patch("s3slower.watcher.start_exec_watch")
    def test_start(
        self, mock_start_watch: MagicMock, sample_targets: List[TargetConfig]
    ) -> None:
        """Start watching for exec events."""
        mock_exec_watcher = MagicMock()
        mock_start_watch.return_value = mock_exec_watcher

        callback = MagicMock()
        watcher = TargetWatcher(sample_targets, callback)
        watcher.start()

        mock_start_watch.assert_called_once()
        assert watcher._watcher == mock_exec_watcher

    @patch("s3slower.watcher.start_exec_watch")
    def test_start_idempotent(
        self, mock_start_watch: MagicMock, sample_targets: List[TargetConfig]
    ) -> None:
        """Starting twice should not create multiple watchers."""
        mock_exec_watcher = MagicMock()
        mock_start_watch.return_value = mock_exec_watcher

        callback = MagicMock()
        watcher = TargetWatcher(sample_targets, callback)
        watcher.start()
        watcher.start()

        mock_start_watch.assert_called_once()

    @patch("s3slower.watcher.start_exec_watch")
    def test_stop(
        self, mock_start_watch: MagicMock, sample_targets: List[TargetConfig]
    ) -> None:
        """Stop watching for exec events."""
        mock_exec_watcher = MagicMock()
        mock_start_watch.return_value = mock_exec_watcher

        callback = MagicMock()
        watcher = TargetWatcher(sample_targets, callback)
        watcher.start()
        watcher.stop()

        mock_exec_watcher.stop.assert_called_once()

    def test_stop_without_start(self, sample_targets: List[TargetConfig]) -> None:
        """Stopping without starting should be safe."""
        callback = MagicMock()
        watcher = TargetWatcher(sample_targets, callback)

        # Should not raise
        watcher.stop()

    @patch("s3slower.watcher.classify_pid")
    @patch("s3slower.watcher.start_exec_watch")
    def test_on_exec_matching_pid(
        self,
        mock_start_watch: MagicMock,
        mock_classify: MagicMock,
        sample_targets: List[TargetConfig],
    ) -> None:
        """Handle exec event for matching PID."""
        mock_exec_watcher = MagicMock()
        mock_start_watch.return_value = mock_exec_watcher
        mock_classify.return_value = sample_targets[0]

        callback = MagicMock()
        watcher = TargetWatcher(sample_targets, callback)
        watcher.start()

        # Simulate exec event
        watcher._on_exec(12345, "testproc")

        callback.assert_called_once_with(12345, "testproc", sample_targets[0])
        assert 12345 in watcher.attached

    @patch("s3slower.watcher.classify_pid")
    @patch("s3slower.watcher.start_exec_watch")
    def test_on_exec_non_matching_pid(
        self,
        mock_start_watch: MagicMock,
        mock_classify: MagicMock,
        sample_targets: List[TargetConfig],
    ) -> None:
        """Handle exec event for non-matching PID."""
        mock_exec_watcher = MagicMock()
        mock_start_watch.return_value = mock_exec_watcher
        mock_classify.return_value = None

        callback = MagicMock()
        watcher = TargetWatcher(sample_targets, callback)
        watcher.start()

        # Simulate exec event
        watcher._on_exec(12345, "unknownproc")

        callback.assert_not_called()
        assert 12345 not in watcher.attached

    @patch("s3slower.watcher.classify_pid")
    @patch("s3slower.watcher.start_exec_watch")
    def test_on_exec_duplicate_pid(
        self,
        mock_start_watch: MagicMock,
        mock_classify: MagicMock,
        sample_targets: List[TargetConfig],
    ) -> None:
        """Duplicate PIDs should not trigger callback again."""
        mock_exec_watcher = MagicMock()
        mock_start_watch.return_value = mock_exec_watcher
        mock_classify.return_value = sample_targets[0]

        callback = MagicMock()
        watcher = TargetWatcher(sample_targets, callback)
        watcher.start()

        # Simulate multiple exec events for same PID
        watcher._on_exec(12345, "testproc")
        watcher._on_exec(12345, "testproc")

        # Callback should only be called once
        callback.assert_called_once()
