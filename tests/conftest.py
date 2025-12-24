"""
Shared pytest fixtures for s3slower test suite.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest

# Mock bcc module before importing s3slower modules
# This allows testing pure Python functions without requiring eBPF/kernel access
_mock_bcc = MagicMock()
_mock_bcc.BPF = MagicMock()
sys.modules["bcc"] = _mock_bcc


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_yaml_config(temp_dir: Path) -> Path:
    """Create a sample YAML configuration file."""
    config_path = temp_dir / "config.yaml"
    config_path.write_text(
        """
logging:
  enabled: true
  path: /var/log/s3slower.log
  max_size_mb: 50
  max_backups: 3

prometheus:
  host: 0.0.0.0
  port: 9090

metrics:
  refresh_interval_seconds: 10.0
"""
    )
    return config_path


@pytest.fixture
def sample_targets_config(temp_dir: Path) -> Path:
    """Create a sample targets YAML configuration file."""
    config_path = temp_dir / "targets.yml"
    config_path.write_text(
        """
targets:
  - id: aws-cli
    match:
      type: comm
      value: aws
    mode: openssl
    prom_labels:
      client: aws-cli
      env: test

  - id: boto3
    match:
      type: cmdline_substring
      value: boto3
    mode: openssl
    prom_labels:
      client: boto3

  - id: curl
    match:
      type: exe_basename
      value: curl
    mode: http
"""
    )
    return config_path


@pytest.fixture
def invalid_targets_config(temp_dir: Path) -> Path:
    """Create an invalid targets YAML configuration file."""
    config_path = temp_dir / "invalid_targets.yml"
    config_path.write_text(
        """
targets:
  - id: missing-match
    mode: openssl
"""
    )
    return config_path


@pytest.fixture
def mock_proc_dir(temp_dir: Path) -> Path:
    """Create a mock /proc directory structure for testing."""
    proc_dir = temp_dir / "proc"
    proc_dir.mkdir()

    # Create a mock process directory
    pid_dir = proc_dir / "12345"
    pid_dir.mkdir()

    # Create mock exe symlink (can't create real symlink to non-existent file)
    # We'll use a different approach in tests
    (pid_dir / "cmdline").write_bytes(b"python3\x00-c\x00import boto3\x00")

    return proc_dir


@pytest.fixture
def sample_ops_log(temp_dir: Path) -> Path:
    """Create a sample operations log file."""
    log_path = temp_dir / "ops.log"
    log_path.write_text(
        """# Operations log
1703462400\thttps\tPUT_OBJECT\tPUT\ttest-bucket\ttest-key-1.txt
1703462401\thttps\tGET_OBJECT\tGET\ttest-bucket\ttest-key-1.txt
1703462402\thttps\tDELETE_OBJECT\tDELETE\ttest-bucket\ttest-key-1.txt
1703462403\thttps\tLIST_PREFIX\tGET\ttest-bucket\tprefix/
1703462404\thttps\tPUT_LARGE_MPU\tPUT\ttest-bucket\tlarge-file.bin
"""
    )
    return log_path


@pytest.fixture
def sample_trace_log(temp_dir: Path) -> Path:
    """Create a sample s3slower trace log file."""
    log_path = temp_dir / "trace.log"
    log_path.write_text(
        """1703462400123456789\t12:00:00\t1234\tpython3\taws-cli\tPUT\t15.234\t200\ttest-bucket\ts3.amazonaws.com\t/test-bucket/test-key-1.txt
1703462401234567890\t12:00:01\t1234\tpython3\taws-cli\tGET\t10.123\t200\ttest-bucket\ts3.amazonaws.com\t/test-bucket/test-key-1.txt
1703462402345678901\t12:00:02\t1234\tpython3\taws-cli\tDELETE\t5.456\t204\ttest-bucket\ts3.amazonaws.com\t/test-bucket/test-key-1.txt
1703462403456789012\t12:00:03\t1234\tpython3\taws-cli\tGET\t8.789\t200\ttest-bucket\ts3.amazonaws.com\t/test-bucket/?list-type=2&prefix=prefix/
1703462404567890123\t12:00:04\t1234\tpython3\taws-cli\tMPU_CREATE\t12.345\t200\ttest-bucket\ts3.amazonaws.com\t/test-bucket/large-file.bin?uploads
1703462404678901234\t12:00:04\t1234\tpython3\taws-cli\tPUT\t50.123\t200\ttest-bucket\ts3.amazonaws.com\t/test-bucket/large-file.bin?uploadId=abc123&partNumber=1
1703462404789012345\t12:00:04\t1234\tpython3\taws-cli\tMPU_COMPLETE\t20.456\t200\ttest-bucket\ts3.amazonaws.com\t/test-bucket/large-file.bin?uploadId=abc123
"""
    )
    return log_path
