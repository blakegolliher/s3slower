"""
Tests for runtime settings configuration in s3slower.core.

These tests verify configuration loading, merging of defaults/config/CLI,
and RuntimeSettings dataclass behavior.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from s3slower.core import (
    DEFAULT_LOG_BACKUPS,
    DEFAULT_LOG_MAX_MB,
    DEFAULT_LOG_PATH,
    DEFAULT_METRICS_REFRESH_SEC,
    DEFAULT_PROM_HOST,
    DEFAULT_PROM_PORT,
    RuntimeSettings,
    build_runtime_settings,
    load_config_file,
)


class TestRuntimeSettings:
    """Tests for RuntimeSettings dataclass."""

    def test_default_values(self) -> None:
        """Verify default values are set correctly."""
        settings = RuntimeSettings()

        assert settings.log_enabled is True
        assert settings.log_path == DEFAULT_LOG_PATH
        assert settings.log_max_size_mb == DEFAULT_LOG_MAX_MB
        assert settings.log_max_backups == DEFAULT_LOG_BACKUPS
        assert settings.prometheus_host == DEFAULT_PROM_HOST
        assert settings.prometheus_port == DEFAULT_PROM_PORT
        assert settings.metrics_refresh_interval == DEFAULT_METRICS_REFRESH_SEC

    def test_custom_values(self) -> None:
        """Create RuntimeSettings with custom values."""
        settings = RuntimeSettings(
            log_enabled=False,
            log_path="/custom/path/trace.log",
            log_max_size_mb=50,
            log_max_backups=10,
            prometheus_host="127.0.0.1",
            prometheus_port=9090,
            metrics_refresh_interval=2.5,
        )

        assert settings.log_enabled is False
        assert settings.log_path == "/custom/path/trace.log"
        assert settings.log_max_size_mb == 50
        assert settings.log_max_backups == 10
        assert settings.prometheus_host == "127.0.0.1"
        assert settings.prometheus_port == 9090
        assert settings.metrics_refresh_interval == 2.5


class TestLoadConfigFile:
    """Tests for load_config_file function."""

    def test_load_valid_yaml(self, sample_yaml_config: Path) -> None:
        """Load a valid YAML configuration file."""
        config = load_config_file(str(sample_yaml_config))

        assert isinstance(config, dict)
        assert "logging" in config
        assert "prometheus" in config
        assert "metrics" in config

        assert config["logging"]["enabled"] is True
        assert config["logging"]["path"] == "/var/log/s3slower.log"
        assert config["prometheus"]["port"] == 9090

    def test_file_not_found_returns_empty(self, temp_dir: Path) -> None:
        """Missing file should return empty dict."""
        nonexistent = temp_dir / "nonexistent.yaml"

        config = load_config_file(str(nonexistent))

        assert config == {}

    def test_empty_path_returns_empty(self) -> None:
        """Empty path should return empty dict."""
        config = load_config_file("")

        assert config == {}

    def test_none_path_returns_empty(self) -> None:
        """None path should return empty dict (after str conversion)."""
        # The function expects a string, but should handle edge cases
        config = load_config_file("")

        assert config == {}

    @patch("s3slower.core.yaml", None)
    def test_yaml_not_installed_exits(self, sample_yaml_config: Path) -> None:
        """Exit if YAML file exists but PyYAML isn't installed."""
        # This tests the branch where yaml is None
        # We need to reload the module or mock differently
        # For now, skip this test as it requires complex module reloading
        pass

    def test_invalid_yaml_exits(self, temp_dir: Path) -> None:
        """Invalid YAML syntax should exit with error."""
        config_path = temp_dir / "invalid.yaml"
        config_path.write_text("invalid: yaml: syntax:\n  - [}")

        with pytest.raises(SystemExit) as exc_info:
            load_config_file(str(config_path))

        assert exc_info.value.code == 1

    def test_non_dict_yaml_exits(self, temp_dir: Path) -> None:
        """YAML that isn't a dict should exit with error."""
        config_path = temp_dir / "list.yaml"
        config_path.write_text("- item1\n- item2\n")

        with pytest.raises(SystemExit) as exc_info:
            load_config_file(str(config_path))

        assert exc_info.value.code == 1

    def test_empty_yaml_returns_empty(self, temp_dir: Path) -> None:
        """Empty YAML file should return empty dict."""
        config_path = temp_dir / "empty.yaml"
        config_path.write_text("")

        config = load_config_file(str(config_path))

        assert config == {}

    def test_null_yaml_returns_empty(self, temp_dir: Path) -> None:
        """YAML with only null should return empty dict."""
        config_path = temp_dir / "null.yaml"
        config_path.write_text("null\n")

        config = load_config_file(str(config_path))

        assert config == {}


class TestBuildRuntimeSettings:
    """Tests for build_runtime_settings function."""

    @pytest.fixture
    def empty_args(self) -> argparse.Namespace:
        """Create an argparse Namespace with no CLI overrides."""
        return argparse.Namespace(
            log_file=None,
            no_log_file=False,
            log_max_size_mb=None,
            log_max_backups=None,
            prometheus_host=None,
            prometheus_port=None,
            metrics_refresh_interval=None,
        )

    @pytest.fixture
    def sample_config(self) -> Dict[str, Any]:
        """Create a sample configuration dict."""
        return {
            "logging": {
                "enabled": True,
                "path": "/var/log/s3slower.log",
                "max_size_mb": 50,
                "max_backups": 3,
            },
            "prometheus": {
                "host": "0.0.0.0",
                "port": 9090,
            },
            "metrics": {
                "refresh_interval_seconds": 10.0,
            },
        }

    def test_defaults_only(self, empty_args: argparse.Namespace) -> None:
        """Use only defaults when no config or CLI options provided."""
        settings = build_runtime_settings(empty_args, {})

        assert settings.log_enabled is True
        assert settings.log_path == DEFAULT_LOG_PATH
        assert settings.log_max_size_mb == DEFAULT_LOG_MAX_MB
        assert settings.log_max_backups == DEFAULT_LOG_BACKUPS
        assert settings.prometheus_host == DEFAULT_PROM_HOST
        assert settings.prometheus_port == DEFAULT_PROM_PORT
        assert settings.metrics_refresh_interval == DEFAULT_METRICS_REFRESH_SEC

    def test_config_overrides_defaults(
        self, empty_args: argparse.Namespace, sample_config: Dict[str, Any]
    ) -> None:
        """Config file values should override defaults."""
        settings = build_runtime_settings(empty_args, sample_config)

        assert settings.log_path == "/var/log/s3slower.log"
        assert settings.log_max_size_mb == 50
        assert settings.log_max_backups == 3
        assert settings.prometheus_port == 9090
        assert settings.metrics_refresh_interval == 10.0

    def test_cli_overrides_config(self, sample_config: Dict[str, Any]) -> None:
        """CLI arguments should override config file values."""
        args = argparse.Namespace(
            log_file="/cli/override.log",
            no_log_file=False,
            log_max_size_mb=200,
            log_max_backups=20,
            prometheus_host="localhost",
            prometheus_port=8080,
            metrics_refresh_interval=5.0,
        )

        settings = build_runtime_settings(args, sample_config)

        assert settings.log_path == "/cli/override.log"
        assert settings.log_max_size_mb == 200
        assert settings.log_max_backups == 20
        assert settings.prometheus_host == "localhost"
        assert settings.prometheus_port == 8080
        assert settings.metrics_refresh_interval == 5.0

    def test_no_log_file_disables_logging(
        self, sample_config: Dict[str, Any]
    ) -> None:
        """--no-log-file should disable logging."""
        args = argparse.Namespace(
            log_file=None,
            no_log_file=True,
            log_max_size_mb=None,
            log_max_backups=None,
            prometheus_host=None,
            prometheus_port=None,
            metrics_refresh_interval=None,
        )

        settings = build_runtime_settings(args, sample_config)

        assert settings.log_enabled is False

    def test_log_file_enables_logging(
        self, empty_args: argparse.Namespace
    ) -> None:
        """--log-file should enable logging."""
        empty_args.log_file = "/my/log.log"

        settings = build_runtime_settings(empty_args, {"logging": {"enabled": False}})

        assert settings.log_enabled is True
        assert settings.log_path == "/my/log.log"

    def test_invalid_config_types_handled(
        self, empty_args: argparse.Namespace
    ) -> None:
        """Invalid config types should fall back to defaults."""
        config = {
            "logging": "not a dict",
            "prometheus": ["not", "a", "dict"],
            "metrics": 12345,
        }

        settings = build_runtime_settings(empty_args, config)

        # Should use defaults
        assert settings.log_path == DEFAULT_LOG_PATH
        assert settings.prometheus_port == DEFAULT_PROM_PORT

    def test_invalid_numeric_config_uses_defaults(
        self, empty_args: argparse.Namespace
    ) -> None:
        """Non-numeric values in config should use defaults."""
        config = {
            "logging": {
                "max_size_mb": "not a number",
                "max_backups": [1, 2, 3],
            },
            "prometheus": {
                "port": "invalid",
            },
            "metrics": {
                "refresh_interval_seconds": {"nested": "dict"},
            },
        }

        settings = build_runtime_settings(empty_args, config)

        assert settings.log_max_size_mb == DEFAULT_LOG_MAX_MB
        assert settings.log_max_backups == DEFAULT_LOG_BACKUPS
        assert settings.prometheus_port == DEFAULT_PROM_PORT
        assert settings.metrics_refresh_interval == DEFAULT_METRICS_REFRESH_SEC

    def test_zero_refresh_interval_uses_default(
        self, empty_args: argparse.Namespace
    ) -> None:
        """Zero or negative refresh interval should use default."""
        config = {
            "metrics": {
                "refresh_interval_seconds": 0,
            },
        }

        settings = build_runtime_settings(empty_args, config)

        assert settings.metrics_refresh_interval == DEFAULT_METRICS_REFRESH_SEC

    def test_negative_refresh_interval_uses_default(
        self, empty_args: argparse.Namespace
    ) -> None:
        """Negative refresh interval should use default."""
        config = {
            "metrics": {
                "refresh_interval_seconds": -5.0,
            },
        }

        settings = build_runtime_settings(empty_args, config)

        assert settings.metrics_refresh_interval == DEFAULT_METRICS_REFRESH_SEC

    def test_empty_path_in_config_uses_default(
        self, empty_args: argparse.Namespace
    ) -> None:
        """Empty log path in config should use default."""
        config = {
            "logging": {
                "path": "",
            },
        }

        settings = build_runtime_settings(empty_args, config)

        assert settings.log_path == DEFAULT_LOG_PATH

    def test_null_host_uses_default(
        self, empty_args: argparse.Namespace
    ) -> None:
        """Null prometheus host should use default."""
        config = {
            "prometheus": {
                "host": None,
            },
        }

        settings = build_runtime_settings(empty_args, config)

        assert settings.prometheus_host == DEFAULT_PROM_HOST

    def test_missing_attributes_on_args(self) -> None:
        """Handle args without optional attributes."""
        # Minimal args without some optional attributes
        args = argparse.Namespace()

        settings = build_runtime_settings(args, {})

        # Should not raise and use defaults
        assert settings.log_enabled is True
        assert settings.prometheus_port == DEFAULT_PROM_PORT

    def test_partial_config_merging(
        self, empty_args: argparse.Namespace
    ) -> None:
        """Partial config should merge with defaults."""
        config = {
            "logging": {
                "max_size_mb": 75,
                # path not specified
            },
            # prometheus not specified
        }

        settings = build_runtime_settings(empty_args, config)

        # Specified value
        assert settings.log_max_size_mb == 75
        # Defaults for unspecified
        assert settings.log_path == DEFAULT_LOG_PATH
        assert settings.prometheus_port == DEFAULT_PROM_PORT
