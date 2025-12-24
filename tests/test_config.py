"""
Tests for configuration loading and validation in s3slower.config.

These tests verify YAML configuration parsing, target matching rules,
and Prometheus label collection.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from s3slower.config import (
    TargetConfig,
    _validate_match_type,
    collect_extra_label_keys,
    load_targets,
)


class TestValidateMatchType:
    """Tests for _validate_match_type function."""

    def test_valid_comm(self) -> None:
        """'comm' is a valid match type."""
        assert _validate_match_type("comm") is True

    def test_valid_exe_basename(self) -> None:
        """'exe_basename' is a valid match type."""
        assert _validate_match_type("exe_basename") is True

    def test_valid_cmdline_substring(self) -> None:
        """'cmdline_substring' is a valid match type."""
        assert _validate_match_type("cmdline_substring") is True

    def test_invalid_type(self) -> None:
        """Invalid match types should return False."""
        assert _validate_match_type("invalid") is False

    def test_empty_string(self) -> None:
        """Empty string should return False."""
        assert _validate_match_type("") is False

    def test_case_sensitive(self) -> None:
        """Match types should be case-sensitive."""
        assert _validate_match_type("COMM") is False
        assert _validate_match_type("Comm") is False


class TestTargetConfig:
    """Tests for TargetConfig dataclass."""

    def test_create_basic(self) -> None:
        """Create a basic TargetConfig."""
        config = TargetConfig(
            id="test-target",
            match_type="comm",
            match_value="python3",
            mode="openssl",
        )

        assert config.id == "test-target"
        assert config.match_type == "comm"
        assert config.match_value == "python3"
        assert config.mode == "openssl"
        assert config.prom_labels == {}

    def test_create_with_labels(self) -> None:
        """Create a TargetConfig with Prometheus labels."""
        config = TargetConfig(
            id="boto3",
            match_type="cmdline_substring",
            match_value="boto3",
            mode="openssl",
            prom_labels={"client": "boto3", "env": "production"},
        )

        assert config.prom_labels == {"client": "boto3", "env": "production"}

    def test_default_labels_empty(self) -> None:
        """Default prom_labels should be an empty dict."""
        config = TargetConfig(
            id="test",
            match_type="comm",
            match_value="test",
            mode="http",
        )

        assert config.prom_labels == {}
        assert isinstance(config.prom_labels, dict)


class TestLoadTargets:
    """Tests for load_targets function."""

    def test_load_valid_config(self, sample_targets_config: Path) -> None:
        """Load a valid targets configuration file."""
        targets = load_targets(str(sample_targets_config))

        assert len(targets) == 3

        # Check first target (aws-cli)
        assert targets[0].id == "aws-cli"
        assert targets[0].match_type == "comm"
        assert targets[0].match_value == "aws"
        assert targets[0].mode == "openssl"
        assert targets[0].prom_labels == {"client": "aws-cli", "env": "test"}

        # Check second target (boto3)
        assert targets[1].id == "boto3"
        assert targets[1].match_type == "cmdline_substring"
        assert targets[1].match_value == "boto3"
        assert targets[1].mode == "openssl"

        # Check third target (curl)
        assert targets[2].id == "curl"
        assert targets[2].match_type == "exe_basename"
        assert targets[2].match_value == "curl"
        assert targets[2].mode == "http"

    def test_file_not_found(self, temp_dir: Path) -> None:
        """Missing configuration file should exit with error."""
        nonexistent = temp_dir / "nonexistent.yml"

        with pytest.raises(SystemExit) as exc_info:
            load_targets(str(nonexistent))

        assert exc_info.value.code == 1

    def test_empty_path(self) -> None:
        """Empty path should exit with error."""
        with pytest.raises(SystemExit) as exc_info:
            load_targets("")

        assert exc_info.value.code == 1

    def test_invalid_yaml_structure(self, temp_dir: Path) -> None:
        """YAML that isn't a dict should exit with error."""
        config_path = temp_dir / "invalid.yml"
        config_path.write_text("- item1\n- item2\n")

        with pytest.raises(SystemExit) as exc_info:
            load_targets(str(config_path))

        assert exc_info.value.code == 1

    def test_missing_targets_key(self, temp_dir: Path) -> None:
        """Config without 'targets' key should exit with error."""
        config_path = temp_dir / "no_targets.yml"
        config_path.write_text("other_key: value\n")

        with pytest.raises(SystemExit) as exc_info:
            load_targets(str(config_path))

        assert exc_info.value.code == 1

    def test_targets_not_list(self, temp_dir: Path) -> None:
        """'targets' that isn't a list should exit with error."""
        config_path = temp_dir / "targets_not_list.yml"
        config_path.write_text("targets: not-a-list\n")

        with pytest.raises(SystemExit) as exc_info:
            load_targets(str(config_path))

        assert exc_info.value.code == 1

    def test_target_entry_not_dict(self, temp_dir: Path) -> None:
        """Target entry that isn't a dict should exit with error."""
        config_path = temp_dir / "entry_not_dict.yml"
        config_path.write_text("targets:\n  - just-a-string\n")

        with pytest.raises(SystemExit) as exc_info:
            load_targets(str(config_path))

        assert exc_info.value.code == 1

    def test_missing_id(self, temp_dir: Path) -> None:
        """Target without 'id' should exit with error."""
        config_path = temp_dir / "missing_id.yml"
        config_path.write_text(
            """
targets:
  - match:
      type: comm
      value: test
    mode: openssl
"""
        )

        with pytest.raises(SystemExit) as exc_info:
            load_targets(str(config_path))

        assert exc_info.value.code == 1

    def test_missing_match(self, temp_dir: Path) -> None:
        """Target without 'match' should exit with error."""
        config_path = temp_dir / "missing_match.yml"
        config_path.write_text(
            """
targets:
  - id: test
    mode: openssl
"""
        )

        with pytest.raises(SystemExit) as exc_info:
            load_targets(str(config_path))

        assert exc_info.value.code == 1

    def test_missing_mode(self, temp_dir: Path) -> None:
        """Target without 'mode' should exit with error."""
        config_path = temp_dir / "missing_mode.yml"
        config_path.write_text(
            """
targets:
  - id: test
    match:
      type: comm
      value: test
"""
        )

        with pytest.raises(SystemExit) as exc_info:
            load_targets(str(config_path))

        assert exc_info.value.code == 1

    def test_invalid_match_type(self, temp_dir: Path) -> None:
        """Target with invalid match type should exit with error."""
        config_path = temp_dir / "invalid_match_type.yml"
        config_path.write_text(
            """
targets:
  - id: test
    match:
      type: invalid_type
      value: test
    mode: openssl
"""
        )

        with pytest.raises(SystemExit) as exc_info:
            load_targets(str(config_path))

        assert exc_info.value.code == 1

    def test_empty_match_value(self, temp_dir: Path) -> None:
        """Target with empty match value should exit with error."""
        config_path = temp_dir / "empty_match_value.yml"
        config_path.write_text(
            """
targets:
  - id: test
    match:
      type: comm
      value: ""
    mode: openssl
"""
        )

        with pytest.raises(SystemExit) as exc_info:
            load_targets(str(config_path))

        assert exc_info.value.code == 1

    def test_empty_targets_list(self, temp_dir: Path) -> None:
        """Empty targets list should return empty list."""
        config_path = temp_dir / "empty_targets.yml"
        config_path.write_text("targets: []\n")

        targets = load_targets(str(config_path))

        assert targets == []

    def test_prom_labels_none(self, temp_dir: Path) -> None:
        """Target with null prom_labels should have empty dict."""
        config_path = temp_dir / "null_labels.yml"
        config_path.write_text(
            """
targets:
  - id: test
    match:
      type: comm
      value: test
    mode: openssl
    prom_labels: null
"""
        )

        targets = load_targets(str(config_path))

        assert len(targets) == 1
        assert targets[0].prom_labels == {}

    def test_prom_labels_various_types(self, temp_dir: Path) -> None:
        """Label values should be converted to strings."""
        config_path = temp_dir / "various_labels.yml"
        config_path.write_text(
            """
targets:
  - id: test
    match:
      type: comm
      value: test
    mode: openssl
    prom_labels:
      string_val: hello
      int_val: 42
      bool_val: true
"""
        )

        targets = load_targets(str(config_path))

        assert len(targets) == 1
        assert targets[0].prom_labels["string_val"] == "hello"
        assert targets[0].prom_labels["int_val"] == "42"
        assert targets[0].prom_labels["bool_val"] == "True"


class TestCollectExtraLabelKeys:
    """Tests for collect_extra_label_keys function."""

    def test_empty_targets(self) -> None:
        """Empty targets list should return empty list."""
        result = collect_extra_label_keys([])

        assert result == []

    def test_no_labels(self) -> None:
        """Targets with no labels should return empty list."""
        targets = [
            TargetConfig(id="t1", match_type="comm", match_value="a", mode="openssl"),
            TargetConfig(id="t2", match_type="comm", match_value="b", mode="http"),
        ]

        result = collect_extra_label_keys(targets)

        assert result == []

    def test_single_target_single_label(self) -> None:
        """Single target with one label."""
        targets = [
            TargetConfig(
                id="t1",
                match_type="comm",
                match_value="a",
                mode="openssl",
                prom_labels={"client": "boto3"},
            ),
        ]

        result = collect_extra_label_keys(targets)

        assert result == ["client"]

    def test_multiple_targets_overlapping_labels(self) -> None:
        """Multiple targets with overlapping labels should deduplicate."""
        targets = [
            TargetConfig(
                id="t1",
                match_type="comm",
                match_value="a",
                mode="openssl",
                prom_labels={"client": "boto3", "env": "prod"},
            ),
            TargetConfig(
                id="t2",
                match_type="comm",
                match_value="b",
                mode="openssl",
                prom_labels={"client": "aws-cli", "region": "us-west-2"},
            ),
        ]

        result = collect_extra_label_keys(targets)

        # Should be sorted and deduplicated
        assert result == ["client", "env", "region"]

    def test_sorted_output(self) -> None:
        """Keys should be returned in sorted order."""
        targets = [
            TargetConfig(
                id="t1",
                match_type="comm",
                match_value="a",
                mode="openssl",
                prom_labels={"zebra": "z", "apple": "a", "mango": "m"},
            ),
        ]

        result = collect_extra_label_keys(targets)

        assert result == ["apple", "mango", "zebra"]

    def test_generator_input(self) -> None:
        """Should accept generator input."""

        def gen_targets():
            yield TargetConfig(
                id="t1",
                match_type="comm",
                match_value="a",
                mode="openssl",
                prom_labels={"key1": "val1"},
            )
            yield TargetConfig(
                id="t2",
                match_type="comm",
                match_value="b",
                mode="http",
                prom_labels={"key2": "val2"},
            )

        result = collect_extra_label_keys(gen_targets())

        assert result == ["key1", "key2"]
