from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # type: ignore


DEFAULT_TARGETS_PATH = "/etc/s3slower/targets.yml"


@dataclass
class TargetConfig:
    """
    Configuration for a single auto-attach target.
    """

    id: str
    match_type: str
    match_value: str
    mode: str
    prom_labels: Dict[str, str] = field(default_factory=dict)


def _fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def _validate_match_type(match_type: str) -> bool:
    return match_type in {"comm", "exe_basename", "cmdline_substring"}


def load_targets(path: str = DEFAULT_TARGETS_PATH) -> List[TargetConfig]:
    """
    Load targets configuration from YAML file.

    Raises SystemExit with a clear message if the file is missing or invalid.
    """
    if not path:
        _fail("no target config path provided")

    if not os.path.isfile(path):
        _fail(f"target config file not found: {path}")

    if yaml is None:
        _fail("PyYAML is required to read the targets config. Install it with: pip install pyyaml")

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception as exc:  # pragma: no cover - runtime safety
        _fail(f"failed to read target config {path}: {exc}")
        raise

    if not isinstance(data, dict):
        _fail(f"target config {path} must be a YAML mapping/object")

    targets_raw = data.get("targets")
    if not isinstance(targets_raw, list):
        _fail(f"target config {path} must contain a top-level 'targets' list")

    targets: List[TargetConfig] = []
    for idx, entry in enumerate(targets_raw):
        if not isinstance(entry, dict):
            _fail(f"target entry #{idx} must be a mapping/object")

        tid = str(entry.get("id", "")).strip()
        match = entry.get("match", {})
        mode = str(entry.get("mode", "")).strip()
        prom_labels: Dict[str, str] = {}
        labels_raw = entry.get("prom_labels", {}) or {}
        if isinstance(labels_raw, dict):
            prom_labels = {str(k): str(v) for k, v in labels_raw.items()}

        if not tid:
            _fail(f"target entry #{idx} is missing 'id'")

        if not isinstance(match, dict):
            _fail(f"target '{tid}' match must be a mapping/object")

        match_type = str(match.get("type", "")).strip()
        match_value = str(match.get("value", "")).strip()

        if not match_type or not _validate_match_type(match_type):
            _fail(f"target '{tid}' has invalid match.type '{match_type}'")
        if not match_value:
            _fail(f"target '{tid}' has empty match.value")
        if not mode:
            _fail(f"target '{tid}' has empty mode (expected openssl/go_tls/http/etc.)")

        targets.append(TargetConfig(
            id=tid,
            match_type=match_type,
            match_value=match_value,
            mode=mode,
            prom_labels=prom_labels,
        ))

    return targets


def collect_extra_label_keys(targets: Iterable[TargetConfig]) -> List[str]:
    """
    Collect the union of extra Prometheus label keys from all targets.
    """
    keys = set()
    for tgt in targets:
        keys.update(tgt.prom_labels.keys())
    return sorted(keys)
