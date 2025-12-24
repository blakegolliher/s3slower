from __future__ import annotations

import os
import threading
from typing import Callable, Dict, List, Optional

from .config import TargetConfig
from .exec_watch import ExecWatcher, start_exec_watch


def _read_exe_basename(pid: int) -> Optional[str]:
    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None
    return os.path.basename(exe_path)


def _read_cmdline(pid: int) -> Optional[str]:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    return data.replace(b"\x00", b" ").decode("utf-8", "replace")


def classify_pid(pid: int, comm: str, targets: List[TargetConfig]) -> Optional[TargetConfig]:
    """
    Apply target rules to an exec event. Returns the matched target or None.
    """
    for tgt in targets:
        tval = tgt.match_value
        if tgt.match_type == "comm":
            if comm == tval:
                return tgt
        elif tgt.match_type == "exe_basename":
            exe = _read_exe_basename(pid)
            if exe is None:
                continue
            # Match if either exe basename matches OR comm matches
            if exe == tval or comm == tval:
                return tgt
        elif tgt.match_type == "cmdline_substring":
            cmdline = _read_cmdline(pid)
            if cmdline is None:
                continue
            # Match if substring is found in cmdline
            if tval in cmdline:
                return tgt
    return None


class TargetWatcher:
    """
    Coordinates exec watching and applying target matching.
    """

    def __init__(self, targets: List[TargetConfig],
                 attach_callback: Callable[[int, str, TargetConfig], None]) -> None:
        self.targets = targets
        self.attach_callback = attach_callback
        self.attached: Dict[int, TargetConfig] = {}
        self._lock = threading.Lock()
        self._watcher: Optional[ExecWatcher] = None

    def start(self) -> None:
        if self._watcher is not None:
            return
        self._watcher = start_exec_watch(self._on_exec)

    def stop(self) -> None:
        if self._watcher is not None:
            self._watcher.stop()

    def _on_exec(self, pid: int, comm: str) -> None:
        with self._lock:
            if pid in self.attached:
                return

        target = classify_pid(pid, comm, self.targets)
        if not target:
            return

        with self._lock:
            # re-check under lock
            if pid in self.attached:
                return
            self.attached[pid] = target
        self.attach_callback(pid, comm, target)
