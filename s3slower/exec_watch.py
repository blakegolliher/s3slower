from __future__ import annotations

import ctypes as ct
import threading
from typing import Callable, Optional

from bcc import BPF

EXEC_BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_exec(struct tracepoint__sched__sched_process_exec *args) {
    struct exec_event_t data = {};
    data.pid = args->pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""


class _ExecEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("comm", ct.c_char * 16),
    ]


class ExecWatcher:
    """
    Watch sched_process_exec events and invoke a callback for each new process.
    """

    def __init__(self, callback: Callable[[int, str], None]) -> None:
        self._callback = callback
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._bpf = BPF(text=EXEC_BPF_TEXT)
        self._bpf.attach_tracepoint(tp="sched:sched_process_exec", fn_name="trace_exec")

    def _handle_event(self, cpu: int, data: bytes, size: int) -> None:
        evt = ct.cast(data, ct.POINTER(_ExecEvent)).contents
        comm = evt.comm.decode("utf-8", "replace").rstrip("\x00")
        self._callback(int(evt.pid), comm)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._bpf["events"].open_perf_buffer(self._handle_event)
        self._thread = threading.Thread(target=self._loop, name="s3slower-exec-watch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _loop(self) -> None:
        while not self._stop_evt.is_set():
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break


def start_exec_watch(on_exec_callback: Callable[[int, str], None]) -> ExecWatcher:
    watcher = ExecWatcher(on_exec_callback)
    watcher.start()
    return watcher
