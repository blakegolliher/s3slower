#!/usr/bin/env python3
#
# s3slower-ssl.py
#
# Prototype: trace HTTPS(S3) request latency by hooking user-space TLS
# libraries (OpenSSL/BoringSSL, GnuTLS, NSS) via uprobes.
#
# Features:
#   - Latency from TLS write (request) -> first TLS read (response).
#   - HTTP/S3 parsing: method, host, path, bucket, endpoint.
#   - Content-Length → request size (bytes).
#   - Response status code (HTTP/1.x).
#   - Text output + per-op p50/p90/p99 summaries.
#   - Optional Prometheus /metrics with:
#       * s3slower_requests_total{bucket,endpoint,method}
#       * s3slower_request_latency_seconds{bucket,endpoint,method}
#       * s3slower_request_bytes_total{bucket,endpoint,method}
#       * s3slower_responses_total{bucket,endpoint,method,status}
#

from __future__ import annotations

import argparse
import ctypes as ct
import glob
import os
import signal
import sys
import time
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

from bcc import BPF

# Prometheus is optional; only required if --prometheus-port is used.
try:
    from prometheus_client import Counter, Histogram, start_http_server  # type: ignore
    HAVE_PROM = True
except ImportError:
    HAVE_PROM = False

# ---------------------------------------------------------------------------
# BPF program (embedded C)
# ---------------------------------------------------------------------------

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_HDR 256

enum http_op_t {
    OP_UNKNOWN = 0,
    OP_GET     = 1,
    OP_PUT     = 2,
    OP_HEAD    = 3,
    OP_POST    = 4,
    OP_DELETE  = 5,
};

struct conn_key_t {
    u32 pid;
    u64 id;  // generic connection identifier: SSL* / gnutls_session_t / PRFileDesc*
};

struct req_val_t {
    u64 start_ns;
    u32 op;
    char hdr[MAX_HDR];   // request header preview
};

struct event_t {
    u64 ts;        // event timestamp (ns)
    u64 delta;     // latency (ns)
    u32 pid;
    u32 tid;
    u32 op;
    char comm[TASK_COMM_LEN];
    char req_hdr[MAX_HDR];
    char resp_hdr[MAX_HDR];
};

struct read_args_t {
    u64 id;
    const void *buf;
};

BPF_HASH(active_reqs, struct conn_key_t, struct req_val_t);
BPF_HASH(read_args, u32, struct read_args_t);
BPF_PERCPU_ARRAY(tmp_evt, struct event_t, 1);
BPF_PERF_OUTPUT(events);

static inline u32 classify_method(char *buf)
{
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ')
        return OP_GET;
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ')
        return OP_PUT;
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ')
        return OP_HEAD;
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ')
        return OP_POST;
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E' && buf[6] == ' ')
        return OP_DELETE;
    return OP_UNKNOWN;
}

// Entry for all TLS write functions (OpenSSL SSL_write, gnutls_record_send, NSS PR_Write/PR_Send)
int ssl_write_enter(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 id = (u64)PT_REGS_PARM1(ctx);      // SSL*/session*/PRFileDesc*
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int len = (int)PT_REGS_PARM3(ctx);

    if (len <= 0)
        return 0;

    struct conn_key_t key = {};
    key.pid = pid;
    key.id  = id;

    struct req_val_t val = {};
    val.start_ns = bpf_ktime_get_ns();

    int copy = len;
    if (copy > MAX_HDR)
        copy = MAX_HDR;

    bpf_probe_read_user(&val.hdr, copy, buf);
    val.op = classify_method(val.hdr);

    active_reqs.update(&key, &val);
    return 0;
}

// Entry for all TLS read functions (OpenSSL SSL_read, gnutls_record_recv, NSS PR_Read/PR_Recv)
int ssl_read_enter(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    struct read_args_t a = {};
    a.id  = (u64)PT_REGS_PARM1(ctx);          // SSL*/session*/PRFileDesc*
    a.buf = (const void *)PT_REGS_PARM2(ctx); // user buffer

    read_args.update(&tid, &a);
    return 0;
}

// Exit for all TLS read functions
int ssl_read_exit(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct read_args_t *ap = read_args.lookup(&tid);
    if (!ap) {
        // nothing recorded for this thread
        return 0;
    }

    if (ret <= 0) {
        // read failed or EOF; drop and clean up
        read_args.delete(&tid);
        return 0;
    }

    struct conn_key_t key = {};
    key.pid = pid;
    key.id  = ap->id;

    struct req_val_t *vp = active_reqs.lookup(&key);
    if (!vp) {
        read_args.delete(&tid);
        return 0;
    }

    int zero = 0;
    struct event_t *evt = tmp_evt.lookup(&zero);
    if (!evt) {
        // should not happen, but be safe
        active_reqs.delete(&key);
        read_args.delete(&tid);
        return 0;
    }

    __builtin_memset(evt, 0, sizeof(*evt));

    evt->ts    = bpf_ktime_get_ns();
    evt->delta = evt->ts - vp->start_ns;
    evt->pid   = pid;
    evt->tid   = tid;
    evt->op    = vp->op;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    __builtin_memcpy(&evt->req_hdr, &vp->hdr, sizeof(evt->req_hdr));

    int rcopy = ret;
    if (rcopy > MAX_HDR)
        rcopy = MAX_HDR;
    bpf_probe_read_user(&evt->resp_hdr, rcopy, ap->buf);

    events.perf_submit(ctx, evt, sizeof(*evt));

    active_reqs.delete(&key);
    read_args.delete(&tid);
    return 0;
}
"""

# ---------------------------------------------------------------------------
# User-space structures & helpers
# ---------------------------------------------------------------------------


class Event(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("delta", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("op", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("req_hdr", ct.c_char * 256),
        ("resp_hdr", ct.c_char * 256),
    ]


OP_MAP = {
    0: "UNK",
    1: "GET",
    2: "PUT",
    3: "HEAD",
    4: "POST",
    5: "DEL",
}


def ns_to_ms(ns: int) -> float:
    return float(ns) / 1e6


def find_library(patterns: Iterable[str]) -> Optional[str]:
    search_roots = [
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/lib",
        "/lib64",
        "/lib/x86_64-linux-gnu",
    ]
    for root in search_roots:
        for pat in patterns:
            for path in glob.glob(os.path.join(root, "**", pat), recursive=True):
                return path
    return None


def attach_openssl(b: BPF, libpath: str, pid: int) -> None:
    # SSL_write: entry
    b.attach_uprobe(name=libpath, sym="SSL_write",
                    fn_name="ssl_write_enter", pid=pid)
    # SSL_read: entry + return
    b.attach_uprobe(name=libpath, sym="SSL_read",
                    fn_name="ssl_read_enter", pid=pid)
    b.attach_uretprobe(name=libpath, sym="SSL_read",
                       fn_name="ssl_read_exit", pid=pid)


def attach_gnutls(b: BPF, libpath: str, pid: int) -> None:
    # gnutls_record_send / gnutls_record_recv
    b.attach_uprobe(name=libpath, sym="gnutls_record_send",
                    fn_name="ssl_write_enter", pid=pid)
    b.attach_uprobe(name=libpath, sym="gnutls_record_recv",
                    fn_name="ssl_read_enter", pid=pid)
    b.attach_uretprobe(name=libpath, sym="gnutls_record_recv",
                       fn_name="ssl_read_exit", pid=pid)


def attach_nss(b: BPF, libpath: str, pid: int) -> None:
    # NSS/NSPR: PR_Write/PR_Send (write), PR_Read/PR_Recv (read)
    for sym in ("PR_Write", "PR_Send"):
        b.attach_uprobe(name=libpath, sym=sym,
                        fn_name="ssl_write_enter", pid=pid)
    for sym in ("PR_Read", "PR_Recv"):
        b.attach_uprobe(name=libpath, sym=sym,
                        fn_name="ssl_read_enter", pid=pid)
        b.attach_uretprobe(name=libpath, sym=sym,
                           fn_name="ssl_read_exit", pid=pid)


def parse_http_request(raw_hdr: bytes) -> Tuple[str, str, str, int]:
    """
    Parse minimal HTTP/1.x request from a small header buffer.

    Returns (method, host, path, content_length).
    """
    try:
        text = raw_hdr.decode("utf-8", "replace")
    except Exception:
        return "", "", "", 0

    lines = text.split("\r\n")
    if not lines:
        return "", "", "", 0

    req_line = lines[0]
    parts = req_line.split()
    if len(parts) < 2:
        return "", "", "", 0

    method = parts[0]
    path = parts[1]
    host = ""
    content_length = 0

    for line in lines[1:]:
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("host:"):
            host = line.split(":", 1)[1].strip()
        elif lower.startswith("content-length:"):
            val = line.split(":", 1)[1].strip()
            try:
                content_length = int(val)
            except ValueError:
                pass

    return method, host, path, content_length


def parse_http_response(raw_hdr: bytes) -> int:
    """
    Parse HTTP/1.x response line from a small buffer.

    Returns status_code (int) or 0 if unknown.
    """
    try:
        text = raw_hdr.decode("utf-8", "replace")
    except Exception:
        return 0

    lines = text.split("\r\n")
    if not lines:
        return 0

    line = lines[0]
    # Expect: HTTP/1.1 200 OK
    parts = line.split()
    if len(parts) < 2:
        return 0

    if not parts[0].startswith("HTTP/"):
        return 0

    try:
        code = int(parts[1])
        return code
    except ValueError:
        return 0


def parse_bucket_endpoint(host: str, path: str) -> Tuple[str, str]:
    """
    Heuristically derive (bucket, endpoint) from Host + path.

    Priority:
      1. Path-style:  /bucket/key...
      2. Virtual-host-style: bucket.endpoint.example.com
    """
    bucket = ""
    endpoint = host or ""

    # 1. Path-style: /bucket/key
    if path.startswith("/"):
        parts = path.split("/", 2)
        # ['', 'bucket', 'key...']
        if len(parts) >= 3 and parts[1]:
            bucket = parts[1]

    # 2. Virtual-host-style: bucket.host.tld
    if not bucket and host:
        labels = host.split(".")
        if len(labels) >= 3:
            bucket = labels[0]
            endpoint = ".".join(labels[1:])
        else:
            endpoint = host

    return bucket, endpoint


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    if p <= 0:
        return min(values)
    if p >= 100:
        return max(values)

    sorted_vals = sorted(values)
    idx = int(round((p / 100.0) * (len(sorted_vals) - 1)))
    return sorted_vals[idx]


def print_summary(stats: Dict[str, List[float]]) -> None:
    if not stats:
        print("\nNo S3-like HTTP traffic captured.")
        return

    print("\nSummary (per-op latency in ms):")
    print("%-6s %8s %10s %8s %8s %8s" %
          ("OP", "COUNT", "AVG", "P50", "P90", "P99"))

    for op in sorted(stats.keys()):
        vals = stats[op]
        if not vals:
            continue
        count = len(vals)
        avg = sum(vals) / count
        p50 = percentile(vals, 50)
        p90 = percentile(vals, 90)
        p99 = percentile(vals, 99)
        print("%-6s %8d %10.3f %8.3f %8.3f %8.3f" %
              (op, count, avg, p50, p90, p99))


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

REQ_LATENCY: Optional[Histogram] = None
REQ_TOTAL: Optional[Counter] = None
REQ_BYTES: Optional[Counter] = None
RESP_TOTAL: Optional[Counter] = None


def init_prometheus(port: int) -> None:
    global REQ_LATENCY, REQ_TOTAL, REQ_BYTES, RESP_TOTAL

    if not HAVE_PROM:
        print(
            "ERROR: prometheus_client is not installed but --prometheus-port was used.\n"
            "Install it with: pip install prometheus_client",
            file=sys.stderr,
        )
        sys.exit(1)

    start_http_server(port)

    # Label set: bucket, endpoint, method
    REQ_LATENCY = Histogram(
        "s3slower_request_latency_seconds",
        "S3-like request latency (request write -> first response read)",
        ["bucket", "endpoint", "method"],
    )
    REQ_TOTAL = Counter(
        "s3slower_requests_total",
        "Total S3-like HTTP requests seen by s3slower",
        ["bucket", "endpoint", "method"],
    )
    REQ_BYTES = Counter(
        "s3slower_request_bytes_total",
        "Total S3-like HTTP request bytes (Content-Length header)",
        ["bucket", "endpoint", "method"],
    )
    RESP_TOTAL = Counter(
        "s3slower_responses_total",
        "Total S3-like HTTP responses seen by s3slower, by status code",
        ["bucket", "endpoint", "method", "status"],
    )


def update_prometheus(bucket: str, endpoint: str, method: str,
                      latency_seconds: float, size_bytes: int, status_code: int) -> None:
    if REQ_LATENCY is None or REQ_TOTAL is None or REQ_BYTES is None or RESP_TOTAL is None:
        return

    bucket_label = bucket or "unknown"
    endpoint_label = endpoint or "unknown"
    method_label = method or "UNK"

    # Request-side metrics
    REQ_LATENCY.labels(bucket=bucket_label,
                       endpoint=endpoint_label,
                       method=method_label).observe(latency_seconds)
    REQ_TOTAL.labels(bucket=bucket_label,
                     endpoint=endpoint_label,
                     method=method_label).inc()
    if size_bytes > 0:
        REQ_BYTES.labels(bucket=bucket_label,
                         endpoint=endpoint_label,
                         method=method_label).inc(size_bytes)

    # Response code counter
    if 100 <= status_code <= 999:
        status_label = str(status_code)
    else:
        status_label = "unknown"

    RESP_TOTAL.labels(bucket=bucket_label,
                      endpoint=endpoint_label,
                      method=method_label,
                      status=status_label).inc()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prototype SSL/TLS-based S3 latency tracer (s3slower-style)")
    parser.add_argument("--pid", type=int, default=0,
                        help="Trace only this PID (default: all processes)")
    parser.add_argument("--openssl", action="store_true",
                        help="Attach to OpenSSL/BoringSSL (libssl.so*)")
    parser.add_argument("--gnutls", action="store_true",
                        help="Attach to GnuTLS (libgnutls.so*)")
    parser.add_argument("--nss", action="store_true",
                        help="Attach to NSS/NSPR (libnspr4.so*)")

    parser.add_argument("--libssl", help="Explicit path to libssl.so")
    parser.add_argument("--libgnutls", help="Explicit path to libgnutls.so")
    parser.add_argument("--libnss", help="Explicit path to libnspr4.so")

    parser.add_argument("--host-substr", metavar="STR",
                        help="Only show requests whose Host header contains STR "
                             "(e.g. s3, minio, vast)")
    parser.add_argument("--method", "-m", action="append",
                        help="Only show given HTTP method(s) (e.g. GET,PUT,HEAD). "
                             "May be given multiple times.")
    parser.add_argument("--min-lat-ms", type=float, default=0.0,
                        help="Only print requests with latency >= this many ms")
    parser.add_argument("--include-unknown", action="store_true",
                        help="Include traffic that doesn't parse as HTTP or has "
                             "unknown method (OP=UNK)")

    parser.add_argument("--prometheus-port", type=int, default=0,
                        help="If >0, expose Prometheus /metrics on this port")

    args = parser.parse_args()

    # Auto-TLS mode: if no TLS library is explicitly selected, try all of them
    auto_tls = False
    if not (args.openssl or args.gnutls or args.nss):
        auto_tls = True
        args.openssl = True
        args.gnutls = True
        args.nss = True
        print("Auto TLS mode: attempting OpenSSL, GnuTLS, and NSS (where present)")

    if args.prometheus_port > 0:
        init_prometheus(args.prometheus_port)
        print(f"Prometheus /metrics listening on :{args.prometheus_port}")

    b = BPF(text=BPF_TEXT)
    pid = args.pid or -1  # BCC uses -1 for "all PIDs" in uprobes

    # Attach libraries -------------------------------------------------------
    if args.openssl:
        libssl = args.libssl or find_library(["libssl.so", "libssl.so.*"])
        if not libssl:
            if auto_tls:
                print("Auto TLS: OpenSSL (libssl.so) not found, skipping")
            else:
                print("Could not find libssl.so; use --libssl to specify path")
                sys.exit(1)
        else:
            print(f"Attaching to OpenSSL/BoringSSL at {libssl}")
            attach_openssl(b, libssl, pid)

    if args.gnutls:
        libgnutls = args.libgnutls or find_library(["libgnutls.so", "libgnutls.so.*"])
        if not libgnutls:
            if auto_tls:
                print("Auto TLS: GnuTLS (libgnutls.so) not found, skipping")
            else:
                print("Could not find libgnutls.so; use --libgnutls to specify path")
                sys.exit(1)
        else:
            print(f"Attaching to GnuTLS at {libgnutls}")
            attach_gnutls(b, libgnutls, pid)

    if args.nss:
        libnss = args.libnss or find_library(["libnspr4.so", "libnspr4.so.*"])
        if not libnss:
            if auto_tls:
                print("Auto TLS: NSS/NSPR (libnspr4.so) not found, skipping")
            else:
                print("Could not find libnspr4.so; use --libnss to specify path")
                sys.exit(1)
        else:
            print(f"Attaching to NSS/NSPR at {libnss}")
            attach_nss(b, libnss, pid)

    host_filter = args.host_substr.lower() if args.host_substr else None
    method_filter = {m.upper() for m in args.method} if args.method else None

    # Per-op latency stats (ms)
    stats: Dict[str, List[float]] = defaultdict(list)

    # Header
    # print("%-8s %-6s %-16s %-4s %-9s %-6s %-20s %-20s %s" %
    #       ("TIME", "PID", "COMM", "OP", "LAT(ms)", "STATUS", "BUCKET", "ENDPOINT", "PATH"))
    # Header
    print("%-8s %-6s %-16s %-12s %-9s %-6s %-20s %-20s %s" %
          ("TIME", "PID", "COMM", "OP", "LAT(ms)", "STATUS", "BUCKET", "ENDPOINT", "PATH"))

    exiting = False

    def handle_sigint(signum, frame) -> None:  # type: ignore[override]
        nonlocal exiting
        exiting = True

    signal.signal(signal.SIGINT, handle_sigint)

    def handle_event(cpu: int, data: bytes, size: int) -> None:
        evt = ct.cast(data, ct.POINTER(Event)).contents

        raw_req = bytes(evt.req_hdr)
        raw_resp = bytes(evt.resp_hdr)

        method, host, path, content_length = parse_http_request(raw_req)
        status_code = parse_http_response(raw_resp)

        if not method and not args.include_unknown:
            return

        op_name = OP_MAP.get(evt.op, "UNK")

        # Filters
        if method_filter is not None:
            if method:
                if method.upper() not in method_filter:
                    return
            else:
                if not args.include_unknown:
                    return

        if host_filter is not None:
            if not host or host_filter not in host.lower():
                return

        lat_ms = ns_to_ms(evt.delta)
        if lat_ms < args.min_lat_ms:
            return

        bucket, endpoint = parse_bucket_endpoint(host, path)

        # Base method bucket: HTTP method if we have one, otherwise fallback (GET/PUT/HEAD/POST/DEL/UNK)
        method_upper = method.upper() if method else ""
        method_bucket = method_upper if method_upper else op_name

    # Friendly MPU naming:
    #   POST ... ?uploads              -> MPU_CREATE
    #   POST ... ?uploadId=...        -> MPU_COMPLETE
        if method_upper == "POST" and path:
            if "uploads" in path and "uploadId=" not in path:
                method_bucket = "MPU_CREATE"
            elif "uploadId=" in path:
                method_bucket = "MPU_COMPLETE"

    # Update local stats
        stats[method_bucket].append(lat_ms)
        stats["ALL"].append(lat_ms)

    # Update Prometheus (latency, size, response code)
        update_prometheus(bucket, endpoint, method_bucket, lat_ms / 1000.0, content_length, status_code)

    # Per-event line
        tstr = time.strftime("%H:%M:%S", time.localtime())
        comm = evt.comm.decode("utf-8", "replace").rstrip("\x00")

        disp_bucket = bucket[:18] + ".." if len(bucket) > 20 else bucket
        disp_endpoint = endpoint[:18] + ".." if len(endpoint) > 20 else endpoint
        disp_path = path or ""
        status_str = str(status_code) if status_code > 0 else "-"

        print("%-8s %-6d %-16s %-12s %-9.3f %-6s %-20s %-20s %s" %
              (tstr, evt.pid, comm, method_bucket, lat_ms,
               status_str, disp_bucket, disp_endpoint, disp_path))


    b["events"].open_perf_buffer(handle_event)

    try:
        while not exiting:
            b.perf_buffer_poll(timeout=100)
    finally:
        print_summary(stats)


if __name__ == "__main__":
    main()
