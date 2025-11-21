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
import select
import signal
import sys
import termios
import time
import tty
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
    u64 seq; // sequence number to handle multiple requests on same connection
};

struct conn_id_t {
    u32 pid;
    u64 id;
};

struct req_val_t {
    u64 start_ns;
    u32 op;
    u8 responded;  // flag to track if we've already captured a response
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
BPF_HASH(http_read_args, u32, struct read_args_t);  // separate state for plain HTTP (syscall-level)
BPF_HASH(conn_seqs, struct conn_id_t, u64);  // track sequence numbers per connection
BPF_PERCPU_ARRAY(tmp_evt, struct event_t, 1);
BPF_PERF_OUTPUT(events);

static inline u32 classify_method(char *buf, int len)
{
    // Search for HTTP method within first 40 bytes to handle offset/partial data
    // Reduced from 64 to help BPF verifier prove bounds safety
    int search_len = len < 40 ? len : 40;

    #pragma unroll 32
    for (int i = 0; i < 32 && i < search_len - 7; i++) {
        // Check for GET followed by space
        if (buf[i] == 'G' && buf[i+1] == 'E' && buf[i+2] == 'T' && buf[i+3] == ' ')
            return OP_GET;
        // Check for PUT followed by space
        if (buf[i] == 'P' && buf[i+1] == 'U' && buf[i+2] == 'T' && buf[i+3] == ' ')
            return OP_PUT;
        // Check for POST
        if (buf[i] == 'P' && buf[i+1] == 'O' && buf[i+2] == 'S' && buf[i+3] == 'T' && buf[i+4] == ' ')
            return OP_POST;
        // Check for HEAD
        if (buf[i] == 'H' && buf[i+1] == 'E' && buf[i+2] == 'A' && buf[i+3] == 'D' && buf[i+4] == ' ')
            return OP_HEAD;
        // Check for DELETE
        if (buf[i] == 'D' && buf[i+1] == 'E' && buf[i+2] == 'L' && buf[i+3] == 'E' &&
            buf[i+4] == 'T' && buf[i+5] == 'E' && buf[i+6] == ' ')
            return OP_DELETE;
    }
    return OP_UNKNOWN;
}

// Helper: check if buffer starts with "HTTP/" (validate response format)
static inline int is_http_response(char *buf, int len)
{
    if (len < 5)
        return 0;
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P' && buf[4] == '/')
        return 1;
    return 0;
}

// Helper: extract status code from HTTP response (returns 0 if invalid)
static inline int extract_status_code(char *buf, int len)
{
    // Look for "HTTP/1.x XXX" pattern
    // Example: "HTTP/1.1 200 OK\r\n"
    if (len < 13 || !is_http_response(buf, len))
        return 0;

    // Find first space after HTTP/1.x
    int space_pos = -1;
    for (int i = 8; i < 12 && i < len; i++) {
        if (buf[i] == ' ') {
            space_pos = i;
            break;
        }
    }

    if (space_pos < 0 || space_pos + 3 >= len)
        return 0;

    // Parse 3-digit status code
    int code = 0;
    for (int i = 0; i < 3; i++) {
        char c = buf[space_pos + 1 + i];
        if (c < '0' || c > '9')
            return 0;
        code = code * 10 + (c - '0');
    }

    return code;
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

    // Store request with unique key (pid, id, seq)
    struct conn_key_t key = {};
    key.pid = pid;
    key.id  = id;

    struct req_val_t val = {};
    val.start_ns = bpf_ktime_get_ns();
    val.responded = 0;

    // Read buffer directly into val.hdr
    int copy = len;
    if (copy > MAX_HDR)
        copy = MAX_HDR;
    bpf_probe_read_user(&val.hdr, copy, buf);

    // Classify method - if UNKNOWN, this might be body data or non-HTTP, skip it
    val.op = classify_method(val.hdr, copy);
    if (val.op == OP_UNKNOWN)
        return 0;  // Skip non-HTTP writes (body data, TLS handshake, etc.)

    // Get or create sequence number for this connection
    struct conn_id_t conn = {};
    conn.pid = pid;
    conn.id = id;

    u64 *seq_ptr = conn_seqs.lookup(&conn);
    u64 seq = 0;
    if (seq_ptr) {
        seq = (*seq_ptr) + 1;
    }
    conn_seqs.update(&conn, &seq);

    key.seq = seq;
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

    // Use the per-CPU event buffer to store response temporarily
    int zero = 0;
    struct event_t *evt = tmp_evt.lookup(&zero);
    if (!evt) {
        read_args.delete(&tid);
        return 0;
    }

    // Read response buffer into event struct (will reuse for final event if needed)
    int rcopy = ret;
    if (rcopy > MAX_HDR)
        rcopy = MAX_HDR;
    bpf_probe_read_user(&evt->resp_hdr, rcopy, ap->buf);

    // Validate this is an HTTP response
    if (!is_http_response(evt->resp_hdr, rcopy)) {
        // Not HTTP response - might be body data or other traffic
        read_args.delete(&tid);
        return 0;
    }

    // Extract status code to check for 1xx intermediate responses
    int status_code = extract_status_code(evt->resp_hdr, rcopy);

    // Get connection info to find matching request
    struct conn_id_t conn = {};
    conn.pid = pid;
    conn.id = ap->id;

    // Get current sequence number for this connection
    u64 *seq_ptr = conn_seqs.lookup(&conn);
    if (!seq_ptr) {
        read_args.delete(&tid);
        return 0;
    }

    // Try to find matching request by checking current and recent sequence numbers
    // Start from current seq and work backwards (in case of response ordering issues)
    struct req_val_t *vp = NULL;
    struct conn_key_t key = {};
    key.pid = pid;
    key.id = ap->id;

    // Check last 10 sequence numbers (handles minor reordering)
    u64 current_seq = *seq_ptr;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (current_seq < i)
            break;
        key.seq = current_seq - i;
        vp = active_reqs.lookup(&key);
        if (vp && !vp->responded) {
            // Found unresp onded request
            break;
        }
        vp = NULL;
    }

    if (!vp) {
        read_args.delete(&tid);
        return 0;
    }

    // Check if already responded (shouldn't happen due to check above, but be safe)
    if (vp->responded) {
        read_args.delete(&tid);
        return 0;
    }

    // If this is a 1xx response (e.g. 100 Continue), mark as responded but don't emit event
    // Keep the request active for the final 2xx/3xx/4xx/5xx response
    if (status_code >= 100 && status_code < 200) {
        vp->responded = 1;  // Mark that we've seen a response, but keep entry
        read_args.delete(&tid);
        // Don't delete from active_reqs - wait for final response
        return 0;
    }

    // This is a final response (2xx, 3xx, 4xx, 5xx) - emit event
    // evt already has resp_hdr filled from earlier
    evt->ts    = bpf_ktime_get_ns();
    evt->delta = evt->ts - vp->start_ns;
    evt->pid   = pid;
    evt->tid   = tid;
    evt->op    = vp->op;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    __builtin_memcpy(&evt->req_hdr, &vp->hdr, sizeof(evt->req_hdr));
    // resp_hdr already filled above

    events.perf_submit(ctx, evt, sizeof(*evt));

    // Delete request after final response
    active_reqs.delete(&key);
    read_args.delete(&tid);
    return 0;
}

// ---------------------------------------------------------------------------
// Plain HTTP over TCP (syscall-level: sendto/recvfrom)
// ---------------------------------------------------------------------------

// Entry for HTTP send syscalls (sendto/send)
int http_send_enter(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    int fd = (int)PT_REGS_PARM1(ctx);       // socket fd
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int len = (int)PT_REGS_PARM3(ctx);

    if (len <= 0)
        return 0;

    // Store request with unique key (pid, fd, seq)
    struct conn_key_t key = {};
    key.pid = pid;
    key.id  = (u64)fd;

    struct req_val_t val = {};
    val.start_ns = bpf_ktime_get_ns();
    val.responded = 0;

    int copy = len;
    if (copy > MAX_HDR)
        copy = MAX_HDR;
    bpf_probe_read_user(&val.hdr, copy, buf);

    // Classify method - if UNKNOWN, this might be body data or non-HTTP, skip it
    val.op = classify_method(val.hdr, copy);
    if (val.op == OP_UNKNOWN)
        return 0;

    // Get or create sequence number for this connection
    struct conn_id_t conn = {};
    conn.pid = pid;
    conn.id = key.id;

    u64 *seq_ptr = conn_seqs.lookup(&conn);
    u64 seq = 0;
    if (seq_ptr) {
        seq = (*seq_ptr) + 1;
    }
    conn_seqs.update(&conn, &seq);

    key.seq = seq;
    active_reqs.update(&key, &val);
    return 0;
}

// Entry for HTTP recv syscalls (recvfrom/recv)
int http_recv_enter(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    struct read_args_t a = {};
    a.id  = (u64)PT_REGS_PARM1(ctx);          // socket fd
    a.buf = (const void *)PT_REGS_PARM2(ctx); // user buffer

    http_read_args.update(&tid, &a);
    return 0;
}

// Exit for HTTP recv syscalls
int http_recv_exit(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct read_args_t *ap = http_read_args.lookup(&tid);
    if (!ap) {
        // nothing recorded for this thread
        return 0;
    }

    if (ret <= 0) {
        // recv failed or EOF; drop and clean up
        http_read_args.delete(&tid);
        return 0;
    }

    // Use the per-CPU event buffer to store response temporarily
    int zero = 0;
    struct event_t *evt = tmp_evt.lookup(&zero);
    if (!evt) {
        http_read_args.delete(&tid);
        return 0;
    }

    // Read response buffer into event struct (will reuse for final event if needed)
    int rcopy = ret;
    if (rcopy > MAX_HDR)
        rcopy = MAX_HDR;
    bpf_probe_read_user(&evt->resp_hdr, rcopy, ap->buf);

    // Validate this is an HTTP response
    if (!is_http_response(evt->resp_hdr, rcopy)) {
        // Not HTTP response - might be body data or other traffic
        http_read_args.delete(&tid);
        return 0;
    }

    // Extract status code to check for 1xx intermediate responses
    int status_code = extract_status_code(evt->resp_hdr, rcopy);

    // Get connection info to find matching request
    struct conn_id_t conn = {};
    conn.pid = pid;
    conn.id = ap->id;

    // Get current sequence number for this connection
    u64 *seq_ptr = conn_seqs.lookup(&conn);
    if (!seq_ptr) {
        http_read_args.delete(&tid);
        return 0;
    }

    // Try to find matching request by checking current and recent sequence numbers
    // Start from current seq and work backwards (in case of response ordering issues)
    struct req_val_t *vp = NULL;
    struct conn_key_t key = {};
    key.pid = pid;
    key.id = ap->id;

    // Check last 10 sequence numbers (handles minor reordering)
    u64 current_seq = *seq_ptr;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (current_seq < i)
            break;
        key.seq = current_seq - i;
        vp = active_reqs.lookup(&key);
        if (vp && !vp->responded) {
            // Found unresponded request
            break;
        }
        vp = NULL;
    }

    if (!vp) {
        http_read_args.delete(&tid);
        return 0;
    }

    // Check if already responded (shouldn't happen due to check above, but be safe)
    if (vp->responded) {
        http_read_args.delete(&tid);
        return 0;
    }

    // If this is a 1xx response (e.g. 100 Continue), mark as responded but don't emit event
    // Keep the request active for the final 2xx/3xx/4xx/5xx response
    if (status_code >= 100 && status_code < 200) {
        vp->responded = 1;  // Mark that we've seen a response, but keep entry
        http_read_args.delete(&tid);
        // Don't delete from active_reqs - wait for final response
        return 0;
    }

    // This is a final response (2xx, 3xx, 4xx, 5xx) - emit event
    // evt already has resp_hdr filled from earlier
    evt->ts    = bpf_ktime_get_ns();
    evt->delta = evt->ts - vp->start_ns;
    evt->pid   = pid;
    evt->tid   = tid;
    evt->op    = vp->op;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    __builtin_memcpy(&evt->req_hdr, &vp->hdr, sizeof(evt->req_hdr));
    // resp_hdr already filled above

    events.perf_submit(ctx, evt, sizeof(*evt));

    // Delete request after final response
    active_reqs.delete(&key);
    http_read_args.delete(&tid);
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


def attach_http(b: BPF) -> None:
    """
    Attach to kernel send/recv syscalls for plain HTTP over TCP.

    We only look at sendto/recvfrom; for most user-space libraries send()
    is implemented via sendto() in the kernel, so this should cover common
    S3 HTTP clients.
    """
    attached = False

    try:
        sendto_fn = b.get_syscall_fnname("sendto")
        b.attach_kprobe(event=sendto_fn, fn_name="http_send_enter")
        attached = True
    except Exception:
        pass

    try:
        recvfrom_fn = b.get_syscall_fnname("recvfrom")
        b.attach_kprobe(event=recvfrom_fn, fn_name="http_recv_enter")
        b.attach_kretprobe(event=recvfrom_fn, fn_name="http_recv_exit")
        attached = True
    except Exception:
        pass

    if attached:
        print("Attaching to plain HTTP via sys_sendto/sys_recvfrom")
    else:
        print(
            "Plain HTTP: could not attach to send/recv syscalls; "
            "HTTP traffic will not be traced",
            file=sys.stderr,
        )


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
# Terminal handling
# ---------------------------------------------------------------------------

def setup_terminal() -> Optional[list]:
    """
    Configure terminal to minimize control character interference.
    Returns the original terminal settings to restore later, or None if not a TTY.
    """
    if not sys.stdin.isatty():
        return None

    try:
        # Save original terminal settings
        old_settings = termios.tcgetattr(sys.stdin)

        # Get current settings to modify
        new_settings = termios.tcgetattr(sys.stdin)

        # Disable echo and special character processing
        # ICANON: canonical mode (line buffering)
        # ECHO: echo input characters
        # ISIG: enable signals (keep this for Ctrl+C)
        # IEXTEN: extended functions
        new_settings[3] &= ~(termios.ICANON | termios.ECHO | termios.IEXTEN)

        # Apply new settings
        termios.tcsetattr(sys.stdin, termios.TCSANOW, new_settings)

        # Disable mouse reporting and other terminal features that send escape sequences
        # These are ANSI escape sequences to disable various reporting modes
        sys.stdout.write('\033[?1000l')  # Disable mouse reporting
        sys.stdout.write('\033[?1002l')  # Disable mouse tracking
        sys.stdout.write('\033[?1003l')  # Disable all mouse reporting
        sys.stdout.write('\033[?1004l')  # Disable focus reporting
        sys.stdout.write('\033[?1005l')  # Disable UTF-8 mouse mode
        sys.stdout.write('\033[?1006l')  # Disable SGR mouse mode
        sys.stdout.write('\033[?1015l')  # Disable URXVT mouse mode
        sys.stdout.flush()

        return old_settings
    except Exception:
        # If we can't configure the terminal, continue anyway
        return None


def restore_terminal(old_settings: Optional[list]) -> None:
    """Restore original terminal settings."""
    if old_settings is not None and sys.stdin.isatty():
        try:
            termios.tcsetattr(sys.stdin, termios.TCSANOW, old_settings)
        except Exception:
            pass


def flush_stdin() -> None:
    """Flush any pending input from stdin to prevent control characters from appearing."""
    if not sys.stdin.isatty():
        return

    try:
        # Check if there's input available and discard it
        while select.select([sys.stdin], [], [], 0)[0]:
            # Read and discard available input
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
            break
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="S3 latency tracer using TLS libraries and plain HTTP (s3slower-style)")
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

    parser.add_argument("--http-only", action="store_true",
                        help="Trace only plain HTTP over TCP (disable TLS library probes)")
    parser.add_argument("--no-http", action="store_true",
                        help="Disable plain HTTP tracing; only trace TLS libraries")

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
    parser.add_argument("--log-file",
                        help="If set, append raw per-request events as TSV to this file")

    args = parser.parse_args()

    log_fh = None
    if args.log_file:
        try:
            log_fh = open(args.log_file, "a", buffering=1)
            print(f"Logging raw events to {args.log_file}")
        except OSError as e:
            print(f"ERROR: could not open log file {args.log_file}: {e}", file=sys.stderr)
            sys.exit(1)

    if args.http_only and args.no_http:
        print("ERROR: --http-only and --no-http are mutually exclusive", file=sys.stderr)
        sys.exit(1)

    if args.http_only and (args.openssl or args.gnutls or args.nss or
                           args.libssl or args.libgnutls or args.libnss):
        print(
            "ERROR: --http-only cannot be combined with TLS library options "
            "(--openssl/--gnutls/--nss/--libssl/--libgnutls/--libnss)",
            file=sys.stderr,
        )
        sys.exit(1)

    # Determine which tracing modes are enabled
    want_http = not args.no_http
    want_tls = not args.http_only

    # Auto-TLS mode: if TLS is enabled and no TLS library is explicitly selected, try all of them
    auto_tls = False
    if want_tls and not (args.openssl or args.gnutls or args.nss):
        auto_tls = True
        args.openssl = True
        args.gnutls = True
        args.nss = True
        print("Auto TLS mode: attempting OpenSSL, GnuTLS, and NSS (where present)")

    if args.prometheus_port > 0:
        init_prometheus(args.prometheus_port)
        print(f"Prometheus /metrics listening on :{args.prometheus_port}")

    # Setup terminal to prevent control character interference
    old_terminal_settings = setup_terminal()

    b = BPF(text=BPF_TEXT)
    pid = args.pid or -1  # BCC uses -1 for "all PIDs" in uprobes

    # Attach libraries -------------------------------------------------------
    if want_tls:
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

    if want_http:
        attach_http(b)

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
        restore_terminal(old_terminal_settings)

    signal.signal(signal.SIGINT, handle_sigint)

    def handle_event(cpu: int, data: bytes, size: int, log_fh=log_fh) -> None:
        evt = ct.cast(data, ct.POINTER(Event)).contents

        # Users may request pid filtering; enforce it here for both TLS and HTTP events.
        if args.pid and evt.pid != args.pid:
            return

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

        # Structured log for correlation with traffic generators
        if log_fh is not None:
            try:
                log_fh.write(
                    f"{evt.ts}\t{tstr}\t{evt.pid}\t{comm}\t{method_bucket}\t"
                    f"{lat_ms:.3f}\t{status_str}\t{bucket}\t{endpoint}\t{path or ''}\n"
                )
            except Exception:
                # Logging failures should not break tracing
                pass


    b["events"].open_perf_buffer(handle_event)

    try:
        poll_counter = 0
        while not exiting:
            # Flush stdin periodically to discard any control characters
            if poll_counter % 10 == 0:  # Flush every 10 polls (1 second)
                flush_stdin()
            poll_counter += 1

            b.perf_buffer_poll(timeout=100)
    finally:
        restore_terminal(old_terminal_settings)
        print_summary(stats)
        if log_fh is not None:
            try:
                log_fh.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
