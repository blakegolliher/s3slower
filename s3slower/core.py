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
import logging
import os
import select
import signal
import sys
import termios
import threading
import time
import tty
from collections import defaultdict
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from bcc import BPF

# Local modules (works when executed as a package or standalone)
try:
    from .config import DEFAULT_TARGETS_PATH, TargetConfig, collect_extra_label_keys, load_targets
    from .watcher import TargetWatcher
except ImportError:
    from config import DEFAULT_TARGETS_PATH, TargetConfig, collect_extra_label_keys, load_targets  # type: ignore
    from watcher import TargetWatcher  # type: ignore

# Prometheus is optional; only required if --prometheus-port is used.
try:
    from prometheus_client import Counter, Histogram, start_http_server  # type: ignore
    HAVE_PROM = True
except ImportError:
    HAVE_PROM = False

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # type: ignore

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_PATH = "/etc/s3slower/config.yaml"
DEFAULT_LOG_PATH = "/opt/s3slower/s3slower.log"
DEFAULT_LOG_MAX_MB = 100
DEFAULT_LOG_BACKUPS = 5
DEFAULT_METRICS_REFRESH_SEC = 5.0
DEFAULT_PROM_HOST = "0.0.0.0"
DEFAULT_PROM_PORT = 0

# Display formatting constants
DISPLAY_BUCKET_MAX_WIDTH = 20
DISPLAY_ENDPOINT_MAX_WIDTH = 20
DISPLAY_TRUNCATE_SUFFIX = ".."

# Tracing constants
PERF_BUFFER_POLL_TIMEOUT_MS = 100
STDIN_FLUSH_INTERVAL = 10  # Flush stdin every N poll cycles

# Minimum metrics refresh interval (seconds)
MIN_METRICS_REFRESH_INTERVAL = 0.1

# Library patterns for TLS library discovery
TLS_LIBRARY_PATTERNS = {
    "openssl": ["libssl.so", "libssl.so.*"],
    "gnutls": ["libgnutls.so", "libgnutls.so.*"],
    "nss": ["libnspr4.so", "libnspr4.so.*"],
}


@dataclass
class RuntimeSettings:
    log_enabled: bool = True
    log_path: str = DEFAULT_LOG_PATH
    log_max_size_mb: int = DEFAULT_LOG_MAX_MB
    log_max_backups: int = DEFAULT_LOG_BACKUPS
    prometheus_host: str = DEFAULT_PROM_HOST
    prometheus_port: int = DEFAULT_PROM_PORT
    metrics_refresh_interval: float = DEFAULT_METRICS_REFRESH_SEC


@dataclass
class TargetMeta:
    """
    Metadata associated with an attached PID for labeling output and metrics.
    """

    target_name: Optional[str] = None
    prom_labels: Dict[str, str] = field(default_factory=dict)


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def load_config_file(path: str) -> Dict[str, Any]:
    """
    Load YAML config if present; return {} if file is absent.
    """
    if not path:
        return {}

    if not os.path.isfile(path):
        return {}

    if yaml is None:
        print(
            f"Config file found at {path} but PyYAML is not installed. "
            "Install it with: pip install pyyaml",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception as exc:
        print(f"ERROR: failed to read config file {path}: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, dict):
        print(f"ERROR: config file {path} must contain a YAML mapping/object", file=sys.stderr)
        sys.exit(1)

    return data


def build_runtime_settings(args: argparse.Namespace, cfg: Dict[str, Any]) -> RuntimeSettings:
    """
    Merge defaults -> config -> CLI overrides into a RuntimeSettings object.
    """
    settings = RuntimeSettings()

    log_cfg = cfg.get("logging", {}) if isinstance(cfg, dict) else {}
    if isinstance(log_cfg, dict):
        settings.log_enabled = bool(log_cfg.get("enabled", settings.log_enabled))
        settings.log_path = log_cfg.get("path", settings.log_path) or settings.log_path
        settings.log_max_size_mb = _safe_int(log_cfg.get("max_size_mb"), settings.log_max_size_mb)
        settings.log_max_backups = _safe_int(log_cfg.get("max_backups"), settings.log_max_backups)

    prom_cfg = cfg.get("prometheus", {}) if isinstance(cfg, dict) else {}
    if isinstance(prom_cfg, dict):
        settings.prometheus_host = prom_cfg.get("host", settings.prometheus_host) or settings.prometheus_host
        settings.prometheus_port = _safe_int(prom_cfg.get("port"), settings.prometheus_port)

    metrics_cfg = cfg.get("metrics", {}) if isinstance(cfg, dict) else {}
    if isinstance(metrics_cfg, dict):
        settings.metrics_refresh_interval = _safe_float(
            metrics_cfg.get("refresh_interval_seconds"),
            settings.metrics_refresh_interval,
        )

    # CLI overrides have final say
    if getattr(args, "log_file", None):
        settings.log_enabled = True
        settings.log_path = args.log_file
    if getattr(args, "no_log_file", False):
        settings.log_enabled = False
    if getattr(args, "log_max_size_mb", None) is not None:
        settings.log_max_size_mb = args.log_max_size_mb
    if getattr(args, "log_max_backups", None) is not None:
        settings.log_max_backups = args.log_max_backups
    if getattr(args, "prometheus_host", None):
        settings.prometheus_host = args.prometheus_host
    if getattr(args, "prometheus_port", None) is not None:
        settings.prometheus_port = args.prometheus_port
    if getattr(args, "metrics_refresh_interval", None) is not None:
        settings.metrics_refresh_interval = args.metrics_refresh_interval

    if settings.metrics_refresh_interval <= 0:
        settings.metrics_refresh_interval = DEFAULT_METRICS_REFRESH_SEC

    return settings


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
    u8 responded;  // response progress: 0=none, 1=interim 1xx seen
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

// Find the next "HTTP/" occurrence starting at or after 'start'
static inline int find_next_http(char *buf, int len, int start)
{
    if (start < 0)
        start = 0;

    #pragma unroll
    for (int i = 0; i < MAX_HDR; i++) {
        int idx = start + i;
        if (idx + 5 >= len || idx + 5 >= MAX_HDR)
            break;
        if (buf[idx] == 'H' && buf[idx + 1] == 'T' && buf[idx + 2] == 'T' &&
            buf[idx + 3] == 'P' && buf[idx + 4] == '/')
            return idx;
    }
    return -1;
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

    // Classify method - if UNKNOWN, this might be body data or non-HTTP
    val.op = classify_method(val.hdr, copy);

    // For debugging: if we can't classify but it looks like it might be HTTP, keep it
    // This helps with boto3 which might send requests differently
    if (val.op == OP_UNKNOWN) {
        // Check if buffer contains "HTTP/1" or common S3 paths
        int might_be_http = 0;
        if (copy >= 7) {
            // Check for HTTP/1 or /bucket patterns
            if ((val.hdr[0] == '/' && val.hdr[1] == 's') ||  // /s3slower-boto3
                (val.hdr[0] == 'H' && val.hdr[1] == 'T' && val.hdr[2] == 'T' && val.hdr[3] == 'P') ||
                (val.hdr[0] == 'C' && val.hdr[1] == 'o' && val.hdr[2] == 'n'))  // Content-
                might_be_http = 1;
        }
        if (!might_be_http)
            return 0;  // Skip non-HTTP writes
        // Otherwise, let it through as OP_UNKNOWN to catch boto3 PUTs
    }

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

// Entry for OpenSSL SSL_read_ex (captures buffer pointer; length comes from 4th arg on exit)
int ssl_read_ex_enter(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    struct read_args_t a = {};
    a.id  = (u64)PT_REGS_PARM1(ctx);          // SSL*
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
    struct req_val_t *fallback_vp = NULL;
    struct conn_key_t key = {};
    key.pid = pid;
    key.id = ap->id;
    u64 found_seq = 0;
    u64 fallback_seq = 0;

    // Check last 10 sequence numbers (handles minor reordering)
    u64 current_seq = *seq_ptr;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (current_seq < i)
            break;
        key.seq = current_seq - i;
        struct req_val_t *candidate = active_reqs.lookup(&key);
        if (!candidate)
            continue;
        if (!fallback_vp) {
            fallback_vp = candidate;
            fallback_seq = key.seq;
        }
        if (candidate->op != OP_UNKNOWN) {
            vp = candidate;
            found_seq = key.seq;
            break;
        }
    }

    if (!vp) {
        vp = fallback_vp;
        found_seq = fallback_seq;
    }

    if (!vp) {
        read_args.delete(&tid);
        return 0;
    }

    key.seq = found_seq;

    // If this buffer contains both an interim 1xx and a final response, prefer the final code
    if (status_code >= 100 && status_code < 200) {
        int next_off = find_next_http(evt->resp_hdr, rcopy, 12);
        if (next_off >= 0) {
            int alt_status = extract_status_code(&evt->resp_hdr[next_off], rcopy - next_off);
            if (alt_status >= 200)
                status_code = alt_status;
        }
    }

    // If this is a 1xx response (e.g. 100 Continue), mark progress but keep waiting
    if (status_code >= 100 && status_code < 200) {
        vp->responded = 1;
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

// Exit for OpenSSL SSL_read_ex (bytes read provided via *readbytes, not return value)
int ssl_read_ex_exit(struct pt_regs *ctx)
{
    int rc = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct read_args_t *ap = read_args.lookup(&tid);
    if (!ap) {
        return 0;
    }

    if (rc <= 0) {
        read_args.delete(&tid);
        return 0;
    }

    u64 read_len = 0;
    void *readbytes_ptr = (void *)PT_REGS_PARM4(ctx);
    if (readbytes_ptr) {
        bpf_probe_read_user(&read_len, sizeof(read_len), readbytes_ptr);
    }
    if (read_len == 0) {
        read_args.delete(&tid);
        return 0;
    }

    int zero = 0;
    struct event_t *evt = tmp_evt.lookup(&zero);
    if (!evt) {
        read_args.delete(&tid);
        return 0;
    }

    u32 rcopy = (u32)read_len;
    if ((int)rcopy <= 0) {
        read_args.delete(&tid);
        return 0;
    }
    if (rcopy > MAX_HDR)
        rcopy = MAX_HDR;
    bpf_probe_read_user(&evt->resp_hdr, rcopy, ap->buf);

    if (!is_http_response(evt->resp_hdr, rcopy)) {
        read_args.delete(&tid);
        return 0;
    }

    int status_code = extract_status_code(evt->resp_hdr, rcopy);

    struct conn_id_t conn = {};
    conn.pid = pid;
    conn.id = ap->id;

    u64 *seq_ptr = conn_seqs.lookup(&conn);
    if (!seq_ptr) {
        read_args.delete(&tid);
        return 0;
    }

    struct req_val_t *vp = NULL;
    struct req_val_t *fallback_vp = NULL;
    struct conn_key_t key = {};
    key.pid = pid;
    key.id = ap->id;
    u64 found_seq = 0;
    u64 fallback_seq = 0;

    u64 current_seq = *seq_ptr;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (current_seq < i)
            break;
        key.seq = current_seq - i;
        struct req_val_t *candidate = active_reqs.lookup(&key);
        if (!candidate)
            continue;
        if (!fallback_vp) {
            fallback_vp = candidate;
            fallback_seq = key.seq;
        }
        if (candidate->op != OP_UNKNOWN) {
            vp = candidate;
            found_seq = key.seq;
            break;
        }
    }

    if (!vp) {
        vp = fallback_vp;
        found_seq = fallback_seq;
    }

    if (!vp) {
        read_args.delete(&tid);
        return 0;
    }

    key.seq = found_seq;

    if (status_code >= 100 && status_code < 200) {
        int next_off = find_next_http(evt->resp_hdr, rcopy, 12);
        if (next_off >= 0) {
            int alt_status = extract_status_code(&evt->resp_hdr[next_off], rcopy - next_off);
            if (alt_status >= 200)
                status_code = alt_status;
        }
    }

    if (status_code >= 100 && status_code < 200) {
        vp->responded = 1;
        read_args.delete(&tid);
        return 0;
    }

    evt->ts    = bpf_ktime_get_ns();
    evt->delta = evt->ts - vp->start_ns;
    evt->pid   = pid;
    evt->tid   = tid;
    evt->op    = vp->op;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    __builtin_memcpy(&evt->req_hdr, &vp->hdr, sizeof(evt->req_hdr));

    events.perf_submit(ctx, evt, sizeof(*evt));

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
    struct req_val_t *fallback_vp = NULL;
    struct conn_key_t key = {};
    key.pid = pid;
    key.id = ap->id;
    u64 found_seq = 0;
    u64 fallback_seq = 0;

    // Check last 10 sequence numbers (handles minor reordering)
    u64 current_seq = *seq_ptr;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (current_seq < i)
            break;
        key.seq = current_seq - i;
        struct req_val_t *candidate = active_reqs.lookup(&key);
        if (!candidate)
            continue;
        if (!fallback_vp) {
            fallback_vp = candidate;
            fallback_seq = key.seq;
        }
        if (candidate->op != OP_UNKNOWN) {
            vp = candidate;
            found_seq = key.seq;
            break;
        }
    }

    if (!vp) {
        vp = fallback_vp;
        found_seq = fallback_seq;
    }

    if (!vp) {
        http_read_args.delete(&tid);
        return 0;
    }

    key.seq = found_seq;

    if (status_code >= 100 && status_code < 200) {
        int next_off = find_next_http(evt->resp_hdr, rcopy, 12);
        if (next_off >= 0) {
            int alt_status = extract_status_code(&evt->resp_hdr[next_off], rcopy - next_off);
            if (alt_status >= 200)
                status_code = alt_status;
        }
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
    # SSL_read_ex (OpenSSL 1.1+/3.x)
    try:
        b.attach_uprobe(name=libpath, sym="SSL_read_ex",
                        fn_name="ssl_read_ex_enter", pid=pid)
        b.attach_uretprobe(name=libpath, sym="SSL_read_ex",
                           fn_name="ssl_read_ex_exit", pid=pid)
    except Exception:
        pass
    # SSL_write_ex uses same parameter order for SSL* / buf / len; reuse existing handler
    try:
        b.attach_uprobe(name=libpath, sym="SSL_write_ex",
                        fn_name="ssl_write_enter", pid=pid)
    except Exception:
        pass


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


def attach_http(b: BPF, quiet: bool = False) -> None:
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
        if not quiet:
            print("Attaching to plain HTTP via sys_sendto/sys_recvfrom")
    else:
        if not quiet:
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

    # Drop query string for bucket inference
    path_only = path.split("?", 1)[0] if path else ""

    # 1. Path-style: /bucket/key
    if path_only.startswith("/"):
        parts = path_only.split("/", 2)
        # ['', 'bucket', 'key...'] or ['', 'bucket']
        if len(parts) >= 2 and parts[1]:
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
PROM_EXTRA_LABELS: List[str] = []


def init_prometheus(host: str, port: int, extra_label_names: Optional[Iterable[str]] = None) -> None:
    global REQ_LATENCY, REQ_TOTAL, REQ_BYTES, RESP_TOTAL, PROM_EXTRA_LABELS

    if not HAVE_PROM:
        print(
            "ERROR: prometheus_client is not installed but --prometheus-port was used.\n"
            "Install it with: pip install prometheus_client",
            file=sys.stderr,
        )
        sys.exit(1)

    PROM_EXTRA_LABELS = sorted(set(extra_label_names or []))

    start_http_server(port, addr=host)

    # Label set: bucket, endpoint, method, pid, target, and any configured extras
    base_labels: List[str] = ["bucket", "endpoint", "method", "pid", "target"] + PROM_EXTRA_LABELS
    REQ_LATENCY = Histogram(
        "s3slower_request_latency_seconds",
        "S3-like request latency (request write -> first response read)",
        base_labels,
    )
    REQ_TOTAL = Counter(
        "s3slower_requests_total",
        "Total S3-like HTTP requests seen by s3slower",
        base_labels,
    )
    REQ_BYTES = Counter(
        "s3slower_request_bytes_total",
        "Total S3-like HTTP request bytes (Content-Length header)",
        base_labels,
    )
    RESP_TOTAL = Counter(
        "s3slower_responses_total",
        "Total S3-like HTTP responses seen by s3slower, by status code",
        base_labels + ["status"],
    )


def update_prometheus(bucket: str, endpoint: str, method: str,
                      latency_seconds: float, size_bytes: int, status_code: int,
                      pid_label: str, target_label: str,
                      extra_labels: Optional[Dict[str, str]] = None) -> None:
    if REQ_LATENCY is None or REQ_TOTAL is None or REQ_BYTES is None or RESP_TOTAL is None:
        return

    bucket_label = bucket or "unknown"
    endpoint_label = endpoint or "unknown"
    method_label = method or "UNK"
    pid_value = pid_label or "unknown"
    target_value = target_label or "unknown"

    labels: Dict[str, str] = {
        "bucket": bucket_label,
        "endpoint": endpoint_label,
        "method": method_label,
        "pid": pid_value,
        "target": target_value,
    }
    extra = extra_labels or {}
    for key in PROM_EXTRA_LABELS:
        labels[key] = extra.get(key, "")

    # Request-side metrics
    REQ_LATENCY.labels(**labels).observe(latency_seconds)
    REQ_TOTAL.labels(**labels).inc()
    if size_bytes > 0:
        REQ_BYTES.labels(**labels).inc(size_bytes)

    # Response code counter
    if 100 <= status_code <= 999:
        status_label = str(status_code)
    else:
        status_label = "unknown"

    resp_labels = dict(labels)
    resp_labels["status"] = status_label
    RESP_TOTAL.labels(**resp_labels).inc()


# ---------------------------------------------------------------------------
# Logging + metrics helpers
# ---------------------------------------------------------------------------


class MetricsAggregator:
    """
    Collect events and push them to Prometheus on a configurable cadence to reduce
    per-event overhead while keeping metrics up to date.
    """

    def __init__(self, refresh_interval: float) -> None:
        self.refresh_interval = max(refresh_interval, MIN_METRICS_REFRESH_INTERVAL)
        self._lock = threading.Lock()
        self._pending: List[Tuple[str, str, str, float, int, int, str, str, Dict[str, str]]] = []
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="s3slower-prom-flush", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=self.refresh_interval * 2)
        self.flush()

    def record(self, bucket: str, endpoint: str, method: str,
               latency_seconds: float, size_bytes: int, status_code: int,
               pid_label: str, target_label: str,
               extra_labels: Optional[Dict[str, str]] = None) -> None:
        with self._lock:
            self._pending.append((
                bucket, endpoint, method, latency_seconds, size_bytes,
                status_code, pid_label, target_label, extra_labels or {},
            ))

    def flush(self) -> None:
        with self._lock:
            batch = self._pending
            self._pending = []

        for bucket, endpoint, method, latency_seconds, size_bytes, status_code, pid_label, target_label, extras in batch:
            update_prometheus(bucket, endpoint, method, latency_seconds, size_bytes, status_code, pid_label, target_label, extras)

    def _run(self) -> None:
        while not self._stop_evt.wait(self.refresh_interval):
            self.flush()


def setup_transaction_logger(settings: RuntimeSettings) -> Optional[logging.Logger]:
    if not settings.log_enabled:
        return None

    if not settings.log_path:
        return None

    log_path = settings.log_path
    dirpath = os.path.dirname(os.path.abspath(log_path))
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    logger = logging.getLogger("s3slower.transactions")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers = []

    max_bytes = max(0, int(settings.log_max_size_mb)) * 1024 * 1024
    backup_count = max(0, int(settings.log_max_backups))

    if max_bytes > 0:
        handler: logging.Handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
    else:
        handler = logging.FileHandler(log_path, encoding="utf-8")

    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


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
# Tracing core
# ---------------------------------------------------------------------------


class TracerCore:
    """
    Core tracer that manages BPF programs, attachments, and event handling.
    """

    def __init__(
        self,
        settings: RuntimeSettings,
        *,
        host_filter: Optional[str],
        method_filter: Optional[Set[str]],
        min_lat_ms: float,
        include_unknown: bool,
        want_http: bool,
        want_tls: bool,
        enabled_tls_modes: Set[str],
        libssl_path: Optional[str],
        libgnutls_path: Optional[str],
        libnss_path: Optional[str],
        metrics_sink: Optional[MetricsAggregator],
        transaction_logger: Optional[logging.Logger],
        pid_filter: Optional[int] = None,
        restrict_to_attached: bool = False,
        prom_extra_label_keys: Optional[List[str]] = None,
        quiet_attach: bool = False,
    ) -> None:
        self.settings = settings
        self.host_filter = host_filter.lower() if host_filter else None
        self.method_filter = {m.upper() for m in method_filter} if method_filter else None
        self.min_lat_ms = min_lat_ms
        self.include_unknown = include_unknown
        self.want_http = want_http
        self.want_tls = want_tls
        self.enabled_tls_modes = enabled_tls_modes
        self.libssl_path = libssl_path
        self.libgnutls_path = libgnutls_path
        self.libnss_path = libnss_path
        self.metrics_sink = metrics_sink
        self.transaction_logger = transaction_logger
        self.pid_filter = pid_filter if pid_filter and pid_filter > 0 else None
        self.restrict_to_attached = restrict_to_attached
        self.prom_extra_label_keys = prom_extra_label_keys or []
        self.quiet_attach = quiet_attach
        self.global_tls = restrict_to_attached

        self.b = BPF(text=BPF_TEXT)
        self.stats: Dict[str, List[float]] = defaultdict(list)
        self.pid_targets: Dict[int, TargetMeta] = {}
        self.pid_modes: Dict[int, Set[str]] = defaultdict(set)
        self.http_attached = False
        self._perf_opened = False
        self._lock = threading.Lock()

    def _resolve_lib_path(self, mode: str) -> Optional[str]:
        """Resolve and cache the library path for a given TLS mode."""
        # Map mode to attribute name for caching
        mode_to_attr = {
            "openssl": "libssl_path",
            "gnutls": "libgnutls_path",
            "nss": "libnss_path",
        }

        attr_name = mode_to_attr.get(mode)
        if attr_name is None:
            return None

        # Return cached path if available
        cached = getattr(self, attr_name, None)
        if cached:
            return cached

        # Look up library and cache the result
        patterns = TLS_LIBRARY_PATTERNS.get(mode)
        if patterns:
            resolved = find_library(patterns)
            setattr(self, attr_name, resolved)
            return resolved

        return None

    def _register_pid_meta(self, pid: int, target_name: Optional[str],
                           prom_labels: Optional[Dict[str, str]]) -> None:
        meta = self.pid_targets.get(pid)
        if meta is None:
            meta = TargetMeta()
        if target_name:
            meta.target_name = target_name
        if prom_labels:
            merged = dict(meta.prom_labels)
            merged.update(prom_labels)
            meta.prom_labels = merged
        self.pid_targets[pid] = meta

    def ensure_http_attached(self) -> None:
        if not self.want_http or self.http_attached:
            return
        attach_http(self.b, quiet=self.quiet_attach)
        self.http_attached = True

    def start_tracing_for_pid(
        self,
        pid: int,
        mode: str,
        target_name: Optional[str] = None,
        prom_labels: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Attach tracing for a given PID and mode. Non-blocking.
        """
        normalized = (mode or "").lower()
        if normalized == "go_tls":
            # Placeholder: map go_tls to openssl for now (boringssl-based stacks)
            normalized = "openssl"

        if normalized == "http":
            if not self.want_http:
                print(f"Skipping http tracing for pid {pid}: HTTP tracing disabled")
                return
            self.ensure_http_attached()
            self._register_pid_meta(pid, target_name, prom_labels)
            return

        if not self.want_tls:
            print(f"Skipping TLS tracing for pid {pid}: TLS tracing disabled")
            return

        if normalized not in self.enabled_tls_modes:
            print(f"Ignoring mode '{mode}' for pid {pid}: not enabled")
            return

        with self._lock:
            if self.global_tls:
                if normalized in self.pid_modes.get(-1, set()):
                    # Already attached globally; just register metadata for this pid
                    self._register_pid_meta(pid, target_name, prom_labels)
                    return
            else:
                if normalized in self.pid_modes.get(pid, set()):
                    return

        libpath = self._resolve_lib_path(normalized)
        if not libpath:
            print(f"Could not find library for mode '{normalized}' (pid {pid})", file=sys.stderr)
            return

        attach_fn_map: Dict[str, Callable[[BPF, str, int], None]] = {
            "openssl": attach_openssl,
            "gnutls": attach_gnutls,
            "nss": attach_nss,
        }
        attach_fn = attach_fn_map.get(normalized)
        if attach_fn is None:
            print(f"Unknown tracing mode '{mode}' for pid {pid}", file=sys.stderr)
            return

        # For boto3, always use per-PID attachment to ensure proper SSL_write capture
        if target_name == "boto3" and pid > 0:
            pid_for_attach = pid
        else:
            pid_for_attach = -1 if self.global_tls else (pid if pid > 0 else -1)
        try:
            attach_fn(self.b, libpath, pid_for_attach)
            with self._lock:
                self.pid_modes[pid_for_attach].add(normalized)
                self._register_pid_meta(pid, target_name, prom_labels)
            if not self.quiet_attach:
                if pid_for_attach == -1:
                    print(f"Attached {normalized} tracing for all PIDs using {libpath}")
                else:
                    print(f"Attached {normalized} tracing for pid {pid} using {libpath}")
        except Exception as exc:  # pragma: no cover - runtime safety
            print(f"WARNING: failed to attach {normalized} for pid {pid}: {exc}", file=sys.stderr)

    def _open_perf_buffer(self) -> None:
        if self._perf_opened:
            return
        self.b["events"].open_perf_buffer(self._handle_event)
        self._perf_opened = True

    @staticmethod
    def _truncate_for_display(value: str, max_width: int) -> str:
        """Truncate a string for display, adding ellipsis if needed."""
        if len(value) > max_width:
            return value[: max_width - len(DISPLAY_TRUNCATE_SUFFIX)] + DISPLAY_TRUNCATE_SUFFIX
        return value

    def _passes_method_filter(self, method: str) -> bool:
        """Check if the HTTP method passes the configured filter."""
        if self.method_filter is None:
            return True

        if method:
            return method.upper() in self.method_filter
        else:
            return self.include_unknown

    def _passes_host_filter(self, host: str) -> bool:
        """Check if the host passes the configured filter."""
        if self.host_filter is None:
            return True

        if not host:
            return False

        return self.host_filter in host.lower()

    @staticmethod
    def _classify_method_bucket(method: str, path: str, op_fallback: str) -> str:
        """
        Classify the method for stats/metrics.

        Returns the appropriate bucket name (e.g., GET, PUT, MPU_CREATE, MPU_COMPLETE).
        """
        method_upper = method.upper() if method else ""
        method_bucket = method_upper if method_upper else op_fallback

        # Friendly MPU naming:
        #   POST ... ?uploads              -> MPU_CREATE
        #   POST ... ?uploadId=...         -> MPU_COMPLETE
        if method_upper == "POST" and path:
            if "uploads" in path and "uploadId=" not in path:
                method_bucket = "MPU_CREATE"
            elif "uploadId=" in path:
                method_bucket = "MPU_COMPLETE"

        return method_bucket

    def _handle_event(self, cpu: int, data: bytes, size: int) -> None:
        evt = ct.cast(data, ct.POINTER(Event)).contents

        # Early exit for PID filtering
        if self.pid_filter is not None and evt.pid != self.pid_filter:
            return

        if self.restrict_to_attached and evt.pid not in self.pid_targets:
            return

        # Parse HTTP request/response
        raw_req = bytes(evt.req_hdr)
        raw_resp = bytes(evt.resp_hdr)

        method, host, path, content_length = parse_http_request(raw_req)
        status_code = parse_http_response(raw_resp)

        # Filter unknown methods if not explicitly included
        if not method and not self.include_unknown:
            return

        op_name = OP_MAP.get(evt.op, "UNK")

        # Apply configured filters
        if not self._passes_method_filter(method):
            return

        if not self._passes_host_filter(host):
            return

        lat_ms = ns_to_ms(evt.delta)
        if lat_ms < self.min_lat_ms:
            return

        bucket, endpoint = parse_bucket_endpoint(host, path)
        method_bucket = self._classify_method_bucket(method, path, op_name)

        # Update local stats
        self.stats[method_bucket].append(lat_ms)
        self.stats["ALL"].append(lat_ms)

        meta = self.pid_targets.get(evt.pid)
        target_label = meta.target_name if meta else None
        prom_labels = dict(meta.prom_labels) if meta else {}
        pid_label = str(evt.pid)
        target_for_metrics = target_label or "unknown"

        # Update Prometheus (latency, size, response code)
        if self.metrics_sink is not None:
            self.metrics_sink.record(
                bucket, endpoint, method_bucket, lat_ms / 1000.0, content_length,
                status_code, pid_label, target_for_metrics, prom_labels,
            )
        else:
            update_prometheus(
                bucket, endpoint, method_bucket, lat_ms / 1000.0, content_length,
                status_code, pid_label, target_for_metrics, prom_labels,
            )

        # Per-event line
        tstr = time.strftime("%H:%M:%S", time.localtime())
        comm = evt.comm.decode("utf-8", "replace").rstrip("\x00")

        disp_bucket = self._truncate_for_display(bucket, DISPLAY_BUCKET_MAX_WIDTH)
        disp_endpoint = self._truncate_for_display(endpoint, DISPLAY_ENDPOINT_MAX_WIDTH)
        disp_path = path or ""
        status_str = str(status_code) if status_code > 0 else "-"
        target_disp = target_label or ""

        print("%-8s %-6d %-16s %-10s %-12s %-9.3f %-6s %-20s %-20s %s" %
              (tstr, evt.pid, comm, target_disp, method_bucket, lat_ms,
               status_str, disp_bucket, disp_endpoint, disp_path))

        # Structured log for correlation with traffic generators
        if self.transaction_logger is not None:
            try:
                self.transaction_logger.info(
                    f"{evt.ts}\t{tstr}\t{evt.pid}\t{comm}\t{target_disp}\t{method_bucket}\t"
                    f"{lat_ms:.3f}\t{status_str}\t{bucket}\t{endpoint}\t{path or ''}"
                )
            except Exception:
                # Logging failures should not break tracing
                pass

    def run(self, stop_event: threading.Event) -> None:
        self._open_perf_buffer()
        poll_counter = 0
        while not stop_event.is_set():
            if poll_counter % STDIN_FLUSH_INTERVAL == 0:
                flush_stdin()
            poll_counter += 1
            self.b.perf_buffer_poll(timeout=PERF_BUFFER_POLL_TIMEOUT_MS)
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="S3 latency tracer using TLS libraries and plain HTTP (s3slower-style)")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH,
                        help=f"Path to YAML config file (default: {DEFAULT_CONFIG_PATH})")
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

    parser.add_argument("--prometheus-host", help="Interface/IP for Prometheus /metrics listener")
    parser.add_argument("--prometheus-port", type=int,
                        help="Expose Prometheus /metrics on this port (overrides config)")
    parser.add_argument("--metrics-refresh-interval", type=float,
                        help="Seconds between Prometheus metric flushes (overrides config)")
    parser.add_argument("--log-file",
                        help="Append raw per-request events as TSV to this file (overrides config)")
    parser.add_argument("--log-max-size-mb", type=int,
                        help="Max log file size in MB before rotation (overrides config)")
    parser.add_argument("--log-max-backups", type=int,
                        help="How many rotated log files to keep (overrides config)")
    parser.add_argument("--no-log-file", action="store_true",
                        help="Disable transaction file logging even if config enables it")
    parser.add_argument(
        "--watch-config",
        nargs="?",
        const=DEFAULT_TARGETS_PATH,
        help=(
            "Enable PID auto-attach using a targets YAML file "
            f"(default path: {DEFAULT_TARGETS_PATH})"
        ),
    )

    args = parser.parse_args()

    if args.no_log_file and args.log_file:
        print("ERROR: --no-log-file cannot be combined with --log-file", file=sys.stderr)
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

    config_from_file = load_config_file(args.config)
    if os.path.isfile(args.config):
        print(f"Loaded config from {args.config}")

    settings = build_runtime_settings(args, config_from_file)

    transaction_logger: Optional[logging.Logger] = None
    if settings.log_enabled:
        try:
            transaction_logger = setup_transaction_logger(settings)
            if transaction_logger is not None:
                print(
                    f"Logging raw events to {settings.log_path} "
                    f"(max {settings.log_max_size_mb} MB, backups {settings.log_max_backups})"
                )
        except OSError as e:
            print(f"ERROR: could not open log file {settings.log_path}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        transaction_logger = None

    # Determine which tracing modes are enabled
    want_http = not args.no_http
    want_tls = not args.http_only
    tls_modes: Set[str] = set()
    auto_tls = False
    if want_tls:
        if args.openssl:
            tls_modes.add("openssl")
        if args.gnutls:
            tls_modes.add("gnutls")
        if args.nss:
            tls_modes.add("nss")
        if not tls_modes:
            auto_tls = True
            tls_modes = {"openssl", "gnutls", "nss"}
            print("Auto TLS mode: attempting OpenSSL, GnuTLS, and NSS (where present)")

    watch_mode = False
    targets: List["TargetConfig"] = []
    prom_extra_label_keys: List[str] = []
    if args.watch_config:
        targets = load_targets(args.watch_config)
        prom_extra_label_keys = collect_extra_label_keys(targets)
        watch_mode = True
        print(f"Loaded auto-attach targets from {args.watch_config} ({len(targets)} entries)")

    # Resolve library paths up-front to preserve legacy strictness when the user
    # explicitly requests a TLS library.
    libssl_path = args.libssl
    libgnutls_path = args.libgnutls
    libnss_path = args.libnss

    if want_tls and "openssl" in tls_modes:
        libssl_path = libssl_path or find_library(["libssl.so", "libssl.so.*"])
        if not libssl_path:
            if not (auto_tls or watch_mode):
                print("Could not find libssl.so; use --libssl to specify path", file=sys.stderr)
                sys.exit(1)
    if want_tls and "gnutls" in tls_modes:
        libgnutls_path = libgnutls_path or find_library(["libgnutls.so", "libgnutls.so.*"])
        if not libgnutls_path:
            if not (auto_tls or watch_mode):
                print("Could not find libgnutls.so; use --libgnutls to specify path", file=sys.stderr)
                sys.exit(1)
    if want_tls and "nss" in tls_modes:
        libnss_path = libnss_path or find_library(["libnspr4.so", "libnspr4.so.*"])
        if not libnss_path:
            if not (auto_tls or watch_mode):
                print("Could not find libnspr4.so; use --libnss to specify path", file=sys.stderr)
                sys.exit(1)

    metrics_sink: Optional[MetricsAggregator] = None

    if settings.prometheus_port > 0:
        init_prometheus(settings.prometheus_host, settings.prometheus_port, prom_extra_label_keys)
        metrics_sink = MetricsAggregator(settings.metrics_refresh_interval)
        metrics_sink.start()
        print(
            f"Prometheus /metrics listening on {settings.prometheus_host}:{settings.prometheus_port} "
            f"(refresh every {settings.metrics_refresh_interval}s)"
        )

    # Setup terminal to prevent control character interference
    old_terminal_settings = setup_terminal()

    method_filter = {m.upper() for m in args.method} if args.method else None

    tracer = TracerCore(
        settings,
        host_filter=args.host_substr,
        method_filter=method_filter,
        min_lat_ms=args.min_lat_ms,
        include_unknown=args.include_unknown,
        want_http=want_http,
        want_tls=want_tls,
        enabled_tls_modes=tls_modes,
        libssl_path=libssl_path,
        libgnutls_path=libgnutls_path,
        libnss_path=libnss_path,
        metrics_sink=metrics_sink,
        transaction_logger=transaction_logger,
        pid_filter=args.pid if args.pid else None,
        restrict_to_attached=watch_mode and not args.pid,
        prom_extra_label_keys=prom_extra_label_keys,
        quiet_attach=True,
    )

    # Perform manual attachments if requested (legacy/manual mode)
    if not watch_mode or args.pid:
        if want_http:
            tracer.ensure_http_attached()
        if want_tls:
            pid_for_attach = args.pid or -1
            for mode in tls_modes:
                tracer.start_tracing_for_pid(pid_for_attach, mode)

    # In watch mode we still want HTTP probes available so matched plaintext PIDs
    # are visible, while restrict_to_attached keeps unrelated traffic hidden.
    if watch_mode and want_http:
        tracer.ensure_http_attached()

    # Header (include target label)
    print("%-8s %-6s %-16s %-10s %-12s %-9s %-6s %-20s %-20s %s" %
          ("TIME", "PID", "COMM", "TARGET", "OP", "LAT(ms)", "STATUS", "BUCKET", "ENDPOINT", "PATH"))

    stop_event = threading.Event()

    def handle_sigint(signum, frame) -> None:  # type: ignore[override]
        stop_event.set()
        restore_terminal(old_terminal_settings)

    signal.signal(signal.SIGINT, handle_sigint)

    watcher: Optional["TargetWatcher"] = None
    if watch_mode:
        # Track attachment counts per target to reduce verbosity for frequently spawning processes
        attach_counts: Dict[str, int] = defaultdict(int)

        def _attach_target(pid: int, comm: str, target: "TargetConfig") -> None:
            attach_counts[target.id] += 1
            # Only print first 3 attachments per target type to reduce noise
            if attach_counts[target.id] <= 3:
                print(f"[watcher] matched target '{target.id}' for pid={pid} comm='{comm}', attaching...")
            elif attach_counts[target.id] == 4:
                print(f"[watcher] (suppressing further attachment messages for '{target.id}')")

            tracer.start_tracing_for_pid(pid, target.mode, target.id, target.prom_labels)
            # For curl and boto3, ensure both HTTP and OpenSSL modes are attached to capture all traffic
            if target.id in ["curl", "boto3"]:
                tracer.ensure_http_attached()
            elif target.mode.lower() == "http":
                tracer.ensure_http_attached()

        watcher = TargetWatcher(targets, _attach_target)
        watcher.start()

    try:
        tracer.run(stop_event)
    finally:
        stop_event.set()
        restore_terminal(old_terminal_settings)
        if watcher is not None:
            watcher.stop()
        if metrics_sink is not None:
            metrics_sink.stop()
        print_summary(tracer.stats)
        if transaction_logger is not None:
            try:
                for handler in transaction_logger.handlers:
                    handler.flush()
                    handler.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
