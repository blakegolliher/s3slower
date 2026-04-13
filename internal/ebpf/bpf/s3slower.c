// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// S3Slower BPF program for tracing S3 client latency

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Data capture sizes
#define MAX_DATA_SIZE 1024
#define MAX_RESP_SIZE 768
#define HTTP_CHECK_SIZE 8
#define TASK_COMM_LEN 16
// Minimum response bytes to create an event. Reads smaller than this
// (e.g. 1-byte peek for HTTP/1.1 100 Continue) are skipped so the
// req_map entry survives until the actual response is read.
#define MIN_RESP_SIZE 16

// Client type constants
#define CLIENT_UNKNOWN  0
#define CLIENT_WARP     1
#define CLIENT_ELBENCHO 2
#define CLIENT_BOTO3    3
#define CLIENT_S3CMD    4
#define CLIENT_AWSCLI   5

// Event structure sent to userspace
struct event_t {
    __u64 timestamp_us;
    __u64 latency_us;
    __u32 pid;
    __u32 tid;
    __u32 fd;
    char comm[TASK_COMM_LEN];
    __u32 req_size;
    __u32 resp_size;
    __u32 actual_resp_bytes;
    __u8 is_partial;
    __u8 client_type;
    __u8 _pad[2];
    char data[MAX_DATA_SIZE];
    char resp_data[MAX_RESP_SIZE];
};

// Request tracking structure
struct req_info_t {
    __u64 start_time;
    __u32 req_size;
    __u32 fd;
    __u8 client_type;
    char comm[TASK_COMM_LEN];
    char data[MAX_DATA_SIZE];
};

// Read args source constants - prevents kretprobe/uretprobe interference.
// When both kprobes and uprobes are attached, kretprobe_sys_read fires
// INSIDE SSL_read (before uretprobe_ssl_read) and would steal the
// read_args_map entry meant for the uretprobe.  The source tag lets
// each return probe ignore entries it didn't create.
#define READ_SRC_KPROBE  0
#define READ_SRC_UPROBE  1

// Saves read() arguments from entry probe for use in return probe.
struct read_args_t {
    __u64 buf_ptr;
    __u64 readbytes_ptr; // SSL_read_ex: pointer to size_t output param
    __u32 fd;
    __u8  source;   // READ_SRC_KPROBE or READ_SRC_UPROBE
    __u8  _pad[3];
};

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

// Request tracking map (key: pid<<32|fd)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct req_info_t);
} req_map SEC(".maps");

// Event output ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Per-CPU scratch space for event_t construction.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event_t);
} event_heap SEC(".maps");

// Per-CPU scratch space for req_info_t construction.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct req_info_t);
} req_heap SEC(".maps");

// Saves buffer pointers from read entry probes for return probes.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct read_args_t);
} read_args_map SEC(".maps");

// Exec notification for dynamic Go TLS binary discovery.
// Sends PID to userspace on every execve so it can check
// whether the new binary uses crypto/tls and attach uprobes.
struct exec_event_t {
    __u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} exec_events SEC(".maps");

// Config keys
#define CONFIG_TARGET_PID 0
#define CONFIG_MIN_LATENCY_US 1

// Check if we should filter this PID
static __always_inline int should_filter_pid(__u32 pid) {
    __u32 key = CONFIG_TARGET_PID;
    __u64 *target_pid = bpf_map_lookup_elem(&config_map, &key);
    if (target_pid && *target_pid != 0 && *target_pid != pid) {
        return 1;
    }
    return 0;
}

// Check if latency meets minimum threshold
static __always_inline int should_filter_latency(__u64 latency_us) {
    __u32 key = CONFIG_MIN_LATENCY_US;
    __u64 *min_latency = bpf_map_lookup_elem(&config_map, &key);
    if (min_latency && latency_us < *min_latency) {
        return 1;
    }
    return 0;
}

// Detect client type from comm name
static __always_inline __u8 detect_client_type(const char *comm) {
    if (comm[0] == 'w' && comm[1] == 'a' && comm[2] == 'r' && comm[3] == 'p') {
        return CLIENT_WARP;
    }
    if (comm[0] == 'e' && comm[1] == 'l' && comm[2] == 'b') {
        return CLIENT_ELBENCHO;
    }
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't') {
        return CLIENT_BOTO3;
    }
    if (comm[0] == 's' && comm[1] == '3' && comm[2] == 'c') {
        return CLIENT_S3CMD;
    }
    if (comm[0] == 'a' && comm[1] == 'w' && comm[2] == 's') {
        return CLIENT_AWSCLI;
    }
    if (comm[0] == 'm' && comm[1] == 'c') {
        return CLIENT_WARP;  // MinIO client
    }
    return CLIENT_UNKNOWN;
}

// Check if data looks like HTTP (starts with valid method or response)
static __always_inline int is_http_data(const char *data, __u32 size) {
    if (size < 4) return 0;

    // Check for HTTP methods
    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') return 1;
    if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') return 1;
    if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') return 1;
    if (data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E') return 1;
    if (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') return 1;

    // Check for HTTP response
    if (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P') return 1;

    return 0;
}

// ========== Write/Send Entry Probes ==========

SEC("kprobe/sys_write")
int kprobe_sys_write(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (should_filter_pid(pid))
        return 0;

    int fd = (int)PT_REGS_PARM1(ctx);
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    __u32 count = (size_t)PT_REGS_PARM3(ctx);

    if (fd < 3 || count == 0)
        return 0;

    // Quick HTTP check on the stack (8 bytes, well within 512-byte limit)
    char check[HTTP_CHECK_SIZE] = {};
    if (bpf_probe_read_user(check, sizeof(check), buf) < 0)
        return 0;
    if (!is_http_data(check, HTTP_CHECK_SIZE))
        return 0;

    // Build req_info in per-CPU scratch space (too large for stack)
    __u32 zero = 0;
    struct req_info_t *req = bpf_map_lookup_elem(&req_heap, &zero);
    if (!req)
        return 0;

    req->start_time = bpf_ktime_get_ns() / 1000;
    req->req_size = count;
    req->fd = fd;
    bpf_get_current_comm(&req->comm, sizeof(req->comm));
    req->client_type = detect_client_type(req->comm);
    bpf_probe_read_user(req->data, MAX_DATA_SIZE, buf);

    __u64 key = ((__u64)pid << 32) | (__u32)fd;
    bpf_map_update_elem(&req_map, &key, req, BPF_ANY);

    return 0;
}

// sendto(int fd, void *buff, size_t len, unsigned flags, ...) - same first 3 args as write
SEC("kprobe/sys_sendto")
int kprobe_sys_sendto(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (should_filter_pid(pid))
        return 0;

    int fd = (int)PT_REGS_PARM1(ctx);
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    __u32 count = (size_t)PT_REGS_PARM3(ctx);

    if (fd < 3 || count == 0)
        return 0;

    char check[HTTP_CHECK_SIZE] = {};
    if (bpf_probe_read_user(check, sizeof(check), buf) < 0)
        return 0;
    if (!is_http_data(check, HTTP_CHECK_SIZE))
        return 0;

    __u32 zero = 0;
    struct req_info_t *req = bpf_map_lookup_elem(&req_heap, &zero);
    if (!req)
        return 0;

    req->start_time = bpf_ktime_get_ns() / 1000;
    req->req_size = count;
    req->fd = fd;
    bpf_get_current_comm(&req->comm, sizeof(req->comm));
    req->client_type = detect_client_type(req->comm);
    bpf_probe_read_user(req->data, MAX_DATA_SIZE, buf);

    __u64 key = ((__u64)pid << 32) | (__u32)fd;
    bpf_map_update_elem(&req_map, &key, req, BPF_ANY);

    return 0;
}

SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    if (num <= 0)
        return 0;

    char check[HTTP_CHECK_SIZE] = {};
    if (bpf_probe_read_user(check, sizeof(check), buf) < 0)
        return 0;
    if (!is_http_data(check, HTTP_CHECK_SIZE))
        return 0;

    __u32 zero = 0;
    struct req_info_t *req = bpf_map_lookup_elem(&req_heap, &zero);
    if (!req)
        return 0;

    req->start_time = bpf_ktime_get_ns() / 1000;
    req->req_size = num;
    req->fd = tid;
    bpf_get_current_comm(&req->comm, sizeof(req->comm));
    req->client_type = detect_client_type(req->comm);
    bpf_probe_read_user(req->data, MAX_DATA_SIZE, buf);

    __u64 key = ((__u64)pid << 32) | tid;
    bpf_map_update_elem(&req_map, &key, req, BPF_ANY);

    return 0;
}

SEC("uprobe/gnutls_record_send")
int uprobe_gnutls_send(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    const char *data = (const char *)PT_REGS_PARM2(ctx);
    size_t data_size = (size_t)PT_REGS_PARM3(ctx);
    if (data_size == 0)
        return 0;

    char check[HTTP_CHECK_SIZE] = {};
    if (bpf_probe_read_user(check, sizeof(check), data) < 0)
        return 0;
    if (!is_http_data(check, HTTP_CHECK_SIZE))
        return 0;

    __u32 zero = 0;
    struct req_info_t *req = bpf_map_lookup_elem(&req_heap, &zero);
    if (!req)
        return 0;

    req->start_time = bpf_ktime_get_ns() / 1000;
    req->req_size = data_size;
    req->fd = tid;
    bpf_get_current_comm(&req->comm, sizeof(req->comm));
    req->client_type = detect_client_type(req->comm);
    bpf_probe_read_user(req->data, MAX_DATA_SIZE, data);

    __u64 key = ((__u64)pid << 32) | tid;
    bpf_map_update_elem(&req_map, &key, req, BPF_ANY);

    return 0;
}

SEC("uprobe/PR_Write")
int uprobe_pr_write(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    int amount = (int)PT_REGS_PARM3(ctx);
    if (amount <= 0)
        return 0;

    char check[HTTP_CHECK_SIZE] = {};
    if (bpf_probe_read_user(check, sizeof(check), buf) < 0)
        return 0;
    if (!is_http_data(check, HTTP_CHECK_SIZE))
        return 0;

    __u32 zero = 0;
    struct req_info_t *req = bpf_map_lookup_elem(&req_heap, &zero);
    if (!req)
        return 0;

    req->start_time = bpf_ktime_get_ns() / 1000;
    req->req_size = amount;
    req->fd = tid;
    bpf_get_current_comm(&req->comm, sizeof(req->comm));
    req->client_type = detect_client_type(req->comm);
    bpf_probe_read_user(req->data, MAX_DATA_SIZE, buf);

    __u64 key = ((__u64)pid << 32) | tid;
    bpf_map_update_elem(&req_map, &key, req, BPF_ANY);

    return 0;
}

// ========== Read Entry Probes (save buffer pointer for return probes) ==========

SEC("kprobe/sys_read")
int kprobe_sys_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_filter_pid(pid))
        return 0;

    int fd = (int)PT_REGS_PARM1(ctx);
    if (fd < 3)
        return 0;

    // Only save args if there's a pending HTTP request for this PID+FD
    __u64 req_key = ((__u64)pid << 32) | (__u32)fd;
    if (!bpf_map_lookup_elem(&req_map, &req_key))
        return 0;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);

    struct read_args_t args = {};
    args.buf_ptr = (__u64)buf;
    args.fd = (__u32)fd;
    args.source = READ_SRC_KPROBE;
    bpf_map_update_elem(&read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// recvfrom(int fd, void *ubuf, size_t size, unsigned flags, ...) - same first 3 args as read
SEC("kprobe/sys_recvfrom")
int kprobe_sys_recvfrom(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_filter_pid(pid))
        return 0;

    int fd = (int)PT_REGS_PARM1(ctx);
    if (fd < 3)
        return 0;

    __u64 req_key = ((__u64)pid << 32) | (__u32)fd;
    if (!bpf_map_lookup_elem(&req_map, &req_key))
        return 0;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);

    struct read_args_t args = {};
    args.buf_ptr = (__u64)buf;
    args.fd = (__u32)fd;
    args.source = READ_SRC_KPROBE;
    bpf_map_update_elem(&read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    __u64 req_key = ((__u64)pid << 32) | tid;
    if (!bpf_map_lookup_elem(&req_map, &req_key))
        return 0;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);

    struct read_args_t args = {};
    args.buf_ptr = (__u64)buf;
    args.source = READ_SRC_UPROBE;
    bpf_map_update_elem(&read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
// Unlike SSL_read, the byte count is in *readbytes, not the return value.
SEC("uprobe/SSL_read_ex")
int uprobe_ssl_read_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    __u64 req_key = ((__u64)pid << 32) | tid;
    if (!bpf_map_lookup_elem(&req_map, &req_key))
        return 0;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    const size_t *readbytes = (const size_t *)PT_REGS_PARM4(ctx);

    struct read_args_t args = {};
    args.buf_ptr = (__u64)buf;
    args.readbytes_ptr = (__u64)readbytes;
    args.source = READ_SRC_UPROBE;
    bpf_map_update_elem(&read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/gnutls_record_recv")
int uprobe_gnutls_recv(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    __u64 req_key = ((__u64)pid << 32) | tid;
    if (!bpf_map_lookup_elem(&req_map, &req_key))
        return 0;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);

    struct read_args_t args = {};
    args.buf_ptr = (__u64)buf;
    args.source = READ_SRC_UPROBE;
    bpf_map_update_elem(&read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/PR_Read")
int uprobe_pr_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    __u64 req_key = ((__u64)pid << 32) | tid;
    if (!bpf_map_lookup_elem(&req_map, &req_key))
        return 0;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);

    struct read_args_t args = {};
    args.buf_ptr = (__u64)buf;
    args.source = READ_SRC_UPROBE;
    bpf_map_update_elem(&read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// ========== Read/Recv Return Probes ==========

SEC("kretprobe/sys_read")
int kretprobe_sys_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_filter_pid(pid))
        return 0;

    ssize_t ret = (ssize_t)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    // Look up saved read arguments from entry probe
    struct read_args_t *args = bpf_map_lookup_elem(&read_args_map, &pid_tgid);
    if (!args)
        return 0;

    // Only consume entries created by kprobe_sys_read.
    // Uprobe entries use the same map+key; touching them here would
    // prevent the matching uretprobe from ever seeing them.
    if (args->source != READ_SRC_KPROBE)
        return 0;

    __u64 buf_ptr = args->buf_ptr;
    __u32 fd = args->fd;
    bpf_map_delete_elem(&read_args_map, &pid_tgid);

    __u64 now = bpf_ktime_get_ns() / 1000;

    // Look up the pending request (kprobes key by real FD, not TID)
    __u64 req_key = ((__u64)pid << 32) | fd;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &req_key);
    if (!req)
        return 0;

    __u64 latency_us = now - req->start_time;
    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    __u32 zero = 0;
    struct event_t *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    event->timestamp_us = now;
    event->latency_us = latency_us;
    event->pid = pid;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->fd = fd;
    __builtin_memcpy(event->comm, req->comm, TASK_COMM_LEN);
    event->req_size = req->req_size;
    event->resp_size = (__u32)ret;
    event->actual_resp_bytes = (__u32)ret;
    event->is_partial = 0;
    event->client_type = req->client_type;
    __builtin_memcpy(event->data, req->data, MAX_DATA_SIZE);

    __builtin_memset(event->resp_data, 0, MAX_RESP_SIZE);
    bpf_probe_read_user(event->resp_data, MAX_RESP_SIZE, (const char *)buf_ptr);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&req_map, &req_key);

    return 0;
}

SEC("kretprobe/sys_recvfrom")
int kretprobe_sys_recvfrom(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_filter_pid(pid))
        return 0;

    ssize_t ret = (ssize_t)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    struct read_args_t *args = bpf_map_lookup_elem(&read_args_map, &pid_tgid);
    if (!args)
        return 0;

    if (args->source != READ_SRC_KPROBE)
        return 0;

    __u64 buf_ptr = args->buf_ptr;
    __u32 fd = args->fd;
    bpf_map_delete_elem(&read_args_map, &pid_tgid);

    __u64 now = bpf_ktime_get_ns() / 1000;

    __u64 req_key = ((__u64)pid << 32) | fd;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &req_key);
    if (!req)
        return 0;

    __u64 latency_us = now - req->start_time;
    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    __u32 zero = 0;
    struct event_t *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    event->timestamp_us = now;
    event->latency_us = latency_us;
    event->pid = pid;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->fd = fd;
    __builtin_memcpy(event->comm, req->comm, TASK_COMM_LEN);
    event->req_size = req->req_size;
    event->resp_size = (__u32)ret;
    event->actual_resp_bytes = (__u32)ret;
    event->is_partial = 0;
    event->client_type = req->client_type;
    __builtin_memcpy(event->data, req->data, MAX_DATA_SIZE);

    __builtin_memset(event->resp_data, 0, MAX_RESP_SIZE);
    bpf_probe_read_user(event->resp_data, MAX_RESP_SIZE, (const char *)buf_ptr);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&req_map, &req_key);

    return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    struct read_args_t *args = bpf_map_lookup_elem(&read_args_map, &pid_tgid);
    if (!args)
        return 0;

    // Only consume entries created by uprobe read probes
    if (args->source != READ_SRC_UPROBE)
        return 0;

    __u64 buf_ptr = args->buf_ptr;
    bpf_map_delete_elem(&read_args_map, &pid_tgid);

    // Skip tiny reads (e.g. 1-byte peek for 100 Continue) - keep req_map
    // entry so the next read captures the actual response.
    if (ret < MIN_RESP_SIZE)
        return 0;

    __u64 now = bpf_ktime_get_ns() / 1000;

    __u64 req_key = ((__u64)pid << 32) | tid;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &req_key);
    if (!req)
        return 0;

    __u64 latency_us = now - req->start_time;
    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    __u32 zero = 0;
    struct event_t *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    event->timestamp_us = now;
    event->latency_us = latency_us;
    event->pid = pid;
    event->tid = tid;
    event->fd = req->fd;
    __builtin_memcpy(event->comm, req->comm, TASK_COMM_LEN);
    event->req_size = req->req_size;
    event->resp_size = ret;
    event->actual_resp_bytes = ret;
    event->is_partial = 0;
    event->client_type = req->client_type;
    __builtin_memcpy(event->data, req->data, MAX_DATA_SIZE);

    __builtin_memset(event->resp_data, 0, MAX_RESP_SIZE);
    bpf_probe_read_user(event->resp_data, MAX_RESP_SIZE, (const char *)buf_ptr);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&req_map, &req_key);

    return 0;
}

// SSL_read_ex returns 1 on success; actual byte count is in *readbytes (PARM4).
SEC("uretprobe/SSL_read_ex")
int uretprobe_ssl_read_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    struct read_args_t *args = bpf_map_lookup_elem(&read_args_map, &pid_tgid);
    if (!args)
        return 0;

    if (args->source != READ_SRC_UPROBE)
        return 0;

    __u64 buf_ptr = args->buf_ptr;
    __u64 readbytes_ptr = args->readbytes_ptr;
    bpf_map_delete_elem(&read_args_map, &pid_tgid);

    // Read actual byte count from *readbytes
    __u64 actual_bytes = 0;
    if (readbytes_ptr) {
        bpf_probe_read_user(&actual_bytes, sizeof(actual_bytes), (const void *)readbytes_ptr);
    }

    // Skip tiny reads (e.g. 1-byte peek for 100 Continue) - keep req_map
    // entry so the next read captures the actual response.
    if (actual_bytes < MIN_RESP_SIZE)
        return 0;

    __u64 now = bpf_ktime_get_ns() / 1000;

    __u64 req_key = ((__u64)pid << 32) | tid;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &req_key);
    if (!req)
        return 0;

    __u64 latency_us = now - req->start_time;
    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    __u32 zero = 0;
    struct event_t *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    event->timestamp_us = now;
    event->latency_us = latency_us;
    event->pid = pid;
    event->tid = tid;
    event->fd = req->fd;
    __builtin_memcpy(event->comm, req->comm, TASK_COMM_LEN);
    event->req_size = req->req_size;
    event->resp_size = (__u32)actual_bytes;
    event->actual_resp_bytes = (__u32)actual_bytes;
    event->is_partial = 0;
    event->client_type = req->client_type;
    __builtin_memcpy(event->data, req->data, MAX_DATA_SIZE);

    __builtin_memset(event->resp_data, 0, MAX_RESP_SIZE);
    bpf_probe_read_user(event->resp_data, MAX_RESP_SIZE, (const char *)buf_ptr);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&req_map, &req_key);

    return 0;
}

SEC("uretprobe/gnutls_record_recv")
int uretprobe_gnutls_recv(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    ssize_t ret = (ssize_t)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    struct read_args_t *args = bpf_map_lookup_elem(&read_args_map, &pid_tgid);
    if (!args)
        return 0;

    // Only consume entries created by uprobe read probes
    if (args->source != READ_SRC_UPROBE)
        return 0;

    __u64 buf_ptr = args->buf_ptr;
    bpf_map_delete_elem(&read_args_map, &pid_tgid);

    __u64 now = bpf_ktime_get_ns() / 1000;

    __u64 req_key = ((__u64)pid << 32) | tid;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &req_key);
    if (!req)
        return 0;

    __u64 latency_us = now - req->start_time;
    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    __u32 zero = 0;
    struct event_t *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    event->timestamp_us = now;
    event->latency_us = latency_us;
    event->pid = pid;
    event->tid = tid;
    event->fd = req->fd;
    __builtin_memcpy(event->comm, req->comm, TASK_COMM_LEN);
    event->req_size = req->req_size;
    event->resp_size = (__u32)ret;
    event->actual_resp_bytes = (__u32)ret;
    event->is_partial = 0;
    event->client_type = req->client_type;
    __builtin_memcpy(event->data, req->data, MAX_DATA_SIZE);

    __builtin_memset(event->resp_data, 0, MAX_RESP_SIZE);
    bpf_probe_read_user(event->resp_data, MAX_RESP_SIZE, (const char *)buf_ptr);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&req_map, &req_key);

    return 0;
}

SEC("uretprobe/PR_Read")
int uretprobe_pr_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;

    if (should_filter_pid(pid))
        return 0;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    struct read_args_t *args = bpf_map_lookup_elem(&read_args_map, &pid_tgid);
    if (!args)
        return 0;

    // Only consume entries created by uprobe read probes
    if (args->source != READ_SRC_UPROBE)
        return 0;

    __u64 buf_ptr = args->buf_ptr;
    bpf_map_delete_elem(&read_args_map, &pid_tgid);

    __u64 now = bpf_ktime_get_ns() / 1000;

    __u64 req_key = ((__u64)pid << 32) | tid;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &req_key);
    if (!req)
        return 0;

    __u64 latency_us = now - req->start_time;
    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    __u32 zero = 0;
    struct event_t *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    event->timestamp_us = now;
    event->latency_us = latency_us;
    event->pid = pid;
    event->tid = tid;
    event->fd = req->fd;
    __builtin_memcpy(event->comm, req->comm, TASK_COMM_LEN);
    event->req_size = req->req_size;
    event->resp_size = ret;
    event->actual_resp_bytes = ret;
    event->is_partial = 0;
    event->client_type = req->client_type;
    __builtin_memcpy(event->data, req->data, MAX_DATA_SIZE);

    __builtin_memset(event->resp_data, 0, MAX_RESP_SIZE);
    bpf_probe_read_user(event->resp_data, MAX_RESP_SIZE, (const char *)buf_ptr);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&req_map, &req_key);

    return 0;
}

// ========== Go crypto/tls Probes ==========
// Go 1.17+ uses a register-based calling convention (ABIInternal) that
// differs from the C ABI.  The standard PT_REGS_PARMx macros do NOT apply.
//
//   func (c *Conn) Write(b []byte) (int, error)
//   func (c *Conn) Read(b []byte)  (int, error)
//
//   RAX = receiver (*Conn)
//   RBX = b.ptr  (ctx->bx)
//   RCX = b.len  (ctx->cx)
//   Return: RAX = n  (PT_REGS_RC / ctx->ax)
//
// Go net/http uses separate goroutines (and OS threads) for writing
// and reading on the same connection.  Keying req_map by TID would
// fail because Write and Read run on different threads.  Instead we
// key by the *Conn pointer (RAX), which is the same for both.

SEC("uprobe/go_tls_write")
int uprobe_go_tls_write(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (should_filter_pid(pid))
        return 0;

    // Go ABI: RAX = *Conn, RBX = buf pointer, RCX = buf length
    __u32 conn_id = (__u32)ctx->ax;  // Lower 32 bits of Conn pointer
    const char *buf = (const char *)ctx->bx;
    int num = (int)ctx->cx;
    if (num <= 0)
        return 0;

    char check[HTTP_CHECK_SIZE] = {};
    if (bpf_probe_read_user(check, sizeof(check), buf) < 0)
        return 0;
    if (!is_http_data(check, HTTP_CHECK_SIZE))
        return 0;

    __u32 zero = 0;
    struct req_info_t *req = bpf_map_lookup_elem(&req_heap, &zero);
    if (!req)
        return 0;

    req->start_time = bpf_ktime_get_ns() / 1000;
    req->req_size = num;
    req->fd = conn_id;
    bpf_get_current_comm(&req->comm, sizeof(req->comm));
    req->client_type = detect_client_type(req->comm);
    bpf_probe_read_user(req->data, MAX_DATA_SIZE, buf);

    __u64 key = ((__u64)pid << 32) | conn_id;
    bpf_map_update_elem(&req_map, &key, req, BPF_ANY);

    return 0;
}

SEC("uprobe/go_tls_read")
int uprobe_go_tls_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_filter_pid(pid))
        return 0;

    // Go ABI: RAX = *Conn, RBX = output buffer pointer
    __u32 conn_id = (__u32)ctx->ax;
    const char *buf = (const char *)ctx->bx;

    // Unlike the C TLS probes, we do NOT check req_map here.
    // Go's net/http readLoop calls tls.Read BEFORE the writeLoop
    // calls tls.Write (via bufio.Peek), so req_map is empty at
    // Read entry. The Write happens between Read entry and Read
    // return, so the return probe will find the req_map entry.
    struct read_args_t args = {};
    args.buf_ptr = (__u64)buf;
    args.fd = conn_id;  // Carry conn_id to return probe
    args.source = READ_SRC_UPROBE;
    bpf_map_update_elem(&read_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/go_tls_read")
int uretprobe_go_tls_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (should_filter_pid(pid))
        return 0;

    // Go ABI: RAX = bytes read (same register as C return value)
    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    struct read_args_t *args = bpf_map_lookup_elem(&read_args_map, &pid_tgid);
    if (!args)
        return 0;

    if (args->source != READ_SRC_UPROBE)
        return 0;

    __u64 buf_ptr = args->buf_ptr;
    __u32 conn_id = args->fd;  // Retrieve conn_id saved at Read entry
    bpf_map_delete_elem(&read_args_map, &pid_tgid);

    // Skip tiny reads (e.g. 1-byte peek for 100 Continue) - keep req_map
    // entry so the next read captures the actual response.
    if (ret < MIN_RESP_SIZE)
        return 0;

    __u64 now = bpf_ktime_get_ns() / 1000;

    __u64 req_key = ((__u64)pid << 32) | conn_id;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &req_key);
    if (!req)
        return 0;

    __u64 latency_us = now - req->start_time;
    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    __u32 zero = 0;
    struct event_t *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&req_map, &req_key);
        return 0;
    }

    event->timestamp_us = now;
    event->latency_us = latency_us;
    event->pid = pid;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->fd = conn_id;
    __builtin_memcpy(event->comm, req->comm, TASK_COMM_LEN);
    event->req_size = req->req_size;
    event->resp_size = ret;
    event->actual_resp_bytes = ret;
    event->is_partial = 0;
    event->client_type = req->client_type;
    __builtin_memcpy(event->data, req->data, MAX_DATA_SIZE);

    __builtin_memset(event->resp_data, 0, MAX_RESP_SIZE);
    bpf_probe_read_user(event->resp_data, MAX_RESP_SIZE, (const char *)buf_ptr);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&req_map, &req_key);

    return 0;
}

// ========== Process Exec Tracepoint for Dynamic Binary Discovery ==========
// Fires on every process start so userspace can check if the new binary
// uses Go crypto/tls and attach uprobes before its first TLS call.

SEC("tracepoint/sched/sched_process_exec")
int tracepoint_exec(void *ctx) {
    struct exec_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
