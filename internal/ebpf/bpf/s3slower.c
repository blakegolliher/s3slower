// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// S3Slower BPF program for tracing S3 client latency

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Maximum data capture size
#define MAX_DATA_SIZE 64
#define TASK_COMM_LEN 16

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
    // Check for known clients
    if (comm[0] == 'w' && comm[1] == 'a' && comm[2] == 'r' && comm[3] == 'p') {
        return CLIENT_WARP;
    }
    if (comm[0] == 'e' && comm[1] == 'l' && comm[2] == 'b') {
        return CLIENT_ELBENCHO;
    }
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't') {
        return CLIENT_BOTO3;  // Python/boto3
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

// ========== Kprobes for plain HTTP ==========

SEC("kprobe/sys_write")
int kprobe_sys_write(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (should_filter_pid(pid)) {
        return 0;
    }

    int fd = (int)PT_REGS_PARM1(ctx);
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    __u32 count = (size_t)PT_REGS_PARM3(ctx);

    // Skip invalid FDs (stdin/stdout/stderr)
    if (fd < 3) {
        return 0;
    }

    // Skip if count is 0 (verifier requires this check)
    if (count == 0) {
        return 0;
    }

    // Read first bytes to check if HTTP
    char data[MAX_DATA_SIZE] = {};
    __u32 to_read = count;
    if (to_read > MAX_DATA_SIZE) {
        to_read = MAX_DATA_SIZE;
    }
    if (bpf_probe_read_user(data, to_read, buf) < 0) {
        return 0;
    }

    if (!is_http_data(data, to_read)) {
        return 0;
    }

    // Store request info
    __u64 key = ((__u64)pid << 32) | (__u32)fd;
    struct req_info_t req = {};
    req.start_time = bpf_ktime_get_ns() / 1000;
    req.req_size = count;
    req.fd = fd;
    bpf_get_current_comm(&req.comm, sizeof(req.comm));
    req.client_type = detect_client_type(req.comm);
    __builtin_memcpy(req.data, data, MAX_DATA_SIZE);

    bpf_map_update_elem(&req_map, &key, &req, BPF_ANY);

    return 0;
}

SEC("kprobe/sys_read")
int kprobe_sys_read(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (should_filter_pid(pid)) {
        return 0;
    }

    int fd = (int)PT_REGS_PARM1(ctx);
    if (fd < 3) {
        return 0;
    }

    return 0;
}

SEC("kretprobe/sys_read")
int kretprobe_sys_read(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (should_filter_pid(pid)) {
        return 0;
    }

    ssize_t ret = (ssize_t)PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }

    // We need to find the matching request
    // This is a simplified version - full implementation would track FD properly

    return 0;
}

// ========== Uprobes for SSL/TLS ==========

SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    if (should_filter_pid(pid)) {
        return 0;
    }

    // SSL *ssl = (void *)PT_REGS_PARM1(ctx);
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);

    // Skip if size is not positive (verifier requires this check)
    if (num <= 0) {
        return 0;
    }

    // Read first bytes to check if HTTP
    char data[MAX_DATA_SIZE] = {};
    __u32 to_read = (__u32)num;
    if (to_read > MAX_DATA_SIZE) {
        to_read = MAX_DATA_SIZE;
    }
    if (bpf_probe_read_user(data, to_read, buf) < 0) {
        return 0;
    }

    if (!is_http_data(data, to_read)) {
        return 0;
    }

    // Use TID as a pseudo-FD for SSL connections
    __u64 key = ((__u64)pid << 32) | tid;
    struct req_info_t req = {};
    req.start_time = bpf_ktime_get_ns() / 1000;
    req.req_size = num;
    req.fd = tid;
    bpf_get_current_comm(&req.comm, sizeof(req.comm));
    req.client_type = detect_client_type(req.comm);
    __builtin_memcpy(req.data, data, MAX_DATA_SIZE);

    bpf_map_update_elem(&req_map, &key, &req, BPF_ANY);

    return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    if (should_filter_pid(pid)) {
        return 0;
    }

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }

    __u64 now = bpf_ktime_get_ns() / 1000;

    // Look up the request
    __u64 key = ((__u64)pid << 32) | tid;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &key);
    if (!req) {
        return 0;
    }

    __u64 latency_us = now - req->start_time;

    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &key);
        return 0;
    }

    // Send event to userspace
    struct event_t event = {};
    event.timestamp_us = now;
    event.latency_us = latency_us;
    event.pid = pid;
    event.tid = tid;
    event.fd = req->fd;
    __builtin_memcpy(event.comm, req->comm, TASK_COMM_LEN);
    event.req_size = req->req_size;
    event.resp_size = ret;
    event.actual_resp_bytes = ret;
    event.is_partial = 0;
    event.client_type = req->client_type;
    __builtin_memcpy(event.data, req->data, MAX_DATA_SIZE);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    bpf_map_delete_elem(&req_map, &key);

    return 0;
}

// GnuTLS probes
SEC("uprobe/gnutls_record_send")
int uprobe_gnutls_send(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    if (should_filter_pid(pid)) {
        return 0;
    }

    // gnutls_session_t session = (void *)PT_REGS_PARM1(ctx);
    const char *data = (const char *)PT_REGS_PARM2(ctx);
    size_t data_size = (size_t)PT_REGS_PARM3(ctx);

    // Skip if size is 0 (verifier requires this check)
    if (data_size == 0) {
        return 0;
    }

    char buf[MAX_DATA_SIZE] = {};
    __u32 to_read = data_size;
    if (to_read > MAX_DATA_SIZE) {
        to_read = MAX_DATA_SIZE;
    }
    if (bpf_probe_read_user(buf, to_read, data) < 0) {
        return 0;
    }

    if (!is_http_data(buf, to_read)) {
        return 0;
    }

    __u64 key = ((__u64)pid << 32) | tid;
    struct req_info_t req = {};
    req.start_time = bpf_ktime_get_ns() / 1000;
    req.req_size = data_size;
    req.fd = tid;
    bpf_get_current_comm(&req.comm, sizeof(req.comm));
    req.client_type = detect_client_type(req.comm);
    __builtin_memcpy(req.data, buf, MAX_DATA_SIZE);

    bpf_map_update_elem(&req_map, &key, &req, BPF_ANY);

    return 0;
}

SEC("uretprobe/gnutls_record_recv")
int uretprobe_gnutls_recv(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    if (should_filter_pid(pid)) {
        return 0;
    }

    ssize_t ret = (ssize_t)PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }

    __u64 now = bpf_ktime_get_ns() / 1000;

    __u64 key = ((__u64)pid << 32) | tid;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &key);
    if (!req) {
        return 0;
    }

    __u64 latency_us = now - req->start_time;

    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &key);
        return 0;
    }

    struct event_t event = {};
    event.timestamp_us = now;
    event.latency_us = latency_us;
    event.pid = pid;
    event.tid = tid;
    event.fd = req->fd;
    __builtin_memcpy(event.comm, req->comm, TASK_COMM_LEN);
    event.req_size = req->req_size;
    event.resp_size = ret;
    event.actual_resp_bytes = ret;
    event.is_partial = 0;
    event.client_type = req->client_type;
    __builtin_memcpy(event.data, req->data, MAX_DATA_SIZE);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    bpf_map_delete_elem(&req_map, &key);

    return 0;
}

// NSS probes
SEC("uprobe/PR_Write")
int uprobe_pr_write(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    if (should_filter_pid(pid)) {
        return 0;
    }

    // PRFileDesc *fd = (void *)PT_REGS_PARM1(ctx);
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    int amount = (int)PT_REGS_PARM3(ctx);

    // Skip if size is not positive (verifier requires this check)
    if (amount <= 0) {
        return 0;
    }

    char data[MAX_DATA_SIZE] = {};
    __u32 to_read = (__u32)amount;
    if (to_read > MAX_DATA_SIZE) {
        to_read = MAX_DATA_SIZE;
    }
    if (bpf_probe_read_user(data, to_read, buf) < 0) {
        return 0;
    }

    if (!is_http_data(data, to_read)) {
        return 0;
    }

    __u64 key = ((__u64)pid << 32) | tid;
    struct req_info_t req = {};
    req.start_time = bpf_ktime_get_ns() / 1000;
    req.req_size = amount;
    req.fd = tid;
    bpf_get_current_comm(&req.comm, sizeof(req.comm));
    req.client_type = detect_client_type(req.comm);
    __builtin_memcpy(req.data, data, MAX_DATA_SIZE);

    bpf_map_update_elem(&req_map, &key, &req, BPF_ANY);

    return 0;
}

SEC("uretprobe/PR_Read")
int uretprobe_pr_read(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    if (should_filter_pid(pid)) {
        return 0;
    }

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }

    __u64 now = bpf_ktime_get_ns() / 1000;

    __u64 key = ((__u64)pid << 32) | tid;
    struct req_info_t *req = bpf_map_lookup_elem(&req_map, &key);
    if (!req) {
        return 0;
    }

    __u64 latency_us = now - req->start_time;

    if (should_filter_latency(latency_us)) {
        bpf_map_delete_elem(&req_map, &key);
        return 0;
    }

    struct event_t event = {};
    event.timestamp_us = now;
    event.latency_us = latency_us;
    event.pid = pid;
    event.tid = tid;
    event.fd = req->fd;
    __builtin_memcpy(event.comm, req->comm, TASK_COMM_LEN);
    event.req_size = req->req_size;
    event.resp_size = ret;
    event.actual_resp_bytes = ret;
    event.is_partial = 0;
    event.client_type = req->client_type;
    __builtin_memcpy(event.data, req->data, MAX_DATA_SIZE);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    bpf_map_delete_elem(&req_map, &key);

    return 0;
}
