#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>

// Configuration - will be replaced by Python
#define TARGET_PID 0
#define MIN_LATENCY_US 0

struct request_t {
    u64 start_ts;
    u32 fd;
    u32 total_req_size;  // Track total request size across syscalls
    u32 total_resp_size; // Track total response size
    u8 is_multipart;     // Flag if request spans multiple syscalls
    char data[64];
};

struct event_t {
    u64 ts_us;
    u64 latency_us;
    u32 pid;
    u32 tid;
    u32 fd;
    char comm[TASK_COMM_LEN];
    u32 req_size;
    u32 resp_size;
    u32 actual_resp_bytes; // Actual bytes returned by read()
    u8 is_partial;         // Flag if this might be partial data
    char data[64];
};

BPF_HASH(requests, u64, struct request_t);
BPF_HASH(ongoing_requests, u64, u32); // Track ongoing multi-part requests
BPF_PERF_OUTPUT(events);

// Simple HTTP detection - just check first few bytes
static int is_http_request(const char *data) {
    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') return 1;
    if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') return 1;
    if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') return 1;
    if (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') return 1;
    if (data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E') return 1;
    return 0;
}

static int is_http_response(const char *data) {
    if (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P') return 1;
    return 0;
}

int trace_write(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    // PID filtering - will be configured by Python
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;

    unsigned int fd = (unsigned int)ctx->di;
    const char __user *buf = (const char *)ctx->si;
    size_t count = (size_t)ctx->dx;

    if (count < 4) return 0;  // Too small to be HTTP

    char data[64] = {};
    if (bpf_probe_read_user(data, sizeof(data), buf) != 0) return 0;

    u64 key = ((u64)pid << 32) | fd;

    // Check if this is a new HTTP request
    if (is_http_request(data)) {
        struct request_t req = {};
        req.start_ts = bpf_ktime_get_ns();
        req.fd = fd;
        req.total_req_size = (u32)count;
        req.is_multipart = 0;

        // Copy first 64 bytes safely
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            req.data[i] = data[i];
        }

        requests.update(&key, &req);
        u32 count_u32 = (u32)count;
        ongoing_requests.update(&key, &count_u32);
    } else {
        // This might be continuation of a previous request
        u32 *ongoing_size = ongoing_requests.lookup(&key);
        if (ongoing_size) {
            *ongoing_size += (u32)count;

            // Update the request record
            struct request_t *req = requests.lookup(&key);
            if (req) {
                req->total_req_size += (u32)count;
                req->is_multipart = 1;
            }
        }
    }

    return 0;
}

int trace_read(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    // PID filtering - will be configured by Python
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;

    int fd = (int)ctx->di;
    void __user *buf = (void *)ctx->si;
    size_t count = (size_t)ctx->dx;

    if (count < 4) return 0;

    char data[64] = {};
    if (bpf_probe_read_user(data, sizeof(data), buf) != 0) return 0;

    if (!is_http_response(data)) return 0;

    u64 key = ((u64)pid << 32) | fd;
    struct request_t *req = requests.lookup(&key);
    if (!req) return 0;

    u64 end_ts = bpf_ktime_get_ns();
    u64 latency_us = (end_ts - req->start_ts) / 1000;

    if (latency_us < MIN_LATENCY_US) return 0;

    struct event_t event = {};
    event.ts_us = end_ts / 1000;
    event.latency_us = latency_us;
    event.pid = pid;
    event.tid = tid;
    event.fd = fd;
    event.req_size = req->total_req_size;  // Use total accumulated size
    event.resp_size = count;               // This is the read buffer size
    event.actual_resp_bytes = 0;           // We'll get this from return value
    event.is_partial = req->is_multipart;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Copy request data
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        event.data[i] = req->data[i];
    }

    events.perf_submit(ctx, &event, sizeof(event));
    requests.delete(&key);
    ongoing_requests.delete(&key);

    return 0;
} 