#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Configuration - will be replaced by Python
#define TARGET_PID 0
#define MIN_LATENCY_US 0

// HTTP method detection - minimal list
enum http_method {
    HTTP_UNKNOWN = 0,
    HTTP_GET = 1,
    HTTP_PUT = 2,
    HTTP_POST = 3,
    HTTP_DELETE = 4,
    HTTP_HEAD = 5,
};

// Minimal state tracking
struct request_state {
    u64 start_ts;
    u32 fd;
    u8 http_method;
    u8 is_s3;
    char url[64];  // Very small URL buffer
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
    u8 http_method;
    u8 is_s3;
    char url[64];
    char s3_operation[32];
};

BPF_HASH(request_states, u64, struct request_state);
BPF_PERF_OUTPUT(events);

// Minimal HTTP method detection
static inline u8 detect_http_method(const char *data, u32 len) {
    if (len < 3) return HTTP_UNKNOWN;
    
    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') return HTTP_GET;
    if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T') return HTTP_PUT;
    if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && len >= 4 && data[3] == 'T') return HTTP_POST;
    if (data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && len >= 6 && data[3] == 'E' && data[4] == 'T' && data[5] == 'E') return HTTP_DELETE;
    if (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && len >= 4 && data[3] == 'D') return HTTP_HEAD;
    
    return HTTP_UNKNOWN;
}

// Check if data contains HTTP request
static inline int is_http_request(const char *data, u32 len) {
    if (len < 4) return 0;
    
    u8 method = detect_http_method(data, len);
    if (method == HTTP_UNKNOWN) return 0;
    
    // Look for space after method
    for (int i = 0; i < len - 1; i++) {
        if (data[i] == ' ') return 1;
    }
    
    return 0;
}

// Check if data contains HTTP response
static inline int is_http_response(const char *data, u32 len) {
    if (len < 4) return 0;
    
    // Look for "HTTP/" at start
    if (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P') {
        return 1;
    }
    
    return 0;
}

// Minimal S3 pattern detection
static inline int detect_s3_patterns(const char *data, u32 len) {
    if (len < 6) return 0;
    
    // Check for x-amz-* headers
    for (int i = 0; i < len - 5; i++) {
        if (data[i] == 'x' && data[i+1] == '-' && data[i+2] == 'a' && 
            data[i+3] == 'm' && data[i+4] == 'z' && data[i+5] == '-') {
            return 1;
        }
    }
    
    return 0;
}

// Minimal URL extraction
static inline void extract_url(const char *data, u32 len, char *url, u32 url_size) {
    int url_start = -1;
    int url_end = -1;
    
    // Find URL start (after first space)
    for (int i = 0; i < len - 1; i++) {
        if (data[i] == ' ' && url_start == -1) {
            url_start = i + 1;
        } else if (data[i] == ' ' && url_start != -1) {
            url_end = i;
            break;
        }
    }
    
    if (url_start != -1 && url_end == -1) {
        url_end = len;
    }
    
    if (url_start != -1 && url_end != -1) {
        u32 copy_len = url_end - url_start;
        if (copy_len > url_size - 1) copy_len = url_size - 1;
        
        for (int i = 0; i < copy_len; i++) {
            url[i] = data[url_start + i];
        }
        url[copy_len] = 0;
    } else {
        url[0] = 0;
    }
}

// Trace write syscall
int trace_write(struct pt_regs *ctx, int fd, const char __user *buf, size_t count) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    // Use very small buffer to save stack space
    char data[128];  // Reduced from 256 to 128
    
    u32 read_size = count > sizeof(data) ? sizeof(data) : count;
    if (bpf_probe_read_user(data, read_size, buf) != 0) return 0;
    
    if (!is_http_request(data, read_size)) return 0;
    
    u8 method = detect_http_method(data, read_size);
    if (method == HTTP_UNKNOWN) return 0;
    
    u64 key = ((u64)pid << 32) | fd;
    struct request_state *state = request_states.lookup(&key);
    
    if (!state) {
        // New request
        struct request_state new_state;
        new_state.start_ts = bpf_ktime_get_ns();
        new_state.fd = fd;
        new_state.http_method = method;
        new_state.is_s3 = detect_s3_patterns(data, read_size);
        
        // Extract URL
        extract_url(data, read_size, new_state.url, sizeof(new_state.url));
        
        request_states.update(&key, &new_state);
    }
    
    return 0;
}

// Trace read syscall
int trace_read(struct pt_regs *ctx, int fd, void __user *buf, size_t count) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    // Use very small buffer to save stack space
    char data[128];  // Reduced from 256 to 128
    
    u32 read_size = count > sizeof(data) ? sizeof(data) : count;
    if (bpf_probe_read_user(data, read_size, buf) != 0) return 0;
    
    if (!is_http_response(data, read_size)) return 0;
    
    u64 key = ((u64)pid << 32) | fd;
    struct request_state *state = request_states.lookup(&key);
    if (!state) return 0;
    
    u64 end_ts = bpf_ktime_get_ns();
    u64 latency_us = (end_ts - state->start_ts) / 1000;
    
    if (latency_us < MIN_LATENCY_US) return 0;
    
    struct event_t event;
    event.ts_us = end_ts / 1000;
    event.latency_us = latency_us;
    event.pid = pid;
    event.tid = tid;
    event.fd = fd;
    event.req_size = count;  // Simplified
    event.resp_size = count;
    event.http_method = state->http_method;
    event.is_s3 = state->is_s3;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Copy URL
    for (int i = 0; i < 64; i++) {
        event.url[i] = state->url[i];
    }
    
    // Determine S3 operation
    if (state->is_s3) {
        if (state->http_method == HTTP_GET) {
            event.s3_operation[0] = 'G'; event.s3_operation[1] = 'e'; event.s3_operation[2] = 't';
            event.s3_operation[3] = 'O'; event.s3_operation[4] = 'b'; event.s3_operation[5] = 'j';
            event.s3_operation[6] = 'e'; event.s3_operation[7] = 'c'; event.s3_operation[8] = 't';
            event.s3_operation[9] = 0;
        } else if (state->http_method == HTTP_PUT) {
            event.s3_operation[0] = 'P'; event.s3_operation[1] = 'u'; event.s3_operation[2] = 't';
            event.s3_operation[3] = 'O'; event.s3_operation[4] = 'b'; event.s3_operation[5] = 'j';
            event.s3_operation[6] = 'e'; event.s3_operation[7] = 'c'; event.s3_operation[8] = 't';
            event.s3_operation[9] = 0;
        } else {
            event.s3_operation[0] = 'U'; event.s3_operation[1] = 'n'; event.s3_operation[2] = 'k';
            event.s3_operation[3] = 'n'; event.s3_operation[4] = 'o'; event.s3_operation[5] = 'w';
            event.s3_operation[6] = 'n'; event.s3_operation[7] = 0;
        }
    } else {
        event.s3_operation[0] = 'H'; event.s3_operation[1] = 'T'; event.s3_operation[2] = 'T';
        event.s3_operation[3] = 'P'; event.s3_operation[4] = 0;
    }
    
    events.perf_submit(ctx, &event, sizeof(event));
    request_states.delete(&key);
    
    return 0;
}

// Minimal syscall handlers - just track calls
int trace_send(struct pt_regs *ctx, int fd, const char __user *buf, size_t len, int flags) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    return 0;
}

int trace_sendto(struct pt_regs *ctx, int fd, const char __user *buf, size_t len, int flags, 
                 const struct sockaddr __user *dest_addr, int addrlen) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    return 0;
}

int trace_recv(struct pt_regs *ctx, int fd, void __user *buf, size_t len, int flags) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    return 0;
}

int trace_recvfrom(struct pt_regs *ctx, int fd, void __user *buf, size_t len, int flags,
                   struct sockaddr __user *src_addr, int __user *addrlen) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    return 0;
}
