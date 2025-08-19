#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>

// Configuration - will be replaced by Python
#define TARGET_PID 0
#define MIN_LATENCY_US 0
#define MAX_BUFFER_SIZE 256  // Reduced for simplicity

// HTTP method detection
enum http_method {
    HTTP_UNKNOWN = 0,
    HTTP_GET = 1,
    HTTP_PUT = 2,
    HTTP_POST = 3,
    HTTP_DELETE = 4,
    HTTP_HEAD = 5,
};

struct request_state {
    u64 start_ts;
    u32 fd;
    u32 total_req_size;
    u32 total_resp_size;
    u8 http_method;
    u8 is_s3;
    u16 url_offset;
    u16 url_len;
    char data[MAX_BUFFER_SIZE];
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
    u8 num_segments;
    char url[256];
    char s3_operation[64];
    char data[MAX_BUFFER_SIZE];
};

BPF_HASH(request_states, u64, struct request_state);
BPF_PERF_OUTPUT(events);

// Simple HTTP method detection
static inline u8 detect_http_method(const char *data, u32 len) {
    if (len < 3) return HTTP_UNKNOWN;
    
    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') return HTTP_GET;
    if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T') return HTTP_PUT;
    if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && len >= 4 && data[3] == 'T') return HTTP_POST;
    if (data[0] == 'D' && len >= 6 && data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && data[4] == 'T' && data[5] == 'E') return HTTP_DELETE;
    if (data[0] == 'H' && len >= 4 && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') return HTTP_HEAD;
    
    return HTTP_UNKNOWN;
}

// Check if this is an HTTP response
static inline int is_http_response(const char *data, u32 len) {
    return (len >= 4 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P');
}

// Simple S3 detection - just look for x-amz- headers
static inline int detect_s3_simple(const char *data, u32 len) {
    if (len < 20) return 0;
    
    // Simple scan for x-amz- pattern
    for (int i = 0; i < 200; i++) {
        if (i >= len - 6) break;
        if (data[i] == 'x' && data[i+1] == '-' && data[i+2] == 'a' && 
            data[i+3] == 'm' && data[i+4] == 'z' && data[i+5] == '-') {
            return 1;
        }
        // Also check for AWS4-HMAC
        if (i < len - 10 && data[i] == 'A' && data[i+1] == 'W' && data[i+2] == 'S' && 
            data[i+3] == '4' && data[i+4] == '-' && data[i+5] == 'H' && data[i+6] == 'M' &&
            data[i+7] == 'A' && data[i+8] == 'C') {
            return 1;
        }
    }
    return 0;
}

// Trace write() syscalls
int trace_write(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    unsigned int fd = (unsigned int)ctx->di;
    const char __user *buf = (const char *)ctx->si;
    size_t count = (size_t)ctx->dx;
    
    if (count < 4) return 0;
    
    char data[MAX_BUFFER_SIZE];
    u32 read_size = count > sizeof(data) ? sizeof(data) : count;
    if (bpf_probe_read_user(data, read_size, buf) != 0) return 0;
    
    u8 method = detect_http_method(data, read_size);
    if (method == HTTP_UNKNOWN) return 0;
    
    u64 key = ((u64)pid << 32) | fd;
    
    struct request_state state;
    state.start_ts = bpf_ktime_get_ns();
    state.fd = fd;
    state.total_req_size = count;
    state.total_resp_size = 0;
    state.http_method = method;
    state.is_s3 = detect_s3_simple(data, read_size);
    state.url_offset = 0;
    state.url_len = 0;
    
    // Copy data manually
    for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
        if (i < read_size) {
            state.data[i] = data[i];
        }
    }
    
    // Find URL boundaries
    int space_count = 0;
    for (int i = 0; i < 200; i++) {
        if (i >= read_size) break;
        if (data[i] == ' ') {
            space_count++;
            if (space_count == 1) {
                state.url_offset = i + 1;
            } else if (space_count == 2) {
                state.url_len = i - state.url_offset;
                break;
            }
        }
    }
    
    request_states.update(&key, &state);
    
    return 0;
}

// Trace read() syscalls
int trace_read(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    int fd = (int)ctx->di;
    void __user *buf = (void *)ctx->si;
    size_t count = (size_t)ctx->dx;
    
    if (count < 4) return 0;
    
    char data[MAX_BUFFER_SIZE];
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
    event.req_size = state->total_req_size;
    event.resp_size = count;
    event.http_method = state->http_method;
    event.is_s3 = state->is_s3;
    event.num_segments = 1;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Clear arrays first
    for (int i = 0; i < 256; i++) {
        event.url[i] = 0;
    }
    for (int i = 0; i < 64; i++) {
        event.s3_operation[i] = 0;
    }
    for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
        event.data[i] = 0;
    }
    
    // Extract URL
    if (state->url_len > 0 && state->url_len < 256 && state->url_offset < MAX_BUFFER_SIZE) {
        for (int i = 0; i < 255; i++) {
            if (i >= state->url_len) break;
            if (state->url_offset + i < MAX_BUFFER_SIZE) {
                event.url[i] = state->data[state->url_offset + i];
            }
        }
    }
    
    // Copy first segment data
    for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
        if (i < read_size) {
            event.data[i] = state->data[i];
        }
    }
    
    // Simple S3 operation detection
    if (state->is_s3) {
        if (state->http_method == HTTP_GET) {
            event.s3_operation[0] = 'G';
            event.s3_operation[1] = 'e';
            event.s3_operation[2] = 't';
            event.s3_operation[3] = 'O';
            event.s3_operation[4] = 'b';
            event.s3_operation[5] = 'j';
            event.s3_operation[6] = 'e';
            event.s3_operation[7] = 'c';
            event.s3_operation[8] = 't';
        } else if (state->http_method == HTTP_PUT) {
            event.s3_operation[0] = 'P';
            event.s3_operation[1] = 'u';
            event.s3_operation[2] = 't';
            event.s3_operation[3] = 'O';
            event.s3_operation[4] = 'b';
            event.s3_operation[5] = 'j';
            event.s3_operation[6] = 'e';
            event.s3_operation[7] = 'c';
            event.s3_operation[8] = 't';
        }
    }
    
    events.perf_submit(ctx, &event, sizeof(event));
    request_states.delete(&key);
    
    return 0;
}

// Additional syscall handlers for enhanced detection
int trace_send(struct pt_regs *ctx) {
    // Just track the call for now - avoid calling trace_write
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    return 0;
}

int trace_sendto(struct pt_regs *ctx) {
    // Just track the call for now - avoid calling trace_write
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    return 0;
}

int trace_recv(struct pt_regs *ctx) {
    // Just track the call for now - avoid calling trace_read
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    return 0;
}

int trace_recvfrom(struct pt_regs *ctx) {
    // Just track the call for now - avoid calling trace_read
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    return 0;
}
