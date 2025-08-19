#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Configuration - will be replaced by Python
#define TARGET_PID 0
#define MIN_LATENCY_US 0

// Minimal event structure
struct event_t {
    u64 ts_us;
    u64 latency_us;
    u32 pid;
    u32 tid;
    u32 fd;
    char comm[TASK_COMM_LEN];
    u8 http_method;
    u8 is_s3;
};

BPF_PERF_OUTPUT(events);

// Minimal HTTP method detection
static inline u8 detect_http_method(const char *data, u32 len) {
    if (len < 3) return 0;
    
    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') return 1;
    if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T') return 2;
    if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && len >= 4 && data[3] == 'T') return 3;
    if (data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && len >= 6 && data[3] == 'E' && data[4] == 'T' && data[5] == 'E') return 4;
    if (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && len >= 4 && data[3] == 'D') return 5;
    
    return 0;
}

// Check if data contains HTTP request
static inline int is_http_request(const char *data, u32 len) {
    if (len < 4) return 0;
    
    u8 method = detect_http_method(data, len);
    if (method == 0) return 0;
    
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

// Simple hash map for tracking requests
BPF_HASH(request_times, u64, u64);

// Trace write syscall
int trace_write(struct pt_regs *ctx, int fd, const char __user *buf, size_t count) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    // Use very small buffer
    char data[64];  // Minimal buffer
    
    u32 read_size = count > sizeof(data) ? sizeof(data) : count;
    if (bpf_probe_read_user(data, read_size, buf) != 0) return 0;
    
    if (!is_http_request(data, read_size)) return 0;
    
    u8 method = detect_http_method(data, read_size);
    if (method == 0) return 0;
    
    u64 key = ((u64)pid << 32) | fd;
    u64 start_time = bpf_ktime_get_ns();
    
    request_times.update(&key, &start_time);
    
    return 0;
}

// Trace read syscall
int trace_read(struct pt_regs *ctx, int fd, void __user *buf, size_t count) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    // Use very small buffer
    char data[64];  // Minimal buffer
    
    u32 read_size = count > sizeof(data) ? sizeof(data) : count;
    if (bpf_probe_read_user(data, read_size, buf) != 0) return 0;
    
    if (!is_http_response(data, read_size)) return 0;
    
    u64 key = ((u64)pid << 32) | fd;
    u64 *start_time = request_times.lookup(&key);
    
    if (!start_time) return 0;
    
    u64 end_time = bpf_ktime_get_ns();
    u64 latency_us = (end_time - *start_time) / 1000;
    
    if (latency_us < MIN_LATENCY_US) return 0;
    
    // Create minimal event
    struct event_t event;
    event.ts_us = end_time / 1000;
    event.latency_us = latency_us;
    event.pid = pid;
    event.tid = tid;
    event.fd = fd;
    event.http_method = 1;  // Simplified
    event.is_s3 = 0;        // Simplified for now
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    events.perf_submit(ctx, &event, sizeof(event));
    request_times.delete(&key);
    
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
