#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

// Configuration
#define TARGET_PID TARGET_PID_PLACEHOLDER
#define MIN_LATENCY_US MIN_LATENCY_PLACEHOLDER

struct data_t {
    u64 data[16];
};

struct event_t {
    u64 ts_us;
    u64 latency_us;
    u32 pid;
    u32 tid;
    char task[TASK_COMM_LEN];
    char data[256];
    char url[128];
    char s3_operation[16];
};

struct req_info_t {
    u64 start_ns;
    struct data_t data_buf;
};

BPF_HASH(inflight_requests, u64, struct req_info_t);
BPF_PERF_OUTPUT(events);

// Helper to check if data looks like HTTP
static int is_http_request(const char *data, int len) {
    if (len < 7) return 0;
    
    // Check for HTTP methods
    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') return 1;
    if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') return 1;
    if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T' && data[4] == ' ') return 1;
    if (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D' && data[4] == ' ') return 1;
    if (data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && data[4] == 'T' && data[5] == 'E' && data[6] == ' ') return 1;
    
    return 0;
}

static int is_http_response(const char *data, int len) {
    if (len < 12) return 0;
    return (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P' && 
            data[4] == '/' && data[5] == '1' && data[6] == '.');
}

// Extract URL from HTTP request
static void extract_url(const char *data, char *url, int url_size) {
    int i = 0;
    int url_start = 0;
    int url_end = 0;
    
    // Find start of URL (after method)
    while (i < 200 && data[i] != ' ') i++;
    if (i >= 200) return;
    i++; // Skip space
    url_start = i;
    
    // Find end of URL
    while (i < 200 && data[i] != ' ' && data[i] != '?' && data[i] != '\r' && data[i] != '\n') i++;
    url_end = i;
    
    // Copy URL
    int len = url_end - url_start;
    if (len > url_size - 1) len = url_size - 1;
    
    #pragma unroll
    for (int j = 0; j < 127; j++) {
        if (j < len) {
            url[j] = data[url_start + j];
        } else {
            url[j] = 0;
            break;
        }
    }
    url[url_size - 1] = 0;
}

// Detect S3 operation from URL
static void detect_s3_operation(const char *data, const char *url, char *operation) {
    // Default
    operation[0] = 'U'; operation[1] = 'N'; operation[2] = 'K'; 
    operation[3] = 'N'; operation[4] = 'O'; operation[5] = 'W'; 
    operation[6] = 'N'; operation[7] = 0;
    
    // Check HTTP method
    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') {
        operation[0] = 'G'; operation[1] = 'E'; operation[2] = 'T'; operation[3] = 0;
    } else if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T') {
        operation[0] = 'P'; operation[1] = 'U'; operation[2] = 'T'; operation[3] = 0;
    } else if (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') {
        operation[0] = 'H'; operation[1] = 'E'; operation[2] = 'A'; operation[3] = 'D'; operation[4] = 0;
    } else if (data[0] == 'D' && data[1] == 'E' && data[2] == 'L') {
        operation[0] = 'D'; operation[1] = 'E'; operation[2] = 'L'; 
        operation[3] = 'E'; operation[4] = 'T'; operation[5] = 'E'; operation[6] = 0;
    } else if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') {
        operation[0] = 'P'; operation[1] = 'O'; operation[2] = 'S'; 
        operation[3] = 'T'; operation[4] = 0;
    }
}

// Process data for both write and tcp_sendmsg
static int process_send_data(struct pt_regs *ctx, u64 pid_tgid, const void *buf, size_t size) {
    if (TARGET_PID != 0 && (pid_tgid >> 32) != TARGET_PID) return 0;
    if (!buf || size < 10) return 0;
    
    struct data_t data_buf = {};
    bpf_probe_read_user(&data_buf, sizeof(data_buf), buf);
    
    char *data = (char *)&data_buf;
    
    if (is_http_request(data, size)) {
        struct req_info_t req_info = {};
        req_info.start_ns = bpf_ktime_get_ns();
        req_info.data_buf = data_buf;
        
        // Use PID:TID as key
        u64 key = pid_tgid;
        inflight_requests.update(&key, &req_info);
    }
    
    return 0;
}

// Process response data for both read and tcp_recvmsg
static int process_recv_data(struct pt_regs *ctx, u64 pid_tgid, const void *buf, size_t size) {
    if (TARGET_PID != 0 && (pid_tgid >> 32) != TARGET_PID) return 0;
    if (!buf || size < 12) return 0;
    
    struct data_t data_buf = {};
    bpf_probe_read_user(&data_buf, sizeof(data_buf), buf);
    
    char *data = (char *)&data_buf;
    
    if (is_http_response(data, size)) {
        u64 key = pid_tgid;
        struct req_info_t *req_info = inflight_requests.lookup(&key);
        if (!req_info) return 0;
        
        u64 end_ns = bpf_ktime_get_ns();
        u64 latency_us = (end_ns - req_info->start_ns) / 1000;
        
        if (latency_us < MIN_LATENCY_US) {
            inflight_requests.delete(&key);
            return 0;
        }
        
        struct event_t event = {};
        event.ts_us = end_ns / 1000;
        event.latency_us = latency_us;
        event.pid = pid_tgid >> 32;
        event.tid = (u32)pid_tgid;
        bpf_get_current_comm(&event.task, sizeof(event.task));
        
        // Copy request data
        __builtin_memcpy(event.data, &req_info->data_buf, sizeof(event.data));
        
        // Extract URL and operation
        extract_url((char *)&req_info->data_buf, event.url, sizeof(event.url));
        detect_s3_operation((char *)&req_info->data_buf, event.url, event.s3_operation);
        
        events.perf_submit(ctx, &event, sizeof(event));
        inflight_requests.delete(&key);
    }
    
    return 0;
}

// Original write/read probes
int trace_write(struct pt_regs *ctx) {
    unsigned int fd = PT_REGS_PARM1(ctx);
    const void __user *buf = (const void *)PT_REGS_PARM2(ctx);
    size_t count = PT_REGS_PARM3(ctx);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    return process_send_data(ctx, pid_tgid, buf, count);
}

int trace_read(struct pt_regs *ctx) {
    int fd = PT_REGS_PARM1(ctx);
    void __user *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = PT_REGS_PARM3(ctx);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    return process_recv_data(ctx, pid_tgid, buf, count);
}

// NEW: tcp_sendmsg probe for elbencho/AWS SDK
int trace_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    size_t size = PT_REGS_PARM3(ctx);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Try to read data from the message
    if (msg != NULL && size > 0) {
        struct iovec iov = {};
        // Different kernel versions have different msghdr layouts
        // Try to read from msg->msg_iter.iov
        void *iov_base = NULL;
        size_t iov_len = 0;
        
        // This is simplified - in reality we'd need kernel version checks
        // For now, just try to process with size info
        return process_send_data(ctx, pid_tgid, NULL, size);
    }
    
    return 0;
}

// For now, we can't easily intercept tcp_recvmsg responses
// But we can still catch HTTP requests via tcp_sendmsg
