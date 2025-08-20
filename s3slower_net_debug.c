#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>

// Configuration - will be replaced by Python
#define TARGET_PID TARGET_PID_PLACEHOLDER
#define MIN_LATENCY_US MIN_LATENCY_PLACEHOLDER

// Client type constants
#define CLIENT_UNKNOWN 0
#define CLIENT_WARP 1
#define CLIENT_ELBENCHO 2
#define CLIENT_BOTO3 3
#define CLIENT_S3CMD 4
#define CLIENT_AWSCLI 5

// Debug event types
#define DEBUG_WRITE_SEEN 1
#define DEBUG_HTTP_REQUEST 2
#define DEBUG_READ_SEEN 3
#define DEBUG_HTTP_RESPONSE 4
#define DEBUG_SENDTO_SEEN 5
#define DEBUG_RECVFROM_SEEN 6
#define DEBUG_SENDMSG_SEEN 7
#define DEBUG_RECVMSG_SEEN 8

struct debug_event_t {
    u64 ts_us;
    u32 pid;
    u32 tid;
    u32 fd;
    char comm[TASK_COMM_LEN];
    u8 event_type;
    u8 client_type;
    u32 size;
    char data[64];
};

BPF_PERF_OUTPUT(debug_events);

// Detect S3 client type from process name
static u8 detect_client_type(const char *comm) {
    // warp client detection
    if (comm[0] == 'w' && comm[1] == 'a' && comm[2] == 'r' && comm[3] == 'p') {
        return CLIENT_WARP;
    }
    
    // elbencho client detection
    if (comm[0] == 'e' && comm[1] == 'l' && comm[2] == 'b' && comm[3] == 'e' && 
        comm[4] == 'n' && comm[5] == 'c' && comm[6] == 'h' && comm[7] == 'o') {
        return CLIENT_ELBENCHO;
    }
    
    // python (boto3 typically runs in python)
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't' && comm[3] == 'h' && 
        comm[4] == 'o' && comm[5] == 'n') {
        return CLIENT_BOTO3;
    }
    
    // s3cmd client detection
    if (comm[0] == 's' && comm[1] == '3' && comm[2] == 'c' && comm[3] == 'm' && comm[4] == 'd') {
        return CLIENT_S3CMD;
    }
    
    // aws cli detection
    if (comm[0] == 'a' && comm[1] == 'w' && comm[2] == 's') {
        return CLIENT_AWSCLI;
    }
    
    return CLIENT_UNKNOWN;
}

// Helper to emit debug event
static void emit_debug_event(struct pt_regs *ctx, u8 event_type, int fd, size_t size, const void *buf) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    // Get process name
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    u8 client_type = detect_client_type(comm);
    
    // Only emit for known clients
    if (client_type == CLIENT_UNKNOWN) return;
    
    struct debug_event_t debug = {};
    debug.ts_us = bpf_ktime_get_ns() / 1000;
    debug.pid = pid;
    debug.tid = tid;
    debug.fd = fd;
    debug.event_type = event_type;
    debug.client_type = client_type;
    debug.size = size;
    
    #pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        debug.comm[i] = comm[i];
    }
    
    // Try to read some data if available
    if (buf && size > 0) {
        bpf_probe_read_user(debug.data, sizeof(debug.data), buf);
    }
    
    debug_events.perf_submit(ctx, &debug, sizeof(debug));
}

// Trace sendto syscall (commonly used by AWS SDK)
int trace_sendto(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // PID filtering
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    int fd = (int)ctx->di;
    const void __user *buf = (const void *)ctx->si;
    size_t len = (size_t)ctx->dx;
    
    // Skip small packets and stdout/stderr
    if (fd <= 2 || len < 4) return 0;
    
    emit_debug_event(ctx, DEBUG_SENDTO_SEEN, fd, len, buf);
    return 0;
}

// Trace recvfrom syscall
int trace_recvfrom(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // PID filtering
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    int fd = (int)ctx->di;
    void __user *buf = (void *)ctx->si;
    size_t len = (size_t)ctx->dx;
    
    // Skip small packets and stdout/stderr
    if (fd <= 2 || len < 4) return 0;
    
    emit_debug_event(ctx, DEBUG_RECVFROM_SEEN, fd, len, buf);
    return 0;
}

// Trace sendmsg syscall (also used for network I/O)
int trace_sendmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // PID filtering
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    int fd = (int)ctx->di;
    
    // Skip stdout/stderr
    if (fd <= 2) return 0;
    
    emit_debug_event(ctx, DEBUG_SENDMSG_SEEN, fd, 0, NULL);
    return 0;
}

// Trace recvmsg syscall
int trace_recvmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // PID filtering
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    int fd = (int)ctx->di;
    
    // Skip stdout/stderr
    if (fd <= 2) return 0;
    
    emit_debug_event(ctx, DEBUG_RECVMSG_SEEN, fd, 0, NULL);
    return 0;
}

// Still trace write/read for comparison
int trace_write(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // PID filtering
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    unsigned int fd = (unsigned int)ctx->di;
    const char __user *buf = (const char *)ctx->si;
    size_t count = (size_t)ctx->dx;
    
    // Skip stdout/stderr and small writes
    if (fd <= 2 || count < 4) return 0;
    
    emit_debug_event(ctx, DEBUG_WRITE_SEEN, fd, count, buf);
    return 0;
}

int trace_read(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // PID filtering
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    int fd = (int)ctx->di;
    void __user *buf = (void *)ctx->si;
    size_t count = (size_t)ctx->dx;
    
    // Skip stdout/stderr and small reads
    if (fd <= 2 || count < 4) return 0;
    
    emit_debug_event(ctx, DEBUG_READ_SEEN, fd, count, buf);
    return 0;
}
