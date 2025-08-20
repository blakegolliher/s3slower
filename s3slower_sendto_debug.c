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

struct debug_event_t {
    u64 ts_us;
    u32 pid;
    u32 tid;
    u32 fd;
    char comm[TASK_COMM_LEN];
    u8 client_type;
    u32 size;
    char data[256];  // Larger buffer for HTTP headers
};

BPF_PERF_OUTPUT(debug_events);

// Detect S3 client type from process name
static u8 detect_client_type(const char *comm) {
    if (comm[0] == 'w' && comm[1] == 'a' && comm[2] == 'r' && comm[3] == 'p') {
        return CLIENT_WARP;
    }
    
    if (comm[0] == 'e' && comm[1] == 'l' && comm[2] == 'b' && comm[3] == 'e' && 
        comm[4] == 'n' && comm[5] == 'c' && comm[6] == 'h' && comm[7] == 'o') {
        return CLIENT_ELBENCHO;
    }
    
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't' && comm[3] == 'h' && 
        comm[4] == 'o' && comm[5] == 'n') {
        return CLIENT_BOTO3;
    }
    
    if (comm[0] == 's' && comm[1] == '3' && comm[2] == 'c' && comm[3] == 'm' && comm[4] == 'd') {
        return CLIENT_S3CMD;
    }
    
    if (comm[0] == 'a' && comm[1] == 'w' && comm[2] == 's') {
        return CLIENT_AWSCLI;
    }
    
    return CLIENT_UNKNOWN;
}

// sendto syscall entry - capture the data being sent
int trace_sendto_entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    // PID filtering
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    // Get process name
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    u8 client_type = detect_client_type(comm);
    
    // Only emit for known clients
    if (client_type == CLIENT_UNKNOWN) return 0;
    
    // Get syscall arguments properly
    int fd = (int)PT_REGS_PARM1(ctx);
    const void __user *buf = (const void *)PT_REGS_PARM2(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);
    
    // Skip if no data
    if (len == 0) return 0;
    
    struct debug_event_t debug = {};
    debug.ts_us = bpf_ktime_get_ns() / 1000;
    debug.pid = pid;
    debug.tid = tid;
    debug.fd = fd;
    debug.client_type = client_type;
    debug.size = len;
    
    #pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        debug.comm[i] = comm[i];
    }
    
    // Try to read the data being sent
    if (buf && len > 0) {
        u32 read_size = len < sizeof(debug.data) ? len : sizeof(debug.data);
        bpf_probe_read_user(debug.data, read_size, buf);
    }
    
    debug_events.perf_submit(ctx, &debug, sizeof(debug));
    return 0;
}

// write syscall for comparison
int trace_write(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    // PID filtering
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    // Get process name
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    u8 client_type = detect_client_type(comm);
    
    // Only emit for known clients
    if (client_type == CLIENT_UNKNOWN) return 0;
    
    // Get syscall arguments
    int fd = (int)PT_REGS_PARM1(ctx);
    const void __user *buf = (const void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    
    // Skip stdout/stderr and small writes
    if (fd <= 2 || count < 10) return 0;
    
    struct debug_event_t debug = {};
    debug.ts_us = bpf_ktime_get_ns() / 1000;
    debug.pid = pid;
    debug.tid = tid;
    debug.fd = fd;
    debug.client_type = client_type;
    debug.size = count;
    
    #pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        debug.comm[i] = comm[i];
    }
    
    // Try to read the data
    if (buf && count > 0) {
        u32 read_size = count < sizeof(debug.data) ? count : sizeof(debug.data);
        bpf_probe_read_user(debug.data, read_size, buf);
    }
    
    debug_events.perf_submit(ctx, &debug, sizeof(debug));
    return 0;
}
