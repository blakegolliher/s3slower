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

// Enhanced buffer size for better HTTP header capture
#define MAX_BUFFER_SIZE 256

struct request_t {
    u64 start_ts;
    u32 fd;
    u32 total_req_size;  // Track total request size across syscalls
    u32 total_resp_size; // Track total response size
    u8 is_multipart;     // Flag if request spans multiple syscalls
    u8 detected_s3;      // Flag if S3-specific patterns detected
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
    u32 actual_resp_bytes; // Actual bytes returned by read()
    u8 is_partial;         // Flag if this might be partial data
    u8 client_type;        // Client type detected from comm and patterns
    u8 detected_s3;        // Flag if S3-specific patterns detected
    char data[MAX_BUFFER_SIZE];
};

BPF_HASH(requests, u64, struct request_t);
BPF_HASH(ongoing_requests, u64, u32); // Track ongoing multi-part requests
BPF_HASH(read_contexts, u64, struct event_t); // Store event context for kretprobe
BPF_PERF_OUTPUT(events);

// Enhanced HTTP method detection - check more methods and patterns
static int is_http_request(const char *data, int len) {
    if (len < 4) return 0;
    
    // Standard methods
    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') return 1;
    if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') return 1;
    if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') return 1;
    if (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') return 1;
    if (data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E') return 1;
    
    // Additional methods that S3 might use
    if (len >= 5) {
        if (data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C' && data[4] == 'H') return 1;
    }
    if (len >= 7) {
        if (data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I' && 
            data[4] == 'O' && data[5] == 'N' && data[6] == 'S') return 1;
    }
    
    return 0;
}

static int is_http_response(const char *data, int len) {
    if (len < 4) return 0;
    if (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P') return 1;
    return 0;
}

// Detect S3-specific patterns in HTTP headers
static int detect_s3_patterns(const char *data, int len) {
    if (len < 20) return 0;
    
    // Look for S3-specific headers or patterns
    // This is a simplified check - we're looking for common S3 patterns
    #pragma unroll
    for (int i = 0; i < 200 && i < len - 10; i++) {
        // Check for "Host: " header pointing to S3-like endpoints
        if (data[i] == 'H' && data[i+1] == 'o' && data[i+2] == 's' && 
            data[i+3] == 't' && data[i+4] == ':' && data[i+5] == ' ') {
            return 1;  // Found Host header - likely S3 traffic
        }
        
        // Check for x-amz- headers (S3-specific)
        if (i < len - 6 && data[i] == 'x' && data[i+1] == '-' && 
            data[i+2] == 'a' && data[i+3] == 'm' && data[i+4] == 'z' && data[i+5] == '-') {
            return 1;
        }
        
        // Check for "bucket" in URL path (common S3 pattern)
        if (i < len - 6 && data[i] == 'b' && data[i+1] == 'u' && 
            data[i+2] == 'c' && data[i+3] == 'k' && data[i+4] == 'e' && data[i+5] == 't') {
            return 1;
        }
        
        // Check for "warp-benchmark" which is the bucket name in the elbencho command
        if (i < len - 14 && data[i] == 'w' && data[i+1] == 'a' && data[i+2] == 'r' && 
            data[i+3] == 'p' && data[i+4] == '-' && data[i+5] == 'b' && 
            data[i+6] == 'e' && data[i+7] == 'n' && data[i+8] == 'c' && 
            data[i+9] == 'h' && data[i+10] == 'm' && data[i+11] == 'a' && 
            data[i+12] == 'r' && data[i+13] == 'k') {
            return 1;
        }
    }
    
    return 0;
}

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

int trace_write(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    // PID filtering - will be configured by Python
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;

    // Use same syscall argument access pattern as original
    unsigned int fd = (unsigned int)ctx->di;
    const char __user *buf = (const char *)ctx->si;
    size_t count = (size_t)ctx->dx;

    if (count < 4) return 0;  // Too small to be HTTP

    // Read larger buffer for better header detection
    char data[MAX_BUFFER_SIZE] = {};
    int read_size = count < MAX_BUFFER_SIZE ? count : MAX_BUFFER_SIZE;
    if (bpf_probe_read_user(data, read_size, buf) != 0) return 0;

    u64 key = ((u64)pid << 32) | fd;

    // Check if this is a new HTTP request
    if (is_http_request(data, read_size)) {
        struct request_t req = {};
        req.start_ts = bpf_ktime_get_ns();
        req.fd = fd;
        req.total_req_size = (u32)count;
        req.is_multipart = 0;
        req.detected_s3 = detect_s3_patterns(data, read_size);

        // Copy data safely
        #pragma unroll
        for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
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
                
                // Check for S3 patterns in continuation data if not already detected
                if (!req->detected_s3) {
                    req->detected_s3 = detect_s3_patterns(data, read_size);
                }
            }
        } else {
            // Even if not a standard HTTP start, check if it could be S3 traffic
            // This helps catch cases where HTTP headers are fragmented
            if (detect_s3_patterns(data, read_size)) {
                struct request_t req = {};
                req.start_ts = bpf_ktime_get_ns();
                req.fd = fd;
                req.total_req_size = (u32)count;
                req.is_multipart = 1;  // Mark as multipart since we didn't see the start
                req.detected_s3 = 1;

                // Copy data safely
                #pragma unroll
                for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
                    req.data[i] = data[i];
                }

                requests.update(&key, &req);
                u32 count_u32 = (u32)count;
                ongoing_requests.update(&key, &count_u32);
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

    // Use same syscall argument access pattern as original
    int fd = (int)ctx->di;
    void __user *buf = (void *)ctx->si;
    size_t count = (size_t)ctx->dx;

    if (count < 4) return 0;

    char data[MAX_BUFFER_SIZE] = {};
    int read_size = count < MAX_BUFFER_SIZE ? count : MAX_BUFFER_SIZE;
    if (bpf_probe_read_user(data, read_size, buf) != 0) return 0;

    u64 key = ((u64)pid << 32) | fd;
    struct request_t *req = requests.lookup(&key);
    
    // Check process name to see if it's elbencho
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    u8 client_type = detect_client_type(comm);
    
    // For elbencho, be more aggressive about detecting S3 traffic
    int is_elbencho = (client_type == CLIENT_ELBENCHO);
    
    // If we have a tracked request OR this is an HTTP response OR it's elbencho with S3 patterns
    if (req || is_http_response(data, read_size) || 
        (is_elbencho && detect_s3_patterns(data, read_size))) {
        
        u64 end_ts = bpf_ktime_get_ns();
        u64 latency_us = 0;
        
        if (req) {
            latency_us = (end_ts - req->start_ts) / 1000;
            if (latency_us < MIN_LATENCY_US) return 0;
        }

        struct event_t event = {};
        event.ts_us = end_ts / 1000;
        event.latency_us = latency_us;
        event.pid = pid;
        event.tid = tid;
        event.fd = fd;
        event.req_size = req ? req->total_req_size : 0;
        event.resp_size = count;
        event.actual_resp_bytes = 0;  // Will be filled in kretprobe
        event.is_partial = req ? req->is_multipart : 0;
        event.detected_s3 = req ? req->detected_s3 : detect_s3_patterns(data, read_size);
        event.client_type = client_type;

        // Copy comm
        #pragma unroll
        for (int i = 0; i < TASK_COMM_LEN; i++) {
            event.comm[i] = comm[i];
        }

        // Copy request data if available, otherwise use response data
        if (req) {
            #pragma unroll
            for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
                event.data[i] = req->data[i];
            }
        } else {
            #pragma unroll
            for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
                event.data[i] = data[i];
            }
        }

        // Store context for kretprobe to get actual bytes read
        read_contexts.update(&pid_tgid, &event);
        
        // Clean up request tracking
        if (req) {
            requests.delete(&key);
            ongoing_requests.delete(&key);
        }
    }

    return 0;
}

int trace_read_ret(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    ssize_t ret = PT_REGS_RC(ctx);
    
    // Only process successful reads
    if (ret <= 0) {
        read_contexts.delete(&pid_tgid);
        return 0;
    }
    
    struct event_t *event = read_contexts.lookup(&pid_tgid);
    if (!event) return 0;
    
    // Update actual bytes read
    event->actual_resp_bytes = (u32)ret;
    
    // Submit the event with actual byte count
    events.perf_submit(ctx, event, sizeof(struct event_t));
    
    // Clean up
    read_contexts.delete(&pid_tgid);
    
    return 0;
}
