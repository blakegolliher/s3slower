#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/tcp.h>

// Configuration - will be replaced by Python
#define TARGET_PID 0
#define MIN_LATENCY_US 0
#define MAX_BUFFER_SIZE 256  // Reduced from 512 to save stack space
#define MAX_HTTP_SEGMENTS 4  // Reduced from 8 to save stack space

// HTTP method detection - comprehensive list
enum http_method {
    HTTP_UNKNOWN = 0,
    HTTP_GET = 1,
    HTTP_PUT = 2,
    HTTP_POST = 3,
    HTTP_DELETE = 4,
    HTTP_HEAD = 5,
    HTTP_OPTIONS = 6,
    HTTP_PATCH = 7,
    HTTP_CONNECT = 8,
    HTTP_TRACE = 9,
};

// State machine for tracking partial HTTP headers
enum http_state {
    STATE_INIT = 0,
    STATE_METHOD_PARTIAL = 1,  // Partial method seen
    STATE_METHOD_COMPLETE = 2, // Full method + space seen
    STATE_URL_PARTIAL = 3,     // Collecting URL
    STATE_HEADERS_PARTIAL = 4, // Collecting headers
    STATE_COMPLETE = 5,        // Full request seen
};

struct http_segment {
    u32 offset;     // Offset in the full HTTP request
    u32 len;        // Length of this segment
    char data[MAX_BUFFER_SIZE];
};

struct request_state {
    u64 start_ts;
    u32 fd;
    u32 total_req_size;
    u32 total_resp_size;
    u8 http_method;          // Detected HTTP method
    u8 state;                // HTTP parsing state
    u8 num_segments;         // Number of segments collected
    u8 is_s3;               // S3-specific request detected
    u16 url_offset;          // Offset where URL starts
    u16 url_len;             // Length of URL
    struct http_segment segments[MAX_HTTP_SEGMENTS];
    char s3_headers[128];    // Reduced from 256 to save stack space
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
    char url[128];           // Reduced from 256 to save stack space
    char s3_operation[32];   // Reduced from 64 to save stack space
    char data[MAX_BUFFER_SIZE]; // First segment data
};

BPF_HASH(request_states, u64, struct request_state);
BPF_PERF_OUTPUT(events);

// Enhanced HTTP method detection with partial matching
static inline u8 detect_http_method(const char *data, u32 len) {
    if (len < 3) return HTTP_UNKNOWN;
    
    // Check for each HTTP method
    if (data[0] == 'G' && len >= 3) {
        if (data[1] == 'E' && data[2] == 'T') return HTTP_GET;
    } else if (data[0] == 'P' && len >= 3) {
        if (data[1] == 'U' && data[2] == 'T') return HTTP_PUT;
        if (data[1] == 'O' && data[2] == 'S' && len >= 4 && data[3] == 'T') return HTTP_POST;
        if (data[1] == 'A' && data[2] == 'T' && len >= 5 && data[3] == 'C' && data[4] == 'H') return HTTP_PATCH;
    } else if (data[0] == 'D' && len >= 6) {
        if (data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && data[4] == 'T' && data[5] == 'E') return HTTP_DELETE;
    } else if (data[0] == 'H' && len >= 4) {
        if (data[1] == 'E' && data[2] == 'A' && data[3] == 'D') return HTTP_HEAD;
        if (data[1] == 'T' && data[2] == 'T' && data[3] == 'P') return HTTP_UNKNOWN; // Response
    } else if (data[0] == 'O' && len >= 7) {
        if (data[1] == 'P' && data[2] == 'T' && data[3] == 'I' && data[4] == 'O' && data[5] == 'N' && data[6] == 'S') return HTTP_OPTIONS;
    } else if (data[0] == 'C' && len >= 7) {
        if (data[1] == 'O' && data[2] == 'N' && data[3] == 'N' && data[4] == 'E' && data[5] == 'C' && data[6] == 'T') return HTTP_CONNECT;
    } else if (data[0] == 'T' && len >= 5) {
        if (data[1] == 'R' && data[2] == 'A' && data[3] == 'C' && data[4] == 'E') return HTTP_TRACE;
    }
    
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

// S3 pattern detection
static inline int detect_s3_patterns(const char *data, u32 len, struct request_state *state) {
    if (len < 10) return 0;
    
    // Check for S3-specific headers
    for (int i = 0; i < len - 10; i++) {
        // x-amz-* headers
        if (data[i] == 'x' && data[i+1] == '-' && data[i+2] == 'a' && 
            data[i+3] == 'm' && data[i+4] == 'z' && data[i+5] == '-') {
            return 1;
        }
        
        // Authorization: AWS4-HMAC-SHA256
        if (data[i] == 'A' && data[i+1] == 'u' && data[i+2] == 't' && 
            data[i+3] == 'h' && data[i+4] == 'o' && data[i+5] == 'r' && 
            data[i+6] == 'i' && data[i+7] == 'z' && data[i+8] == 'a' && 
            data[i+9] == 't' && data[i+10] == 'i' && data[i+11] == 'o' && 
            data[i+12] == 'n') {
            return 1;
        }
    }
    
    return 0;
}

// S3 URL pattern detection
static inline int is_s3_url_pattern(const char *data, u32 len) {
    if (len < 5) return 0;
    
    // Look for S3 URL patterns
    for (int i = 0; i < len - 5; i++) {
        // /bucket/key pattern
        if (data[i] == '/' && data[i+1] != '/' && data[i+1] != '?') {
            // Look for second slash (key part)
            for (int j = i + 1; j < len; j++) {
                if (data[j] == '/') return 1;
                if (data[j] == ' ' || data[j] == '\r' || data[j] == '\n') break;
            }
        }
        
        // Query parameters like ?partNumber=
        if (data[i] == '?' && data[i+1] == 'p' && data[i+2] == 'a' && 
            data[i+3] == 'r' && data[i+4] == 't' && data[i+5] == 'N' && 
            data[i+6] == 'u' && data[i+7] == 'm' && data[i+8] == 'b' && 
            data[i+9] == 'e' && data[i+10] == 'r') {
            return 1;
        }
    }
    
    return 0;
}

// Helper function to handle write operations - must be static inline for BPF
static inline int handle_write_operation(struct pt_regs *ctx, int fd, const char __user *buf, size_t count) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    // Use smaller buffer to save stack space
    char data[MAX_BUFFER_SIZE];
    // Manual zeroing
    #pragma unroll
    for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
        data[i] = 0;
    }
    
    u32 read_size = count > sizeof(data) ? sizeof(data) : count;
    if (bpf_probe_read_user(data, read_size, buf) != 0) return 0;
    
    if (!is_http_request(data, read_size)) return 0;
    
    u8 method = detect_http_method(data, read_size);
    if (method == HTTP_UNKNOWN) return 0;
    
    u64 key = ((u64)pid << 32) | fd;
    struct request_state *state = request_states.lookup(&key);
    
    if (!state) {
        // New request - use smaller struct to save stack
        struct request_state new_state;
        // Manual zeroing - initialize each field individually
        new_state.start_ts = 0;
        new_state.fd = 0;
        new_state.total_req_size = 0;
        new_state.total_resp_size = 0;
        new_state.http_method = 0;
        new_state.state = 0;
        new_state.num_segments = 0;
        new_state.is_s3 = 0;
        new_state.url_offset = 0;
        new_state.url_len = 0;
        
        // Zero out segments array
        #pragma unroll
        for (int i = 0; i < MAX_HTTP_SEGMENTS; i++) {
            new_state.segments[i].offset = 0;
            new_state.segments[i].len = 0;
            #pragma unroll
            for (int j = 0; j < MAX_BUFFER_SIZE; j++) {
                new_state.segments[i].data[j] = 0;
            }
        }
        
        // Zero out s3_headers
        #pragma unroll
        for (int i = 0; i < 128; i++) {
            new_state.s3_headers[i] = 0;
        }
        
        new_state.start_ts = bpf_ktime_get_ns();
        new_state.fd = fd;
        new_state.total_req_size = count;
        new_state.http_method = method;
        new_state.state = STATE_METHOD_COMPLETE;
        new_state.num_segments = 1;
        
        // Store first segment
        new_state.segments[0].offset = 0;
        new_state.segments[0].len = read_size;
        // Manual copy to avoid memcpy issues
        #pragma unroll
        for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
            if (i < read_size) {
                new_state.segments[0].data[i] = data[i];
            }
        }
        
        // Check for S3 patterns
        new_state.is_s3 = detect_s3_patterns(data, read_size, &new_state);
        
        // Extract URL if visible in first segment
        int url_start = -1;
        for (int i = 0; i < read_size; i++) {
            if (data[i] == ' ' && url_start == -1) {
                url_start = i + 1;
                new_state.url_offset = url_start;
            } else if (data[i] == ' ' && url_start != -1) {
                new_state.url_len = i - url_start;
                break;
            }
        }
        
        // Check for S3 URL patterns
        if (new_state.url_len > 0) {
            new_state.is_s3 |= is_s3_url_pattern(&data[new_state.url_offset], new_state.url_len);
        }
        
        request_states.update(&key, &new_state);
    } else {
        // Continuation of existing request
        if (state->num_segments < MAX_HTTP_SEGMENTS) {
            u8 seg_idx = state->num_segments;
            state->segments[seg_idx].offset = state->total_req_size - count;
            state->segments[seg_idx].len = read_size;
            // Manual copy to avoid memcpy issues
            #pragma unroll
            for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
                if (i < read_size) {
                    state->segments[seg_idx].data[i] = data[i];
                }
            }
            state->num_segments++;
            
            // Check for S3 patterns in new segment
            if (!state->is_s3) {
                state->is_s3 = detect_s3_patterns(data, read_size, state);
            }
        }
    }
    
    return 0;
}

// Helper function to handle read operations - must be static inline for BPF
static inline int handle_read_operation(struct pt_regs *ctx, int fd, void __user *buf, size_t count) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    // Use smaller buffer to save stack space
    char data[MAX_BUFFER_SIZE];
    // Manual zeroing
    #pragma unroll
    for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
        data[i] = 0;
    }
    
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
    // Zero out critical fields - initialize each field individually
    event.ts_us = 0;
    event.latency_us = 0;
    event.pid = 0;
    event.tid = 0;
    event.fd = 0;
    event.req_size = 0;
    event.resp_size = 0;
    event.http_method = 0;
    event.is_s3 = 0;
    event.num_segments = 0;
    
    // Zero out comm
    #pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        event.comm[i] = 0;
    }
    
    // Zero out url
    #pragma unroll
    for (int i = 0; i < 128; i++) {
        event.url[i] = 0;
    }
    
    // Zero out s3_operation
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        event.s3_operation[i] = 0;
    }
    
    // Zero out data
    #pragma unroll
    for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
        event.data[i] = 0;
    }
    
    event.ts_us = end_ts / 1000;
    event.latency_us = latency_us;
    event.pid = pid;
    event.tid = tid;
    event.fd = fd;
    event.req_size = state->total_req_size;
    event.resp_size = count;
    event.http_method = state->http_method;
    event.is_s3 = state->is_s3;
    event.num_segments = state->num_segments;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Extract URL from segments
    if (state->url_len > 0 && state->url_offset < MAX_BUFFER_SIZE) {
        u32 url_end = state->url_offset + state->url_len;
        if (url_end <= MAX_BUFFER_SIZE) {
            u32 copy_len = state->url_len < 128 ? state->url_len : 127;
            #pragma unroll
            for (int i = 0; i < 128; i++) {
                if (i < copy_len) {
                    event.url[i] = state->segments[0].data[state->url_offset + i];
                }
            }
        }
    }
    
    // Copy first segment data
    u32 data_len = state->segments[0].len;
    #pragma unroll
    for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
        if (i < data_len) {
            event.data[i] = state->segments[0].data[i];
        }
    }
    
    // Determine S3 operation type from URL and method
    if (state->is_s3) {
        if (state->http_method == HTTP_GET) {
            char op[] = "GetObject";
            #pragma unroll
            for (int i = 0; i < 10; i++) { event.s3_operation[i] = op[i]; }
        } else if (state->http_method == HTTP_PUT) {
            char op[] = "PutObject";
            #pragma unroll
            for (int i = 0; i < 10; i++) { event.s3_operation[i] = op[i]; }
        } else if (state->http_method == HTTP_DELETE) {
            char op[] = "DeleteObject";
            #pragma unroll
            for (int i = 0; i < 12; i++) { event.s3_operation[i] = op[i]; }
        } else if (state->http_method == HTTP_HEAD) {
            char op[] = "HeadObject";
            #pragma unroll
            for (int i = 0; i < 11; i++) { event.s3_operation[i] = op[i]; }
        } else if (state->http_method == HTTP_POST) {
            char op[] = "PostObject";
            #pragma unroll
            for (int i = 0; i < 11; i++) { event.s3_operation[i] = op[i]; }
        }
    }
    
    events.perf_submit(ctx, &event, sizeof(event));
    request_states.delete(&key);
    return 0;
}

// Trace write syscall
int trace_write(struct pt_regs *ctx, int fd, const char __user *buf, size_t count) {
    return handle_write_operation(ctx, fd, buf, count);
}

// Trace send syscall
int trace_send(struct pt_regs *ctx, int fd, const char __user *buf, size_t len, int flags) {
    return handle_write_operation(ctx, fd, buf, len);
}

// Trace sendto syscall
int trace_sendto(struct pt_regs *ctx, int fd, const char __user *buf, size_t len, int flags, 
                 const struct sockaddr __user *dest_addr, int addrlen) {
    return handle_write_operation(ctx, fd, buf, len);
}

// Trace sendmsg syscall
int trace_sendmsg(struct pt_regs *ctx, int fd, const struct msghdr __user *msg, int flags) {
    // For sendmsg, we can't easily extract the buffer, so just track the call
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    return 0;
}

// Trace tcp_sendmsg for TCP-level detection
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    // TCP-level hook - just track for now
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    return 0;
}

// Trace read syscall
int trace_read(struct pt_regs *ctx, int fd, void __user *buf, size_t count) {
    return handle_read_operation(ctx, fd, buf, count);
}

// Trace recv syscall
int trace_recv(struct pt_regs *ctx, int fd, void __user *buf, size_t len, int flags) {
    return handle_read_operation(ctx, fd, buf, len);
}

// Trace recvfrom syscall
int trace_recvfrom(struct pt_regs *ctx, int fd, void __user *buf, size_t len, int flags,
                   struct sockaddr __user *src_addr, int __user *addrlen) {
    return handle_read_operation(ctx, fd, buf, len);
}

// Trace recvmsg syscall
int trace_recvmsg(struct pt_regs *ctx, int fd, struct msghdr __user *msg, int flags) {
    // For recvmsg, we can't easily extract the buffer, so just track the call
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    return 0;
}
