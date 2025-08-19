#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/tcp.h>

// Configuration - will be replaced by Python
#define TARGET_PID 0
#define MIN_LATENCY_US 0
#define MAX_BUFFER_SIZE 512  // Increased from 64 to capture more data
#define MAX_HTTP_SEGMENTS 8  // Track up to 8 segments of a fragmented request

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
    char s3_headers[256];    // Store S3-specific headers
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
    char url[256];           // Extracted URL
    char s3_operation[64];   // S3 operation type
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

// Check if this is an HTTP response
static inline int is_http_response(const char *data, u32 len) {
    return (len >= 4 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P');
}

// Enhanced S3-specific detection
static inline int detect_s3_patterns(const char *data, u32 len, struct request_state *state) {
    int is_s3 = 0;
    
    // Look for S3-specific headers
    #pragma unroll
    for (int i = 0; i < len - 10; i++) {
        // Check for x-amz- headers
        if (i + 6 < len && data[i] == 'x' && data[i+1] == '-' && data[i+2] == 'a' && 
            data[i+3] == 'm' && data[i+4] == 'z' && data[i+5] == '-') {
            is_s3 = 1;
            
            // Try to capture the header name
            int j = i;
            int k = 0;
            while (j < len && k < 255 && data[j] != '\r' && data[j] != '\n') {
                state->s3_headers[k++] = data[j++];
            }
            state->s3_headers[k] = '\0';
            break;
        }
        
        // Check for AWS4-HMAC-SHA256 authorization
        if (i + 16 < len && data[i] == 'A' && data[i+1] == 'W' && data[i+2] == 'S' && 
            data[i+3] == '4' && data[i+4] == '-' && data[i+5] == 'H' && data[i+6] == 'M' &&
            data[i+7] == 'A' && data[i+8] == 'C' && data[i+9] == '-' && data[i+10] == 'S' &&
            data[i+11] == 'H' && data[i+12] == 'A' && data[i+13] == '2' && data[i+14] == '5' &&
            data[i+15] == '6') {
            is_s3 = 1;
            break;
        }
        
        // Check for S3 URL patterns (simplified)
        if (i + 7 < len && data[i] == '/' && data[i+1] != ' ' && data[i+1] != '/') {
            // Look for ?partNumber= or ?uploadId= patterns
            int j = i;
            while (j < len - 12) {
                if (data[j] == '?' && (
                    (data[j+1] == 'p' && data[j+2] == 'a' && data[j+3] == 'r' && data[j+4] == 't') ||
                    (data[j+1] == 'u' && data[j+2] == 'p' && data[j+3] == 'l' && data[j+4] == 'o'))) {
                    is_s3 = 1;
                    break;
                }
                j++;
            }
        }
    }
    
    return is_s3;
}

// Helper function to handle write/send operations
static inline int handle_write_operation(struct pt_regs *ctx, u32 fd, const char __user *buf, size_t count) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    // PID filtering
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    if (count < 3) return 0;  // Too small to be HTTP
    
    char data[MAX_BUFFER_SIZE] = {};
    u32 read_size = count > sizeof(data) ? sizeof(data) : count;
    if (bpf_probe_read_user(data, read_size, buf) != 0) return 0;
    
    u64 key = ((u64)pid << 32) | fd;
    struct request_state *state = request_states.lookup(&key);
    
    if (!state) {
        // Check if this is a new HTTP request
        u8 method = detect_http_method(data, read_size);
        if (method == HTTP_UNKNOWN) return 0;
        
        // Initialize new request state
        struct request_state new_state = {};
        new_state.start_ts = bpf_ktime_get_ns();
        new_state.fd = fd;
        new_state.total_req_size = count;
        new_state.http_method = method;
        new_state.state = STATE_METHOD_COMPLETE;
        new_state.num_segments = 1;
        
        // Store first segment
        new_state.segments[0].offset = 0;
        new_state.segments[0].len = read_size;
        __builtin_memcpy(new_state.segments[0].data, data, read_size);
        
        // Check for S3 patterns
        new_state.is_s3 = detect_s3_patterns(data, read_size, &new_state);
        
        // Extract URL if visible in first segment
        int url_start = -1;
        #pragma unroll
        for (int i = 0; i < read_size - 1; i++) {
            if (data[i] == ' ' && url_start == -1) {
                url_start = i + 1;
                new_state.url_offset = url_start;
            } else if (data[i] == ' ' && url_start != -1) {
                new_state.url_len = i - url_start;
                break;
            }
        }
        
        request_states.update(&key, &new_state);
    } else {
        // Continuation of existing request
        state->total_req_size += count;
        
        // Add new segment if we have space
        if (state->num_segments < MAX_HTTP_SEGMENTS) {
            u8 seg_idx = state->num_segments;
            state->segments[seg_idx].offset = state->total_req_size - count;
            state->segments[seg_idx].len = read_size;
            __builtin_memcpy(state->segments[seg_idx].data, data, read_size);
            state->num_segments++;
            
            // Check for S3 patterns in new segment
            if (!state->is_s3) {
                state->is_s3 = detect_s3_patterns(data, read_size, state);
            }
        }
    }
    
    return 0;
}

// Trace write() syscalls
int trace_write(struct pt_regs *ctx) {
    unsigned int fd = (unsigned int)ctx->di;
    const char __user *buf = (const char *)ctx->si;
    size_t count = (size_t)ctx->dx;
    
    return handle_write_operation(ctx, fd, buf, count);
}

// Trace send() syscalls
int trace_send(struct pt_regs *ctx) {
    int fd = (int)ctx->di;
    const void __user *buf = (const void *)ctx->si;
    size_t len = (size_t)ctx->dx;
    
    return handle_write_operation(ctx, fd, buf, len);
}

// Trace sendto() syscalls
int trace_sendto(struct pt_regs *ctx) {
    int fd = (int)ctx->di;
    const void __user *buf = (const void *)ctx->si;
    size_t len = (size_t)ctx->dx;
    
    return handle_write_operation(ctx, fd, buf, len);
}

// Trace sendmsg() syscalls
int trace_sendmsg(struct pt_regs *ctx) {
    int fd = (int)ctx->di;
    // Note: sendmsg is more complex, simplified here
    return 0;
}

// TCP-level probe for tcp_sendmsg
int trace_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)ctx->di;
    struct msghdr *msg = (struct msghdr *)ctx->si;
    size_t size = (size_t)ctx->dx;
    
    if (!sk || !msg || size < 4) return 0;
    
    // Extract socket info to correlate with fd
    // This is more complex in real implementation
    
    return 0;
}

// Helper function to handle read operations - must be static inline for BPF
static inline int handle_read_operation(struct pt_regs *ctx, int fd, void __user *buf, size_t count) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    if (TARGET_PID != 0 && pid != TARGET_PID) return 0;
    
    if (count < 4) return 0;
    
    char data[MAX_BUFFER_SIZE] = {};
    u32 read_size = count > sizeof(data) ? sizeof(data) : count;
    if (bpf_probe_read_user(data, read_size, buf) != 0) return 0;
    
    if (!is_http_response(data, read_size)) return 0;
    
    u64 key = ((u64)pid << 32) | fd;
    struct request_state *state = request_states.lookup(&key);
    if (!state) return 0;
    
    u64 end_ts = bpf_ktime_get_ns();
    u64 latency_us = (end_ts - state->start_ts) / 1000;
    
    if (latency_us < MIN_LATENCY_US) return 0;
    
    // Prepare event
    struct event_t event = {};
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
            __builtin_memcpy(event.url, state->segments[0].data + state->url_offset, 
                           state->url_len < 256 ? state->url_len : 255);
        }
    }
    
    // Copy first segment data
    __builtin_memcpy(event.data, state->segments[0].data, state->segments[0].len);
    
    // Determine S3 operation type from URL and method
    if (state->is_s3) {
        if (state->http_method == HTTP_GET) {
            __builtin_memcpy(event.s3_operation, "GetObject", 10);
        } else if (state->http_method == HTTP_PUT) {
            __builtin_memcpy(event.s3_operation, "PutObject", 10);
        } else if (state->http_method == HTTP_DELETE) {
            __builtin_memcpy(event.s3_operation, "DeleteObject", 13);
        } else if (state->http_method == HTTP_HEAD) {
            __builtin_memcpy(event.s3_operation, "HeadObject", 11);
        } else if (state->http_method == HTTP_POST) {
            // Could be various operations - need to check URL
            if (state->url_len > 0) {
                // Simple heuristic - if URL contains "?uploads" it's multipart
                __builtin_memcpy(event.s3_operation, "PostObject", 11);
            }
        }
    }
    
    events.perf_submit(ctx, &event, sizeof(event));
    request_states.delete(&key);
    
    return 0;
}

// Enhanced read handler
int trace_read(struct pt_regs *ctx) {
    int fd = (int)ctx->di;
    void __user *buf = (void *)ctx->si;
    size_t count = (size_t)ctx->dx;
    
    return handle_read_operation(ctx, fd, buf, count);
}

// Similar handlers for recv, recvfrom, recvmsg...
int trace_recv(struct pt_regs *ctx) {
    int fd = (int)ctx->di;
    void __user *buf = (void *)ctx->si;
    size_t count = (size_t)ctx->dx;
    
    return handle_read_operation(ctx, fd, buf, count);
}

int trace_recvfrom(struct pt_regs *ctx) {
    int fd = (int)ctx->di;
    void __user *buf = (void *)ctx->si;
    size_t count = (size_t)ctx->dx;
    
    return handle_read_operation(ctx, fd, buf, count);
}
