#!/usr/bin/env python3
"""
Trace ALL network-related syscalls and kernel functions
"""

import os
import sys
import time
import logging
from bcc import BPF
import ctypes as ct

# Setup logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('trace_all')

# BPF program that traces everything
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u64 ts_us;
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    char syscall[32];
    u64 arg1;
    u64 arg2;
    u64 arg3;
};

BPF_PERF_OUTPUT(events);

// Helper to check if this is elbencho or boto3
static int is_target_process(char *comm) {
    // Check for elbencho
    if (comm[0] == 'e' && comm[1] == 'l' && comm[2] == 'b' && comm[3] == 'e' && 
        comm[4] == 'n' && comm[5] == 'c' && comm[6] == 'h' && comm[7] == 'o') {
        return 1;
    }
    
    // Check for python (boto3)
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't' && comm[3] == 'h' && 
        comm[4] == 'o' && comm[5] == 'n') {
        return 1;
    }
    
    // Check for warp
    if (comm[0] == 'w' && comm[1] == 'a' && comm[2] == 'r' && comm[3] == 'p') {
        return 1;
    }
    
    return 0;
}

// Generic probe function
static int trace_syscall(struct pt_regs *ctx, const char *name) {
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    
    if (!is_target_process(comm)) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct event_t event = {};
    event.ts_us = bpf_ktime_get_ns() / 1000;
    event.pid = pid_tgid >> 32;
    event.tid = (u32)pid_tgid;
    event.arg1 = PT_REGS_PARM1(ctx);
    event.arg2 = PT_REGS_PARM2(ctx);
    event.arg3 = PT_REGS_PARM3(ctx);
    
    __builtin_memcpy(event.comm, comm, TASK_COMM_LEN);
    __builtin_memcpy(event.syscall, name, 32);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Define trace functions for each syscall
int trace_write(struct pt_regs *ctx) { return trace_syscall(ctx, "write"); }
int trace_read(struct pt_regs *ctx) { return trace_syscall(ctx, "read"); }
int trace_send(struct pt_regs *ctx) { return trace_syscall(ctx, "send"); }
int trace_recv(struct pt_regs *ctx) { return trace_syscall(ctx, "recv"); }
int trace_sendto(struct pt_regs *ctx) { return trace_syscall(ctx, "sendto"); }
int trace_recvfrom(struct pt_regs *ctx) { return trace_syscall(ctx, "recvfrom"); }
int trace_sendmsg(struct pt_regs *ctx) { return trace_syscall(ctx, "sendmsg"); }
int trace_recvmsg(struct pt_regs *ctx) { return trace_syscall(ctx, "recvmsg"); }
int trace_sendmmsg(struct pt_regs *ctx) { return trace_syscall(ctx, "sendmmsg"); }
int trace_recvmmsg(struct pt_regs *ctx) { return trace_syscall(ctx, "recvmmsg"); }
int trace_writev(struct pt_regs *ctx) { return trace_syscall(ctx, "writev"); }
int trace_readv(struct pt_regs *ctx) { return trace_syscall(ctx, "readv"); }
int trace_pwrite64(struct pt_regs *ctx) { return trace_syscall(ctx, "pwrite64"); }
int trace_pread64(struct pt_regs *ctx) { return trace_syscall(ctx, "pread64"); }
int trace_pwritev(struct pt_regs *ctx) { return trace_syscall(ctx, "pwritev"); }
int trace_preadv(struct pt_regs *ctx) { return trace_syscall(ctx, "preadv"); }
int trace_connect(struct pt_regs *ctx) { return trace_syscall(ctx, "connect"); }
int trace_accept(struct pt_regs *ctx) { return trace_syscall(ctx, "accept"); }
int trace_accept4(struct pt_regs *ctx) { return trace_syscall(ctx, "accept4"); }
int trace_socket(struct pt_regs *ctx) { return trace_syscall(ctx, "socket"); }
int trace_bind(struct pt_regs *ctx) { return trace_syscall(ctx, "bind"); }
int trace_listen(struct pt_regs *ctx) { return trace_syscall(ctx, "listen"); }
int trace_tcp_sendmsg(struct pt_regs *ctx) { return trace_syscall(ctx, "tcp_sendmsg"); }
"""

# Event structure
class Event(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("syscall", ct.c_char * 32),
        ("arg1", ct.c_ulonglong),
        ("arg2", ct.c_ulonglong),
        ("arg3", ct.c_ulonglong)
    ]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    
    # Decode common args based on syscall type
    syscall = event.syscall.decode('utf-8', 'replace').strip('\x00')
    comm = event.comm.decode('utf-8', 'replace').strip('\x00')
    
    # For I/O syscalls, arg1 is usually FD, arg3 is usually size
    if syscall in ['write', 'read', 'send', 'recv', 'sendto', 'recvfrom', 
                   'pwrite64', 'pread64', 'writev', 'readv']:
        fd = event.arg1
        size = event.arg3
        if fd < 0 or fd > 10000:  # Skip invalid FDs
            return
        if size == 0 or size > 100000000:  # Skip empty or huge operations
            return
        print(f"[{syscall:12}] {comm:8} | PID: {event.pid:6} | FD: {fd:4} | Size: {size:8}")
    
    # For socket operations
    elif syscall in ['socket', 'connect', 'bind', 'listen', 'accept']:
        print(f"[{syscall:12}] {comm:8} | PID: {event.pid:6} | Args: {event.arg1:#x}, {event.arg2:#x}, {event.arg3:#x}")
    
    # tcp_sendmsg is special
    elif syscall == 'tcp_sendmsg':
        size = event.arg3
        if size > 0 and size < 100000000:
            print(f"[{syscall:12}] {comm:8} | PID: {event.pid:6} | Size: {size:8}")

def main():
    print("Comprehensive Network Syscall Tracer")
    print("=" * 60)
    print("Tracing ALL network-related syscalls and kernel functions")
    print("Looking for elbencho, boto3, and warp traffic")
    print("")
    
    try:
        logger.info("Compiling BPF program...")
        b = BPF(text=bpf_text)
        
        logger.info("Attaching probes...")
        
        # List of all syscalls to trace
        syscalls = [
            ('write', 'trace_write'),
            ('read', 'trace_read'),
            ('send', 'trace_send'),
            ('recv', 'trace_recv'),
            ('sendto', 'trace_sendto'),
            ('recvfrom', 'trace_recvfrom'),
            ('sendmsg', 'trace_sendmsg'),
            ('recvmsg', 'trace_recvmsg'),
            ('sendmmsg', 'trace_sendmmsg'),
            ('recvmmsg', 'trace_recvmmsg'),
            ('writev', 'trace_writev'),
            ('readv', 'trace_readv'),
            ('pwrite64', 'trace_pwrite64'),
            ('pread64', 'trace_pread64'),
            ('pwritev', 'trace_pwritev'),
            ('preadv', 'trace_preadv'),
            ('connect', 'trace_connect'),
            ('accept', 'trace_accept'),
            ('accept4', 'trace_accept4'),
            ('socket', 'trace_socket'),
            ('bind', 'trace_bind'),
            ('listen', 'trace_listen'),
        ]
        
        attached = 0
        for syscall, func in syscalls:
            # Try different prefixes
            for prefix in ['__x64_sys_', 'ksys_', 'sys_', '']:
                try:
                    b.attach_kprobe(event=f"{prefix}{syscall}", fn_name=func)
                    logger.info(f"✓ Attached to {prefix}{syscall}")
                    attached += 1
                    break
                except:
                    pass
        
        # Also try tcp_sendmsg kernel function
        try:
            b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
            logger.info("✓ Attached to tcp_sendmsg")
            attached += 1
        except:
            pass
        
        if attached == 0:
            logger.error("Failed to attach any probes")
            return 1
        
        logger.info(f"Successfully attached {attached} probes")
        
        # Open perf buffer
        b["events"].open_perf_buffer(print_event)
        
        print(f"\nTracing {attached} syscalls... Press Ctrl+C to stop")
        print("\nRun elbencho/boto3 and look for their network activity")
        print("")
        
        # Poll for events
        while True:
            try:
                b.perf_buffer_poll()
                time.sleep(0.01)
            except KeyboardInterrupt:
                break
        
        print("\nDetaching probes...")
        
    except Exception as e:
        logger.error(f"Failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
