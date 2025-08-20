#!/usr/bin/env python3
"""
Simple test to detect ANY elbencho file descriptor activity
"""

import os
import sys
import time
from bcc import BPF

# BPF program - trace all FD operations from elbencho
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(fd_map, u32, u64);  // Track FDs by PID

// Check if process is elbencho
static int is_elbencho(char *comm) {
    return (comm[0] == 'e' && comm[1] == 'l' && comm[2] == 'b' && 
            comm[3] == 'e' && comm[4] == 'n' && comm[5] == 'c' && 
            comm[6] == 'h' && comm[7] == 'o');
}

// Trace open/openat to see what files elbencho opens
int trace_open(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_elbencho(comm)) return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    
    // Try to read filename
    char fname[64] = {};
    bpf_probe_read_user_str(&fname, sizeof(fname), filename);
    
    bpf_trace_printk("OPEN: pid=%d file=%s\\n", pid, fname);
    return 0;
}

int trace_openat(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_elbencho(comm)) return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    
    // Try to read filename
    char fname[64] = {};
    bpf_probe_read_user_str(&fname, sizeof(fname), filename);
    
    bpf_trace_printk("OPENAT: pid=%d file=%s\\n", pid, fname);
    return 0;
}

// Trace socket creation
int trace_socket(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_elbencho(comm)) return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int domain = (int)PT_REGS_PARM1(ctx);
    int type = (int)PT_REGS_PARM2(ctx);
    int protocol = (int)PT_REGS_PARM3(ctx);
    
    bpf_trace_printk("SOCKET: pid=%d domain=%d type=%d proto=%d\\n", 
                     pid, domain, type, protocol);
    return 0;
}

// Trace connect to see where elbencho connects
int trace_connect(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_elbencho(comm)) return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int fd = (int)PT_REGS_PARM1(ctx);
    
    bpf_trace_printk("CONNECT: pid=%d fd=%d\\n", pid, fd);
    return 0;
}

// Return probe for socket - capture the FD
int trace_socket_ret(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_elbencho(comm)) return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int ret = PT_REGS_RC(ctx);
    
    if (ret >= 0) {
        bpf_trace_printk("SOCKET_RET: pid=%d new_fd=%d\\n", pid, ret);
        u64 val = 1;
        fd_map.update(&pid, &val);
    }
    return 0;
}

// Trace close to see when FDs are closed
int trace_close(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!is_elbencho(comm)) return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int fd = (int)PT_REGS_PARM1(ctx);
    
    if (fd > 2) {  // Skip stdin/stdout/stderr
        bpf_trace_printk("CLOSE: pid=%d fd=%d\\n", pid, fd);
    }
    return 0;
}
"""

def main():
    print("Elbencho Activity Monitor")
    print("=" * 50)
    print("Tracing file and socket operations from elbencho")
    print("")
    
    try:
        b = BPF(text=bpf_text)
        
        # Attach probes
        for syscall in ['open', 'openat', 'socket', 'connect', 'close']:
            for prefix in ['__x64_sys_', 'ksys_', 'sys_', '']:
                try:
                    b.attach_kprobe(event=f"{prefix}{syscall}", fn_name=f"trace_{syscall}")
                    print(f"✓ Attached to {prefix}{syscall}")
                    break
                except:
                    pass
        
        # Return probe for socket
        for prefix in ['__x64_sys_', 'ksys_', 'sys_', '']:
            try:
                b.attach_kretprobe(event=f"{prefix}socket", fn_name="trace_socket_ret")
                print(f"✓ Attached return probe to {prefix}socket")
                break
            except:
                pass
        
        print("\nWatching elbencho... (check /sys/kernel/debug/tracing/trace_pipe)")
        print("Run: sudo cat /sys/kernel/debug/tracing/trace_pipe | grep elbencho")
        print("\nPress Ctrl+C to stop")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nDetaching...")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
