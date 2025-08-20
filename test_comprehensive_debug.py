#!/usr/bin/env python3
"""
Comprehensive I/O syscall debug monitor
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
logger = logging.getLogger('comprehensive_debug')

# Define the debug event structure
class DebugEvent(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("fd", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("event_type", ct.c_uint8),
        ("client_type", ct.c_uint8),
        ("size", ct.c_uint32),
        ("data", ct.c_char * 64)
    ]

def print_debug_event(cpu, data, size):
    """Debug event handler"""
    event = ct.cast(data, ct.POINTER(DebugEvent)).contents
    
    # Decode event type
    event_types = {
        1: "WRITE",
        3: "READ", 
        5: "SENDTO",
        6: "RECVFROM",
        7: "SENDMSG",
        8: "RECVMSG",
        9: "SEND",
        10: "RECV",
        11: "PWRITE",
        12: "PREAD",
        13: "WRITEV",
        14: "READV",
        15: "PWRITEV",
        16: "PREADV"
    }
    event_type = event_types.get(event.event_type, "UNKNOWN")
    
    # Decode client type
    client_types = {
        0: "UNKNOWN",
        1: "WARP",
        2: "ELBENCHO",
        3: "BOTO3",
        4: "S3CMD",
        5: "AWSCLI"
    }
    client = client_types.get(event.client_type, "UNKNOWN")
    
    # Skip ELBENCHO reads of small files (startup noise)
    if client == "ELBENCHO" and event_type == "READ" and event.size < 10000:
        return
    
    # Show first 30 bytes as hex and ASCII
    hex_str = ' '.join(f'{b:02x}' for b in event.data[:30])
    
    # Try to show ASCII for printable chars
    ascii_str = ''
    for b in event.data[:30]:
        if 32 <= b <= 126:  # Printable ASCII
            ascii_str += chr(b)
        else:
            ascii_str += '.'
    
    # Check if it might be HTTP
    try:
        text = event.data.decode('utf-8', errors='strict')[:30]
        if text.startswith(('GET ', 'PUT ', 'POST ', 'HEAD ', 'DELETE ', 'HTTP/')):
            ascii_str = f"HTTP: {text}"
    except:
        pass
    
    print(f"[{event_type:9}] {client:8} | PID: {event.pid:6} TID: {event.tid:6} | FD: {event.fd:3} | Size: {event.size:8}")
    if event.size > 0:
        print(f"           HEX: {hex_str}")
        print(f"           ASCII: {ascii_str}")
    print()

def main():
    print("Comprehensive I/O Syscall Debug Monitor")
    print("=" * 60)
    print("Monitoring ALL I/O syscalls:")
    print("- write/read")
    print("- send/recv")
    print("- sendto/recvfrom")
    print("- sendmsg/recvmsg")
    print("- pwrite/pread")
    print("- writev/readv")
    print("")
    
    # Load the BPF program
    bpf_file = os.path.join(os.path.dirname(__file__), "s3slower_comprehensive_debug.c")
    
    try:
        logger.info(f"Loading comprehensive debug BPF program from {bpf_file}")
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration placeholders
        bpf_text = bpf_text.replace("TARGET_PID_PLACEHOLDER", "0")
        bpf_text = bpf_text.replace("MIN_LATENCY_PLACEHOLDER", "0")
        
        logger.info("Compiling BPF program...")
        b = BPF(text=bpf_text)
        
        logger.info("Attaching probes...")
        
        # All I/O syscalls to monitor
        syscalls = [
            ("write", "trace_write"),
            ("read", "trace_read"),
            ("send", "trace_send"),
            ("recv", "trace_recv"),
            ("sendto", "trace_sendto"),
            ("recvfrom", "trace_recvfrom"),
            ("sendmsg", "trace_sendmsg"),
            ("recvmsg", "trace_recvmsg"),
            ("pwrite64", "trace_pwrite"),
            ("pread64", "trace_pread"),
            ("writev", "trace_writev"),
            ("readv", "trace_readv")
        ]
        
        attached = 0
        for syscall, trace_func in syscalls:
            # Try different syscall name variations
            for prefix in ["__x64_sys_", "ksys_", "sys_", ""]:
                try:
                    b.attach_kprobe(event=f"{prefix}{syscall}", fn_name=trace_func)
                    logger.info(f"✓ Attached to {prefix}{syscall}")
                    attached += 1
                    break
                except:
                    pass
        
        if attached == 0:
            logger.error("Failed to attach to any syscalls")
            return 1
        
        logger.info(f"✓ Successfully attached {attached} probes!")
        
        # Open perf buffer
        b["debug_events"].open_perf_buffer(print_debug_event)
        
        print(f"\nMonitoring {attached} I/O syscalls... Press Ctrl+C to stop")
        print("\nFiltering out small elbencho startup reads")
        print("\nRun elbencho to see its I/O patterns")
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
        logger.error(f"Failed to load BPF program: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
