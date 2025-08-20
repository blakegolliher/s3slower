#!/usr/bin/env python3
"""
Network-focused debug to catch sendto/recvfrom used by AWS SDK
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
logger = logging.getLogger('net_debug')

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
        2: "HTTP_REQ",
        3: "READ", 
        4: "HTTP_RESP",
        5: "SENDTO",
        6: "RECVFROM",
        7: "SENDMSG",
        8: "RECVMSG"
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
    
    print(f"[{event_type:9}] {client:8} | PID: {event.pid:6} | FD: {event.fd:3} | Size: {event.size:6}")
    print(f"           HEX: {hex_str}")
    print(f"           ASCII: {ascii_str}")
    print()

def main():
    print("Network I/O Debug Monitor (sendto/recvfrom/sendmsg/recvmsg)")
    print("=" * 60)
    print("This monitors network syscalls used by AWS SDK")
    print("")
    
    # Load the BPF program
    bpf_file = os.path.join(os.path.dirname(__file__), "s3slower_net_debug.c")
    
    try:
        logger.info(f"Loading network debug BPF program from {bpf_file}")
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration placeholders
        bpf_text = bpf_text.replace("TARGET_PID_PLACEHOLDER", "0")
        bpf_text = bpf_text.replace("MIN_LATENCY_PLACEHOLDER", "0")
        
        logger.info("Compiling BPF program...")
        b = BPF(text=bpf_text)
        
        logger.info("Attaching probes...")
        
        # Network syscalls
        network_syscalls = [
            ("sendto", "trace_sendto"),
            ("recvfrom", "trace_recvfrom"),
            ("sendmsg", "trace_sendmsg"),
            ("recvmsg", "trace_recvmsg")
        ]
        
        attached = 0
        for syscall, trace_func in network_syscalls:
            # Try different syscall names
            for prefix in ["__x64_sys_", "ksys_", ""]:
                try:
                    b.attach_kprobe(event=f"{prefix}{syscall}", fn_name=trace_func)
                    logger.info(f"✓ Attached to {prefix}{syscall}")
                    attached += 1
                    break
                except:
                    pass
        
        # Also attach write/read for comparison
        for syscall, trace_func in [("write", "trace_write"), ("read", "trace_read")]:
            for prefix in ["ksys_", "__x64_sys_", ""]:
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
        
        print("\nMonitoring network I/O... Press Ctrl+C to stop")
        print("\nThis will show:")
        print("- sendto/recvfrom (commonly used by AWS SDK)")
        print("- sendmsg/recvmsg (also used for network I/O)")
        print("- write/read (for comparison)")
        print("\nRun elbencho or boto3 to see network traffic")
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
