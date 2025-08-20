#!/usr/bin/env python3
"""
Debug version focused ONLY on elbencho traffic
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
logger = logging.getLogger('elbencho_debug')

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

# Define the event structure matching the C struct
class Event(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("latency_us", ct.c_ulonglong),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("fd", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("req_size", ct.c_uint32),
        ("resp_size", ct.c_uint32),
        ("actual_resp_bytes", ct.c_uint32),
        ("is_partial", ct.c_uint8),
        ("client_type", ct.c_uint8),
        ("data", ct.c_char * 64)
    ]

def print_debug_event(cpu, data, size):
    """Debug event handler"""
    event = ct.cast(data, ct.POINTER(DebugEvent)).contents
    
    # Only show elbencho events
    if event.client_type != 2:  # CLIENT_ELBENCHO = 2
        return
    
    # Decode event type
    event_types = {
        1: "WRITE",
        2: "HTTP_REQ",
        3: "READ",
        4: "HTTP_RESP"
    }
    event_type = event_types.get(event.event_type, "UNKNOWN")
    
    # Show first 30 bytes as hex and ASCII
    hex_str = ' '.join(f'{b:02x}' for b in event.data[:30])
    
    # Try to show ASCII for printable chars
    ascii_str = ''
    for b in event.data[:30]:
        if 32 <= b <= 126:  # Printable ASCII
            ascii_str += chr(b)
        else:
            ascii_str += '.'
    
    print(f"[{event_type:9}] PID: {event.pid:6} TID: {event.tid:6} FD: {event.fd:3} Size: {event.size:6}")
    print(f"           HEX: {hex_str}")
    print(f"           ASCII: {ascii_str}")
    print()

def print_event(cpu, data, size):
    """Event handler"""
    event = ct.cast(data, ct.POINTER(Event)).contents
    
    # Only show elbencho events
    if event.client_type != 2:  # CLIENT_ELBENCHO = 2
        return
    
    # Extract request info
    try:
        req_data = event.data.decode('utf-8', errors='replace')[:80]
        req_line = req_data.split('\n')[0] if '\n' in req_data else req_data
    except:
        req_line = str(event.data[:80])
    
    # Print detailed info
    print(f"\n{'='*80}")
    print(f"[ELBENCHO S3 REQUEST COMPLETE]")
    print(f"Process: {event.comm.decode('utf-8', errors='replace')} (PID: {event.pid})")
    print(f"Latency: {event.latency_us} us | FD: {event.fd}")
    print(f"Request Size: {event.req_size} bytes | Response Size: {event.resp_size} bytes")
    print(f"Request: {req_line}")
    print('='*80)

def main():
    print("Elbencho-Only Debug Monitor")
    print("=" * 50)
    print("This will show ONLY elbencho write/read activity")
    print("")
    
    # Load the BPF program
    bpf_file = os.path.join(os.path.dirname(__file__), "s3slower_debug.c")
    
    try:
        logger.info(f"Loading debug BPF program from {bpf_file}")
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration placeholders
        bpf_text = bpf_text.replace("TARGET_PID_PLACEHOLDER", "0")
        bpf_text = bpf_text.replace("MIN_LATENCY_PLACEHOLDER", "0")
        
        logger.info("Compiling BPF program...")
        b = BPF(text=bpf_text)
        
        logger.info("Attaching probes...")
        
        # Try to attach to write syscalls
        write_attached = False
        write_syscalls = ["ksys_write", "__x64_sys_write", "sys_write"]
        for syscall in write_syscalls:
            try:
                b.attach_kprobe(event=syscall, fn_name="trace_write")
                logger.info(f"✓ Attached to {syscall}")
                write_attached = True
                break
            except:
                pass
        
        if not write_attached:
            logger.error("Failed to attach to any write syscall")
            return 1
        
        # Try to attach to read syscalls
        read_attached = False
        read_syscalls = ["ksys_read", "__x64_sys_read", "sys_read"]
        for syscall in read_syscalls:
            try:
                b.attach_kprobe(event=syscall, fn_name="trace_read")
                b.attach_kretprobe(event=syscall, fn_name="trace_read_ret")
                logger.info(f"✓ Attached to {syscall}")
                read_attached = True
                break
            except:
                pass
        
        if not read_attached:
            logger.error("Failed to attach to any read syscall")
            return 1
        
        logger.info("✓ Successfully attached all probes!")
        
        # Open perf buffers
        b["debug_events"].open_perf_buffer(print_debug_event)
        b["events"].open_perf_buffer(print_event)
        
        print("\nMonitoring elbencho traffic... Press Ctrl+C to stop")
        print("\nRun elbencho in another terminal:")
        print("elbencho --s3endpoints http://172.200.201.1:80 --s3key supercools3accesskey \\")
        print("         --s3secret SuperCoolS3SecretAccessKeyItReallyIsCool -w -t 4 -n 5 \\")
        print("         -N 5 -s 1g -b 10m warp-benchmark-bucket --timelimit 0")
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
