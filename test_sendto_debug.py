#!/usr/bin/env python3
"""
Fixed sendto debug monitor
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
logger = logging.getLogger('sendto_debug')

# Define the debug event structure
class DebugEvent(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("fd", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("client_type", ct.c_uint8),
        ("size", ct.c_uint32),
        ("data", ct.c_char * 256)
    ]

def print_debug_event(cpu, data, size):
    """Debug event handler"""
    event = ct.cast(data, ct.POINTER(DebugEvent)).contents
    
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
    
    # Determine if this is write or sendto based on data patterns
    syscall = "SENDTO" if event.fd > 100 else "WRITE"
    
    print(f"[{syscall:9}] {client:8} | PID: {event.pid:6} TID: {event.tid:6} | FD: {event.fd:3} | Size: {event.size:8}")
    
    if event.size > 0:
        # Show first 100 bytes as hex
        hex_str = ' '.join(f'{b:02x}' for b in event.data[:min(100, event.size)])
        print(f"           HEX: {hex_str}")
        
        # Try to show ASCII for printable chars
        ascii_str = ''
        for b in event.data[:min(100, event.size)]:
            if 32 <= b <= 126:  # Printable ASCII
                ascii_str += chr(b)
            else:
                ascii_str += '.'
        
        # Check if it might be HTTP
        try:
            text = event.data.decode('utf-8', errors='strict')[:100]
            if text.startswith(('GET ', 'PUT ', 'POST ', 'HEAD ', 'DELETE ', 'HTTP/')):
                print(f"           HTTP DETECTED: {text.split(chr(13))[0]}")  # First line
        except:
            pass
        
        print(f"           ASCII: {ascii_str}")
    print()

def main():
    print("Fixed sendto/write Debug Monitor")
    print("=" * 60)
    print("Monitoring sendto and write syscalls with proper argument reading")
    print("")
    
    # Load the BPF program
    bpf_file = os.path.join(os.path.dirname(__file__), "s3slower_sendto_debug.c")
    
    try:
        logger.info(f"Loading sendto debug BPF program from {bpf_file}")
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration placeholders
        bpf_text = bpf_text.replace("TARGET_PID_PLACEHOLDER", "0")
        bpf_text = bpf_text.replace("MIN_LATENCY_PLACEHOLDER", "0")
        
        logger.info("Compiling BPF program...")
        b = BPF(text=bpf_text)
        
        logger.info("Attaching probes...")
        
        # Try different syscall name variations for sendto
        attached = False
        for prefix in ["__x64_sys_", "ksys_", "sys_", ""]:
            try:
                b.attach_kprobe(event=f"{prefix}sendto", fn_name="trace_sendto_entry")
                logger.info(f"✓ Attached to {prefix}sendto")
                attached = True
                break
            except:
                pass
        
        if not attached:
            logger.error("Failed to attach to sendto")
            return 1
            
        # Attach write for comparison
        for prefix in ["ksys_", "__x64_sys_", "sys_", ""]:
            try:
                b.attach_kprobe(event=f"{prefix}write", fn_name="trace_write")
                logger.info(f"✓ Attached to {prefix}write")
                break
            except:
                pass
        
        # Open perf buffer
        b["debug_events"].open_perf_buffer(print_debug_event)
        
        print("\nMonitoring sendto and write syscalls... Press Ctrl+C to stop")
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
