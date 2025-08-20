#!/usr/bin/env python3
"""
Test the focused enhanced BPF program - simpler version without extra syscalls
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
logger = logging.getLogger('s3slower_test')

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
        ("detected_s3", ct.c_uint8),
        ("data", ct.c_char * 256)
    ]

def print_event(cpu, data, size):
    """Event handler"""
    event = ct.cast(data, ct.POINTER(Event)).contents
    
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
    
    # Extract request info
    try:
        req_data = event.data.decode('utf-8', errors='replace')[:80]
        req_line = req_data.split('\n')[0] if '\n' in req_data else req_data
    except:
        req_line = str(event.data[:80])
    
    # Print detailed info
    print(f"\n{'='*80}")
    print(f"Timestamp: {event.ts_us} us")
    print(f"Process: {event.comm.decode('utf-8', errors='replace')} (PID: {event.pid}, TID: {event.tid})")
    print(f"Client Type: {client}")
    print(f"FD: {event.fd}")
    print(f"Latency: {event.latency_us} us")
    print(f"Request Size: {event.req_size} bytes")
    print(f"Response Size: {event.resp_size} bytes (actual: {event.actual_resp_bytes})")
    print(f"S3 Detected: {'Yes' if event.detected_s3 else 'No'}")
    print(f"Multipart: {'Yes' if event.is_partial else 'No'}")
    print(f"Request: {req_line}")
    print('='*80)

def main():
    print("Enhanced S3 Latency Monitor (Focused Version)")
    print("=" * 50)
    
    # Load the BPF program
    bpf_file = os.path.join(os.path.dirname(__file__), "s3slower_enhanced_focused.c")
    
    try:
        logger.info(f"Loading BPF program from {bpf_file}")
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration placeholders
        bpf_text = bpf_text.replace("TARGET_PID_PLACEHOLDER", "0")
        bpf_text = bpf_text.replace("MIN_LATENCY_PLACEHOLDER", "0")
        
        logger.info("Compiling BPF program...")
        b = BPF(text=bpf_text)
        
        logger.info("✓ BPF program compiled successfully!")
        
        logger.info("Attaching probes...")
        # Attach only the basic syscalls
        b.attach_kprobe(event="sys_write", fn_name="trace_write")
        b.attach_kprobe(event="sys_read", fn_name="trace_read")
        b.attach_kretprobe(event="sys_read", fn_name="trace_read_ret")
        
        logger.info("✓ Successfully attached all probes!")
        
        # Open perf buffer
        b["events"].open_perf_buffer(print_event)
        
        print("\nMonitoring S3 traffic... Press Ctrl+C to stop")
        print("\nEnhanced Features:")
        print("- 256-byte buffer (vs 64 in original)")
        print("- Better HTTP method detection")
        print("- S3-specific pattern detection")
        print("- Special handling for elbencho clients")
        print("- Detects 'warp-benchmark' bucket name")
        print("\nRun your elbencho test in another terminal:")
        print("elbencho --s3endpoints http://172.200.201.1:80 --s3key supercools3accesskey \\")
        print("         --s3secret SuperCoolS3SecretAccessKeyItReallyIsCool -w -t 4 -n 5 \\")
        print("         -N 5 -s 1g -b 10m warp-benchmark-bucket --timelimit 0")
        print("")
        
        # Poll for events
        while True:
            try:
                b.perf_buffer_poll()
                time.sleep(0.1)
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
