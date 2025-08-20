#!/usr/bin/env python3
"""
Debug version to understand why elbencho isn't being detected
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
logger = logging.getLogger('s3slower_debug')

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
    
    # Decode event type
    event_types = {
        1: "WRITE_SEEN",
        2: "HTTP_REQUEST",
        3: "READ_SEEN",
        4: "HTTP_RESPONSE"
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
    
    # Extract data
    try:
        data_str = event.data.decode('utf-8', errors='replace')[:50]
        # Escape newlines for cleaner output
        data_str = data_str.replace('\n', '\\n').replace('\r', '\\r')
    except:
        data_str = str(event.data[:50])
    
    print(f"[DEBUG] {event_type:14} | {client:8} | PID: {event.pid:6} | FD: {event.fd:3} | Size: {event.size:6} | Data: {data_str}")

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
    print(f"[S3 REQUEST COMPLETE]")
    print(f"Client: {client} | Process: {event.comm.decode('utf-8', errors='replace')} (PID: {event.pid})")
    print(f"Latency: {event.latency_us} us | FD: {event.fd}")
    print(f"Request Size: {event.req_size} bytes | Response Size: {event.resp_size} bytes")
    print(f"Request: {req_line}")
    print('='*80)

def main():
    print("S3 Latency Monitor - Debug Mode")
    print("=" * 50)
    print("This will show ALL write/read activity from known S3 clients")
    print("(warp, elbencho, boto3/python, s3cmd, aws cli)")
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
        # Attach kprobes
        b.attach_kprobe(event="sys_write", fn_name="trace_write")
        b.attach_kprobe(event="sys_read", fn_name="trace_read")
        b.attach_kretprobe(event="sys_read", fn_name="trace_read_ret")
        
        logger.info("✓ Successfully attached all probes!")
        
        # Open perf buffers
        b["debug_events"].open_perf_buffer(print_debug_event)
        b["events"].open_perf_buffer(print_event)
        
        print("\nMonitoring S3 traffic... Press Ctrl+C to stop")
        print("\nDEBUG OUTPUT FORMAT:")
        print("[DEBUG] EVENT_TYPE      | CLIENT   | PID: xxxxxx | FD: xxx | Size: xxxxxx | Data: <first 50 bytes>")
        print("")
        print("Run your tests:")
        print("1. elbencho: elbencho --s3endpoints http://172.200.201.1:80 ... warp-benchmark-bucket")
        print("2. boto3: python3 -c \"import boto3; s3=boto3.client('s3', endpoint_url='http://172.200.201.1:80'); s3.list_buckets()\"")
        print("")
        
        # Poll for events
        while True:
            try:
                b.perf_buffer_poll()
                time.sleep(0.01)  # Faster polling for debug
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
