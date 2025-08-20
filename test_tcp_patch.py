#!/usr/bin/env python3
"""
Test the tcp_sendmsg patch to s3slower
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
logger = logging.getLogger('tcp_patch_test')

# Event structure from s3slower
class Event(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("latency_us", ct.c_ulonglong),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("client_type", ct.c_uint8),
        ("req_size", ct.c_uint32),
        ("resp_size", ct.c_uint32),
        ("actual_resp_bytes", ct.c_uint32),
        ("task", ct.c_char * 16),
        ("operation", ct.c_char * 16),
        ("key", ct.c_char * 128),
        ("http_method", ct.c_char * 8),
        ("http_status", ct.c_uint16),
        ("fd", ct.c_int32)
    ]

def print_event(cpu, data, size):
    """Print S3 operation event"""
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
    
    # Decode strings
    task = event.task.decode('utf-8', 'replace').strip('\x00')
    operation = event.operation.decode('utf-8', 'replace').strip('\x00')
    key = event.key.decode('utf-8', 'replace').strip('\x00')
    method = event.http_method.decode('utf-8', 'replace').strip('\x00')
    
    print(f"\n{'='*60}")
    print(f"S3 Operation Detected!")
    print(f"Client: {client} ({task})")
    print(f"PID: {event.pid} TID: {event.tid}")
    print(f"Operation: {operation} ({method})")
    print(f"Key: {key}")
    print(f"Latency: {event.latency_us/1000:.2f} ms")
    print(f"Request Size: {event.req_size} bytes")
    print(f"Response Size: {event.resp_size} bytes")
    print(f"FD: {event.fd} {'(tcp_sendmsg)' if event.fd == -1 else ''}")
    print(f"HTTP Status: {event.http_status}")
    print(f"{'='*60}")

def main():
    print("S3Slower tcp_sendmsg Patch Test")
    print("=" * 60)
    print("This tests if the patched s3slower can detect elbencho traffic")
    print("")
    
    # Load the patched BPF program
    bpf_file = os.path.join(os.path.dirname(__file__), "s3slower.c")
    
    try:
        logger.info(f"Loading patched BPF program from {bpf_file}")
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration placeholders
        bpf_text = bpf_text.replace("TARGET_PID 0", "TARGET_PID 0")
        bpf_text = bpf_text.replace("MIN_LATENCY_US 0", "MIN_LATENCY_US 0")
        
        logger.info("Compiling BPF program...")
        b = BPF(text=bpf_text)
        
        logger.info("Attaching probes...")
        
        # Attach write/read syscalls
        attached = 0
        for prefix in ["ksys_", "__x64_sys_", ""]:
            try:
                b.attach_kprobe(event=f"{prefix}write", fn_name="trace_write")
                logger.info(f"✓ Attached to {prefix}write")
                attached += 1
                break
            except:
                pass
        
        for prefix in ["ksys_", "__x64_sys_", ""]:
            try:
                b.attach_kprobe(event=f"{prefix}read", fn_name="trace_read")
                b.attach_kretprobe(event=f"{prefix}read", fn_name="trace_read_ret")
                logger.info(f"✓ Attached to {prefix}read")
                attached += 1
                break
            except:
                pass
        
        # NEW: Attach tcp_sendmsg
        try:
            b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
            logger.info("✓ Attached to tcp_sendmsg for elbencho/AWS SDK support!")
            attached += 1
        except Exception as e:
            logger.warning(f"Could not attach to tcp_sendmsg: {e}")
        
        if attached == 0:
            logger.error("Failed to attach any probes")
            return 1
        
        logger.info(f"Successfully attached {attached} probes")
        
        # Open perf buffer
        b["events"].open_perf_buffer(print_event)
        
        print("\nMonitoring S3 traffic... Press Ctrl+C to stop")
        print("\nRun elbencho or warp to test:")
        print("- elbencho should show FD: -1 (tcp_sendmsg)")
        print("- warp should show normal FD numbers")
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
