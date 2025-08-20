#!/usr/bin/env python3
"""
TCP-level debug monitor - traces tcp_sendmsg/tcp_recvmsg kernel functions
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
logger = logging.getLogger('tcp_debug')

# Define the debug event structure
class DebugEvent(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("event_type", ct.c_uint8),
        ("client_type", ct.c_uint8),
        ("size", ct.c_uint32),
        ("data", ct.c_char * 128)
    ]

def print_debug_event(cpu, data, size):
    """Debug event handler"""
    event = ct.cast(data, ct.POINTER(DebugEvent)).contents
    
    # Decode event type
    event_types = {
        1: "TCP_SEND",
        2: "TCP_RECV"
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
    
    # Show first 60 bytes as hex and ASCII
    hex_str = ' '.join(f'{b:02x}' for b in event.data[:60])
    
    # Try to show ASCII for printable chars
    ascii_str = ''
    for b in event.data[:60]:
        if 32 <= b <= 126:  # Printable ASCII
            ascii_str += chr(b)
        else:
            ascii_str += '.'
    
    # Check if it might be HTTP
    try:
        text = event.data.decode('utf-8', errors='strict')[:60]
        if text.startswith(('GET ', 'PUT ', 'POST ', 'HEAD ', 'DELETE ', 'HTTP/')):
            ascii_str = f"HTTP: {text}"
    except:
        pass
    
    print(f"[{event_type:9}] {client:8} | PID: {event.pid:6} TID: {event.tid:6} | Size: {event.size:8}")
    if event.size > 0 and event_type == "TCP_SEND":
        print(f"           HEX: {hex_str[:90]}")
        print(f"           ASCII: {ascii_str}")
    print()

def main():
    print("TCP-Level Debug Monitor (tcp_sendmsg/tcp_recvmsg)")
    print("=" * 60)
    print("This traces the kernel TCP functions directly")
    print("Should catch ALL TCP traffic including SSL/TLS")
    print("")
    
    # Load the BPF program
    bpf_file = os.path.join(os.path.dirname(__file__), "s3slower_tcp_debug.c")
    
    try:
        logger.info(f"Loading TCP debug BPF program from {bpf_file}")
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration placeholders
        bpf_text = bpf_text.replace("TARGET_PID_PLACEHOLDER", "0")
        bpf_text = bpf_text.replace("MIN_LATENCY_PLACEHOLDER", "0")
        
        logger.info("Compiling BPF program...")
        b = BPF(text=bpf_text)
        
        logger.info("Attaching to kernel TCP functions...")
        
        # Attach to tcp_sendmsg and tcp_recvmsg
        b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
        logger.info("✓ Attached to tcp_sendmsg")
        
        b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg")
        logger.info("✓ Attached to tcp_recvmsg")
        
        # Open perf buffer
        b["debug_events"].open_perf_buffer(print_debug_event)
        
        print("\nMonitoring TCP traffic at kernel level... Press Ctrl+C to stop")
        print("\nRun elbencho to see if it uses TCP for S3")
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
