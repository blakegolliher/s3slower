#!/usr/bin/env python3
"""
Test just BPF compilation without attachment
"""

import sys
import os
from pathlib import Path

def test_bpf_compile_only(bpf_file):
    """Test if a BPF file compiles without attaching"""
    try:
        from bcc import BPF
        
        print(f"Testing {bpf_file} compilation only...")
        
        # Read BPF program
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration
        bpf_text = bpf_text.replace('TARGET_PID 0', 'TARGET_PID 0')
        bpf_text = bpf_text.replace('MIN_LATENCY_US 0', 'MIN_LATENCY_US 0')
        
        # Try to compile (but not attach)
        b = BPF(text=bpf_text)
        print(f"✓ {bpf_file} compiled successfully!")
        
        # Try to get the functions to see if they exist
        try:
            write_func = b.load_func("trace_write", b.RAW_TRACEPOINT)
            read_func = b.load_func("trace_read", b.RAW_TRACEPOINT)
            print(f"✓ Functions loaded successfully")
            print(f"  - trace_write: {write_func}")
            print(f"  - trace_read: {read_func}")
        except Exception as e:
            print(f"⚠ Functions loaded with warnings: {e}")
        
        return True
        
    except Exception as e:
        print(f"✗ {bpf_file} failed to compile:")
        print(f"  Error: {e}")
        return False

def main():
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 test_bpf_compile_only.py")
        sys.exit(1)
    
    print("BPF Compilation Test (No Attachment)")
    print("=" * 40)
    
    base_path = Path(__file__).parent
    
    # Test the basic-only version
    basic_only_file = base_path / "s3slower_basic_only.c"
    
    if basic_only_file.exists():
        if test_bpf_compile_only(basic_only_file):
            print(f"\n✅ Basic-only BPF compiles successfully!")
            print("The issue might be with syscall attachment, not compilation.")
            print("\nTry running with the original s3slower.c to see if it works:")
            print("sudo python3 -c \"from s3slower.s3ops import S3LatencyMonitor; m = S3LatencyMonitor(); m.start(); import time; time.sleep(5); m.stop()\"")
        else:
            print(f"\n❌ Basic-only BPF compilation failed!")
    else:
        print(f"Basic-only file not found: {basic_only_file}")

if __name__ == '__main__':
    main()
