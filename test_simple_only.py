#!/usr/bin/env python3
"""
Test only the simple BPF version
"""

import sys
import os
from pathlib import Path

# Add s3slower to path
sys.path.insert(0, str(Path(__file__).parent))

def test_simple_bpf():
    """Test the simple BPF version directly"""
    try:
        from bcc import BPF
        
        print("Testing Simple BPF Version")
        print("=" * 40)
        
        # Read simple BPF program
        base_path = Path(__file__).parent
        bpf_file = base_path / "s3slower_enhanced_simple.c"
        
        if not bpf_file.exists():
            print(f"❌ Simple BPF file not found: {bpf_file}")
            return False
        
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration
        bpf_text = bpf_text.replace('TARGET_PID 0', 'TARGET_PID 0')
        bpf_text = bpf_text.replace('MIN_LATENCY_US 0', 'MIN_LATENCY_US 0')
        
        print("Compiling simple BPF program...")
        b = BPF(text=bpf_text)
        print("✓ Simple BPF compiled successfully!")
        
        print("✓ Simple version works!")
        return True
        
    except Exception as e:
        print(f"❌ Simple version failed: {e}")
        return False

def main():
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 test_simple_only.py")
        sys.exit(1)
    
    print("Simple BPF Test")
    print("=" * 40)
    
    if test_simple_bpf():
        print("\n✅ Simple BPF version works!")
        print("\nYou can now use it with:")
        print("sudo python3 -c \"from s3slower.s3ops_enhanced import UniversalS3Monitor; m = UniversalS3Monitor(use_simple=True); m.start(); import time; time.sleep(5); m.stop()\"")
        
        print("\nOr test with elbencho:")
        print("elbencho --s3endpoints http://172.200.201.80 ...")
    else:
        print("\n❌ Even simple version failed!")
        print("This suggests a fundamental BPF compatibility issue.")

if __name__ == '__main__':
    main()
