#!/usr/bin/env python3
"""
Simple BPF compilation test
"""

import sys
import os
from pathlib import Path

def test_bpf_compile(bpf_file):
    """Test if a BPF file compiles"""
    try:
        from bcc import BPF
        
        print(f"Testing {bpf_file}...")
        
        # Read BPF program
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration
        bpf_text = bpf_text.replace('TARGET_PID 0', 'TARGET_PID 0')
        bpf_text = bpf_text.replace('MIN_LATENCY_US 0', 'MIN_LATENCY_US 0')
        
        # Try to compile
        b = BPF(text=bpf_text)
        print(f"✓ {bpf_file} compiled successfully!")
        return True
        
    except Exception as e:
        print(f"✗ {bpf_file} failed to compile:")
        print(f"  Error: {e}")
        return False

def main():
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 test_bpf_compile.py")
        sys.exit(1)
    
    print("BPF Compilation Test")
    print("=" * 30)
    
    base_path = Path(__file__).parent
    
    # Test all BPF versions
    versions = [
        ("Original", "s3slower.c"),
        ("Stack-Fixed", "s3slower_enhanced_stack_fixed.c"),
        ("Simple", "s3slower_enhanced_simple.c"),
        ("Compatibility", "s3slower_enhanced_compat.c"),
        ("Enhanced", "s3slower_enhanced.c"),
    ]
    
    results = {}
    
    for name, filename in versions:
        filepath = base_path / filename
        if filepath.exists():
            results[name] = test_bpf_compile(filepath)
        else:
            print(f"{name}: File not found ({filename})")
            results[name] = None
    
    print("\n" + "=" * 30)
    print("Summary:")
    print("-" * 30)
    
    for name, result in results.items():
        if result is True:
            print(f"  {name}: ✓ Success")
        elif result is False:
            print(f"  {name}: ✗ Failed")
        else:
            print(f"  {name}: - Not found")
    
    # Find first working version
    working = [name for name, result in results.items() if result is True]
    if working:
        print(f"\n✅ First working version: {working[0]}")
        print(f"You can use this version for testing.")
    else:
        print("\n❌ No BPF versions compiled successfully!")

if __name__ == '__main__':
    main()
