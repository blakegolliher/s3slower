#!/usr/bin/env python3
"""
Test all BPF versions to see which ones work
"""

import sys
import os
from pathlib import Path

# Add s3slower to path
sys.path.insert(0, str(Path(__file__).parent))

def test_bpf_version(version_name, bpf_file):
    """Test if a specific BPF version compiles"""
    from bcc import BPF
    
    print(f"\nTesting {version_name}...")
    print("-" * 50)
    
    try:
        # Read BPF program
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Replace configuration
        bpf_text = bpf_text.replace('TARGET_PID 0', 'TARGET_PID 0')
        bpf_text = bpf_text.replace('MIN_LATENCY_US 0', 'MIN_LATENCY_US 0')
        
        # Try to compile
        print(f"Compiling {bpf_file}...")
        b = BPF(text=bpf_text)
        print(f"✓ {version_name} compiled successfully!")
        return True
        
    except Exception as e:
        print(f"✗ {version_name} failed to compile:")
        print(f"  Error: {e}")
        
        # Check error type
        error_str = str(e)
        if "memcpy" in error_str:
            print("  → memcpy not supported")
        elif "memset" in error_str:
            print("  → memset not supported")
        elif "loop not unrolled" in error_str:
            print("  → Loop unrolling issue")
        else:
            print("  → Other BPF verifier error")
        
        return False

def main():
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 test_bpf_versions.py")
        sys.exit(1)
    
    print("BPF Version Compatibility Test")
    print("=" * 50)
    
    base_path = Path(__file__).parent
    
    versions = [
        ("Original", base_path / "s3slower.c"),
        ("Enhanced", base_path / "s3slower_enhanced.c"),
        ("Compatibility", base_path / "s3slower_enhanced_compat.c"),
        ("Simple", base_path / "s3slower_enhanced_simple.c"),
    ]
    
    results = {}
    
    for name, path in versions:
        if path.exists():
            results[name] = test_bpf_version(name, path)
        else:
            print(f"\n{name}: File not found ({path})")
            results[name] = None
    
    print("\n" + "=" * 50)
    print("Summary:")
    print("-" * 50)
    
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
        print(f"\nRecommendation: Use {working[0]} version")
    else:
        print("\nERROR: No BPF versions compiled successfully!")
        print("This may indicate a kernel or BCC compatibility issue.")

if __name__ == '__main__':
    main()
