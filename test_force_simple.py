#!/usr/bin/env python3
"""
Force use of simple BPF program to test
"""

import sys
import time
import argparse
from pathlib import Path

# Add s3slower to path
sys.path.insert(0, str(Path(__file__).parent))

from s3slower.s3ops_enhanced import EnhancedS3StatsCollector

def test_simple_version():
    print("Testing SIMPLE BPF version directly...")
    print("-" * 50)
    
    # Create args that force simple version
    args = argparse.Namespace(
        pid=None,
        min_latency_ms=0,
        enhanced=True,
        s3_only=False,
        debug=True,
        use_simple=True,  # Force simple version
        use_compat=False
    )
    
    try:
        print("Loading simple BPF program...")
        collector = EnhancedS3StatsCollector(args)
        print("✓ Simple BPF program loaded successfully!")
        
        print("\nAttaching probes...")
        probes = collector.attach()
        print(f"✓ Attached {len(probes)} probes")
        
        print("\nStarting collection...")
        collector.start()
        print("✓ Collection started")
        
        print("\nRunning for 5 seconds...")
        time.sleep(5)
        
        print("\nStopping...")
        collector.stop()
        print("✓ Success!")
        
        return True
        
    except Exception as e:
        print(f"\n✗ Failed: {e}")
        return False

def main():
    import os
    
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 test_force_simple.py")
        sys.exit(1)
    
    print("Force Simple BPF Test")
    print("=" * 50)
    
    if test_simple_version():
        print("\n✅ Simple version works!")
        print("\nYou can now test with actual S3 traffic.")
        print("The simple version has basic S3 detection capabilities.")
    else:
        print("\n❌ Even simple version failed!")
        print("This suggests a more fundamental issue with BPF on this system.")

if __name__ == '__main__':
    main()
