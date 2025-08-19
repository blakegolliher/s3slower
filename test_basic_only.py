#!/usr/bin/env python3
"""
Test the basic-only BPF version
"""

import sys
import os
from pathlib import Path

# Add s3slower to path
sys.path.insert(0, str(Path(__file__).parent))

def test_basic_only():
    """Test the basic-only BPF version directly"""
    from s3slower.s3ops_enhanced import UniversalS3Monitor
    
    print("Testing Basic-Only BPF Version")
    print("=" * 40)
    
    try:
        # Force basic-only version
        monitor = UniversalS3Monitor(
            enhanced=True,
            use_basic_only=True,
            debug=True
        )
        
        print("✓ Basic-only monitor created successfully")
        
        # Try to start it
        monitor.start()
        print("✓ Basic-only monitor started successfully")
        
        # Stop it
        monitor.stop()
        print("✓ Basic-only monitor stopped successfully")
        
        print("\n✅ Basic-only version works!")
        return True
        
    except Exception as e:
        print(f"\n❌ Basic-only version failed: {e}")
        return False

def main():
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 test_basic_only.py")
        sys.exit(1)
    
    print("Basic-Only BPF Test")
    print("=" * 40)
    
    if test_basic_only():
        print("\nYou can now use the basic-only version with:")
        print("sudo python3 -c \"from s3slower.s3ops_enhanced import UniversalS3Monitor; m = UniversalS3Monitor(use_basic_only=True); m.start(); import time; time.sleep(5); m.stop()\"")
        
        print("\nOr test with elbencho:")
        print("elbencho --s3endpoints http://172.200.201.80 ...")
        
        print("\nNote: Basic-only version provides minimal features but maximum compatibility.")
        print("It will detect HTTP requests/responses and measure latency, but with limited S3 detection.")
    else:
        print("\n❌ Even basic-only version failed!")
        print("This suggests a fundamental BPF compatibility issue.")

if __name__ == '__main__':
    main()
