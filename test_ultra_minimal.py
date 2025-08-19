#!/usr/bin/env python3
"""
Test the ultra-minimal BPF version
"""

import sys
import os
from pathlib import Path

# Add s3slower to path
sys.path.insert(0, str(Path(__file__).parent))

def test_ultra_minimal():
    """Test the ultra-minimal BPF version directly"""
    from s3slower.s3ops_enhanced import UniversalS3Monitor
    
    print("Testing Ultra-Minimal BPF Version")
    print("=" * 40)
    
    try:
        # Force ultra-minimal version
        monitor = UniversalS3Monitor(
            enhanced=True,
            use_ultra_minimal=True,
            debug=True
        )
        
        print("✓ Ultra-minimal monitor created successfully")
        
        # Try to start it
        monitor.start()
        print("✓ Ultra-minimal monitor started successfully")
        
        # Stop it
        monitor.stop()
        print("✓ Ultra-minimal monitor stopped successfully")
        
        print("\n✅ Ultra-minimal version works!")
        return True
        
    except Exception as e:
        print(f"\n❌ Ultra-minimal version failed: {e}")
        return False

def main():
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 test_ultra_minimal.py")
        sys.exit(1)
    
    print("Ultra-Minimal BPF Test")
    print("=" * 40)
    
    if test_ultra_minimal():
        print("\nYou can now use the ultra-minimal version with:")
        print("sudo python3 -c \"from s3slower.s3ops_enhanced import UniversalS3Monitor; m = UniversalS3Monitor(use_ultra_minimal=True); m.start(); import time; time.sleep(5); m.stop()\"")
        
        print("\nOr test with elbencho:")
        print("elbencho --s3endpoints http://172.200.201.80 ...")
    else:
        print("\n❌ Even ultra-minimal version failed!")
        print("This suggests a fundamental BPF compatibility issue.")

if __name__ == '__main__':
    main()
