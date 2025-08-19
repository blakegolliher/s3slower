#!/usr/bin/env python3
"""
Test if the original s3slower.c works
"""

import sys
import os
from pathlib import Path

# Add s3slower to path
sys.path.insert(0, str(Path(__file__).parent))

def test_original():
    """Test the original s3slower functionality"""
    try:
        from s3slower.s3ops import S3LatencyMonitor
        
        print("Testing Original s3slower.c")
        print("=" * 40)
        
        # Create original monitor
        monitor = S3LatencyMonitor()
        print("✓ Original monitor created successfully")
        
        # Try to start it
        monitor.start()
        print("✓ Original monitor started successfully")
        
        # Stop it
        monitor.stop()
        print("✓ Original monitor stopped successfully")
        
        print("\n✅ Original s3slower.c works!")
        return True
        
    except Exception as e:
        print(f"\n❌ Original s3slower.c failed: {e}")
        return False

def main():
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 test_original_working.py")
        sys.exit(1)
    
    print("Original s3slower.c Test")
    print("=" * 40)
    
    if test_original():
        print("\nGreat! The original s3slower.c works.")
        print("This means your system supports basic BPF functionality.")
        print("\nThe issue with the enhanced versions might be:")
        print("1. Syscall attachment problems")
        print("2. BPF verifier restrictions")
        print("3. Kernel compatibility issues")
        print("\nYou can use the original version for basic S3 monitoring:")
        print("sudo python3 -c \"from s3slower.s3ops import S3LatencyMonitor; m = S3LatencyMonitor(); m.start(); import time; time.sleep(5); m.stop()\"")
    else:
        print("\n❌ Even the original s3slower.c failed!")
        print("This suggests a fundamental BPF or system issue.")

if __name__ == '__main__':
    main()
