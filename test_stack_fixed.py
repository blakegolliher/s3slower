#!/usr/bin/env python3
"""
Test the stack-fixed BPF version
"""

import sys
import os
from pathlib import Path

# Add s3slower to path
sys.path.insert(0, str(Path(__file__).parent))

def test_stack_fixed():
    """Test the stack-fixed BPF version directly"""
    from s3slower.s3ops_enhanced import UniversalS3Monitor
    
    print("Testing Stack-Fixed BPF Version")
    print("=" * 40)
    
    try:
        # Force stack-fixed version
        monitor = UniversalS3Monitor(
            enhanced=True,
            use_stack_fixed=True,
            debug=True
        )
        
        print("✓ Stack-fixed monitor created successfully")
        
        # Try to start it
        monitor.start()
        print("✓ Stack-fixed monitor started successfully")
        
        # Stop it
        monitor.stop()
        print("✓ Stack-fixed monitor stopped successfully")
        
        print("\n✅ Stack-fixed version works!")
        return True
        
    except Exception as e:
        print(f"\n❌ Stack-fixed version failed: {e}")
        return False

def main():
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 test_stack_fixed.py")
        sys.exit(1)
    
    print("Stack-Fixed BPF Test")
    print("=" * 40)
    
    if test_stack_fixed():
        print("\nYou can now use the stack-fixed version with:")
        print("sudo python3 example_usage.py")
        print("\nOr force it with:")
        print("sudo python3 -c \"from s3slower.s3ops_enhanced import UniversalS3Monitor; m = UniversalS3Monitor(use_stack_fixed=True); m.start(); import time; time.sleep(5); m.stop()\"")
    else:
        print("\nStack-fixed version failed. Try the simple version instead.")

if __name__ == '__main__':
    main()
