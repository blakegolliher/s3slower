#!/usr/bin/env python3
"""
Basic test script to verify enhanced BPF compilation works
"""

import sys
import time
import traceback
from pathlib import Path

# Add s3slower to path
sys.path.insert(0, str(Path(__file__).parent))

def test_bpf_compilation():
    """Test that the enhanced BPF program compiles correctly"""
    print("Testing Enhanced BPF Compilation...")
    print("-" * 50)
    
    try:
        from s3slower.s3ops_enhanced import EnhancedS3StatsCollector
        import argparse
        
        # Create args
        args = argparse.Namespace(
            pid=None,
            min_latency_ms=0,
            enhanced=True,
            s3_only=False,
            debug=True
        )
        
        print("1. Loading enhanced BPF program...")
        collector = EnhancedS3StatsCollector(args)
        print("   ✓ BPF program loaded successfully")
        
        print("\n2. Attaching probes...")
        probes = collector.attach()
        print(f"   ✓ Attached {len(probes)} probes:")
        for probe in probes[:5]:  # Show first 5
            print(f"     - {probe}")
        if len(probes) > 5:
            print(f"     ... and {len(probes) - 5} more")
        
        print("\n3. Starting collection...")
        collector.start()
        print("   ✓ Collection started")
        
        print("\n4. Running for 3 seconds...")
        time.sleep(3)
        
        print("\n5. Checking for events...")
        events = collector.events
        if events:
            print(f"   ✓ Captured {len(events)} events")
        else:
            print("   ℹ No events captured (this is normal if no HTTP traffic)")
        
        print("\n6. Stopping collection...")
        collector.stop()
        print("   ✓ Collection stopped")
        
        print("\n✅ Enhanced BPF test PASSED!")
        return True
        
    except Exception as e:
        print(f"\n❌ Enhanced BPF test FAILED!")
        print(f"Error: {e}")
        print("\nTraceback:")
        traceback.print_exc()
        return False


def test_original_mode():
    """Test that original mode still works"""
    print("\n\nTesting Original Mode Compatibility...")
    print("-" * 50)
    
    try:
        from s3slower.s3ops import S3LatencyMonitor
        
        print("1. Creating original monitor...")
        monitor = S3LatencyMonitor()
        
        print("2. Starting monitor...")
        monitor.start()
        print("   ✓ Original mode started")
        
        time.sleep(2)
        
        print("3. Stopping monitor...")
        monitor.stop()
        print("   ✓ Original mode stopped")
        
        print("\n✅ Original mode test PASSED!")
        return True
        
    except Exception as e:
        print(f"\n❌ Original mode test FAILED!")
        print(f"Error: {e}")
        traceback.print_exc()
        return False


def main():
    import os
    
    print("S3 Latency Monitor - Basic Functionality Test")
    print("=" * 50)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges for BPF")
        print("Please run with: sudo python3 test_basic.py")
        sys.exit(1)
    
    # Run tests
    enhanced_ok = test_bpf_compilation()
    original_ok = test_original_mode()
    
    print("\n" + "=" * 50)
    print("Test Summary:")
    print(f"  Enhanced BPF: {'PASSED' if enhanced_ok else 'FAILED'}")
    print(f"  Original Mode: {'PASSED' if original_ok else 'FAILED'}")
    
    if enhanced_ok and original_ok:
        print("\n✅ All tests PASSED!")
        print("\nYou can now test with actual S3 traffic:")
        print("  - sudo python3 test_elbencho_detection.py")
        print("  - sudo python3 example_usage.py")
        return 0
    else:
        print("\n❌ Some tests FAILED!")
        print("Please check the error messages above.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
