#!/usr/bin/env python3
"""
Example usage of the enhanced S3 latency monitor
Shows how to use both original and enhanced modes
"""

import time
import sys
from pathlib import Path

# Add s3slower to path
sys.path.insert(0, str(Path(__file__).parent))

from s3slower.s3ops import S3LatencyMonitor as OriginalMonitor
from s3slower.s3ops_enhanced import UniversalS3Monitor as EnhancedMonitor


def compare_detection_modes():
    """Compare original vs enhanced detection"""
    print("S3 Latency Monitor - Detection Mode Comparison")
    print("=" * 60)
    
    # Test 1: Original mode
    print("\n1. Testing ORIGINAL detection mode (5 seconds)...")
    print("   - Small 64-byte buffer")
    print("   - Basic write/read syscalls only")
    print("   - No S3-specific detection")
    
    with OriginalMonitor() as monitor:
        time.sleep(5)
        stats = monitor.get_stats(5)
        
        if not stats.empty:
            print(f"\n   Captured {len(stats)} operation types:")
            for _, row in stats.iterrows():
                print(f"   - {row['COMM']}: {row['REQUEST_COUNT']} requests")
        else:
            print("   No events captured")
    
    # Test 2: Enhanced mode  
    print("\n2. Testing ENHANCED detection mode (5 seconds)...")
    print("   - Large 512-byte buffer")
    print("   - Multiple syscall types")
    print("   - S3-specific pattern detection")
    print("   - Multi-segment reassembly")
    
    with EnhancedMonitor(enhanced=True) as monitor:
        time.sleep(5)
        events = monitor.get_events()
        stats = monitor.get_stats(5)
        
        if events:
            print(f"\n   Captured {len(events)} total events")
            
            # Count S3 vs non-S3
            s3_events = [e for e in events if e.is_s3]
            print(f"   - S3 events: {len(s3_events)}")
            print(f"   - Non-S3 HTTP events: {len(events) - len(s3_events)}")
            
            # Show sample events
            print("\n   Sample events:")
            for event in events[:3]:
                if event.is_s3:
                    print(f"   - S3 {event.s3_operation}: {event.bucket}/{event.key}")
                else:
                    print(f"   - HTTP {event.http_method.name}: {event.url}")
        else:
            print("   No events captured")


def production_monitoring_example():
    """Example of production monitoring setup"""
    print("\n\nProduction Monitoring Example")
    print("=" * 60)
    
    # Configuration
    config = {
        'enhanced': True,           # Use enhanced detection
        'min_latency_ms': 100,     # Only show requests > 100ms
        's3_only': True,           # Filter to S3 traffic only
        'debug': False,            # Disable debug logging
    }
    
    print("Configuration:")
    for key, value in config.items():
        print(f"  {key}: {value}")
    
    print("\nMonitoring for 20 seconds...")
    
    with EnhancedMonitor(**config) as monitor:
        for i in range(4):  # 4 x 5 = 20 seconds
            time.sleep(5)
            
            stats = monitor.get_stats(5)
            if not stats.empty:
                print(f"\n[{(i+1)*5}s] Latest statistics:")
                
                # Show top operations by latency
                top_ops = stats.nlargest(3, 'AVG_LATENCY_MS')
                for _, op in top_ops.iterrows():
                    print(f"  {op['S3_OPERATION']} ({op['COMM']}): "
                          f"{op['REQUEST_COUNT']} reqs, "
                          f"avg {op['AVG_LATENCY_MS']:.1f}ms, "
                          f"max {op['MAX_LATENCY_MS']:.1f}ms")


def targeted_process_monitoring():
    """Example of monitoring a specific process"""
    print("\n\nTargeted Process Monitoring Example")
    print("=" * 60)
    
    import subprocess
    
    # Find elbencho process
    try:
        result = subprocess.run(['pgrep', '-f', 'elbencho'], 
                              capture_output=True, text=True)
        if result.stdout.strip():
            pid = int(result.stdout.strip().split('\n')[0])
            print(f"Found elbencho process: PID {pid}")
            
            print("\nMonitoring only elbencho traffic...")
            with EnhancedMonitor(pid=pid, enhanced=True) as monitor:
                time.sleep(10)
                
                events = monitor.get_events()
                if events:
                    print(f"\nCaptured {len(events)} events from elbencho")
                    
                    # Group by operation
                    ops = {}
                    for e in events:
                        if e.is_s3:
                            ops[e.s3_operation] = ops.get(e.s3_operation, 0) + 1
                    
                    print("\nOperations breakdown:")
                    for op, count in sorted(ops.items()):
                        print(f"  {op}: {count}")
                else:
                    print("\nNo events captured from elbencho")
                    print("Make sure elbencho is using HTTP (not HTTPS)")
        else:
            print("elbencho process not found")
            print("Start elbencho with HTTP endpoint first")
            
    except Exception as e:
        print(f"Error finding process: {e}")


def main():
    """Run all examples"""
    
    # Check if running as root
    import os
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges for BPF")
        print("Please run with: sudo python3 example_usage.py")
        sys.exit(1)
    
    print("S3 Latency Monitor - Usage Examples")
    print("Make sure you have S3 traffic running (warp, elbencho, etc.)")
    print("")
    
    # Run examples
    compare_detection_modes()
    production_monitoring_example()
    targeted_process_monitoring()
    
    print("\n\nFor more examples, see:")
    print("  - test_elbencho_detection.py")
    print("  - debug_s3_detection.py")
    print("  - README_ENHANCED.md")


if __name__ == '__main__':
    main()
