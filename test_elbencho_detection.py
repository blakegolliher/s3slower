#!/usr/bin/env python3
"""
Test script specifically for detecting elbencho S3 traffic
"""

import sys
import os
import time
import subprocess
from pathlib import Path

# Add the s3slower module to path
sys.path.insert(0, str(Path(__file__).parent))

from s3slower.s3ops_enhanced import UniversalS3Monitor
from s3slower.logger import get_logger, COLORS

logger = get_logger("elbencho_test", COLORS.green)


def find_elbencho_process():
    """Find elbencho process ID"""
    try:
        result = subprocess.run(['pgrep', '-f', 'elbencho'], 
                              capture_output=True, text=True)
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            return int(pids[0])
    except:
        pass
    return None


def analyze_elbencho_traffic():
    """
    Analyze why elbencho traffic might not be detected
    """
    logger.info("Analyzing elbencho S3 traffic detection...")
    logger.info("This script will help identify why elbencho traffic isn't detected")
    logger.info("")
    
    # Check if elbencho is running
    elbencho_pid = find_elbencho_process()
    if elbencho_pid:
        logger.info(f"Found elbencho process: PID {elbencho_pid}")
    else:
        logger.warning("elbencho process not found. Please start elbencho first.")
        logger.info("Example: elbencho --s3endpoints http://your-s3-server:9000 "
                   "--s3accesskey KEY --s3secretkey SECRET -b BUCKET -n 10 -N 10 -s 1M -t 4")
        return
    
    # Key insight about elbencho
    logger.info("\nImportant: elbencho uses the AWS SDK, which may:")
    logger.info("1. Use HTTPS by default (not detectable with current HTTP-only approach)")
    logger.info("2. Use connection pooling and keep-alive")
    logger.info("3. Buffer requests differently than expected")
    logger.info("4. Use different syscalls (e.g., sendmsg instead of write)")
    
    # Test with enhanced monitor
    logger.info("\nStarting enhanced monitor...")
    
    with UniversalS3Monitor(pid=elbencho_pid, enhanced=True, debug=True) as monitor:
        logger.info("Monitoring elbencho traffic for 30 seconds...")
        logger.info("Make sure elbencho is actively making S3 requests")
        
        for i in range(6):  # 6 x 5 = 30 seconds
            time.sleep(5)
            
            events = monitor.get_events()
            if events:
                logger.info(f"\nCaptured {len(events)} events after {(i+1)*5} seconds:")
                
                # Show last few events
                for event in events[-3:]:
                    if hasattr(event, 'is_s3'):
                        logger.info(f"  {'S3' if event.is_s3 else 'HTTP'}: "
                                   f"{event.comm} {event.http_method.name} "
                                   f"{event.url[:50]}... "
                                   f"latency: {event.latency_ms:.1f}ms")
            else:
                logger.debug(f"No events captured yet ({(i+1)*5}s elapsed)")
        
        # Final analysis
        logger.info("\n=== Analysis Results ===")
        
        if not events:
            logger.warning("No HTTP traffic detected from elbencho!")
            logger.info("\nPossible reasons:")
            logger.info("1. elbencho is using HTTPS (check --s3endpoints parameter)")
            logger.info("2. elbencho hasn't started making requests yet")
            logger.info("3. Kernel compatibility issue with probes")
            logger.info("\nRecommendations:")
            logger.info("1. Ensure elbencho uses HTTP: --s3endpoints http://...")
            logger.info("2. Use a simple S3 operation like listing: elbencho --s3endpoints http://... -b BUCKET --list")
            logger.info("3. Check dmesg for BPF-related errors: sudo dmesg | tail")
        else:
            s3_events = [e for e in events if getattr(e, 'is_s3', False)]
            logger.info(f"Total events captured: {len(events)}")
            logger.info(f"S3 events: {len(s3_events)}")
            
            if s3_events:
                logger.info("✓ Successfully detected elbencho S3 traffic!")
                
                # Show S3 operation breakdown
                ops = {}
                for e in s3_events:
                    op = getattr(e, 's3_operation', 'Unknown')
                    ops[op] = ops.get(op, 0) + 1
                
                logger.info("\nS3 Operations detected:")
                for op, count in ops.items():
                    logger.info(f"  {op}: {count}")
            else:
                logger.warning("HTTP traffic detected but no S3-specific patterns found")
                logger.info("The traffic might be:")
                logger.info("- Non-S3 HTTP traffic")
                logger.info("- S3 traffic with unusual headers")
                logger.info("- Fragmented requests not fully reassembled")


def suggest_elbencho_test_commands():
    """Suggest test commands for elbencho"""
    logger.info("\n=== Suggested elbencho Test Commands ===")
    logger.info("\nFor S3-compatible storage (MinIO, Ceph, etc.):")
    logger.info("  # List objects (simple test):")
    logger.info("  elbencho --s3endpoints http://localhost:9000 --s3accesskey minioadmin "
               "--s3secretkey minioadmin -b testbucket --list")
    logger.info("\n  # Write test:")
    logger.info("  elbencho --s3endpoints http://localhost:9000 --s3accesskey minioadmin "
               "--s3secretkey minioadmin -b testbucket -n 10 -N 10 -s 1M -t 4 -w")
    logger.info("\n  # Read test:")
    logger.info("  elbencho --s3endpoints http://localhost:9000 --s3accesskey minioadmin "
               "--s3secretkey minioadmin -b testbucket -n 10 -N 10 -s 1M -t 4 -r")
    
    logger.info("\nIMPORTANT: Use http:// not https:// for the endpoint!")


def check_https_usage():
    """Check if elbencho might be using HTTPS"""
    logger.info("\n=== Checking for HTTPS Usage ===")
    
    try:
        # Look for TLS/SSL connections
        result = subprocess.run(['sudo', 'ss', '-tpn'], 
                              capture_output=True, text=True)
        
        if 'elbencho' in result.stdout:
            logger.info("elbencho network connections found:")
            for line in result.stdout.split('\n'):
                if 'elbencho' in line:
                    if ':443' in line or ':9001' in line:  # Common HTTPS ports
                        logger.warning(f"Possible HTTPS connection: {line}")
                    else:
                        logger.info(f"Connection: {line}")
    except Exception as e:
        logger.debug(f"Could not check connections: {e}")


def main():
    logger.info("elbencho S3 Detection Test Tool")
    logger.info("=" * 50)
    
    # Check if running as root
    if os.geteuid() != 0:
        logger.error("This script must be run as root/sudo for BPF access")
        sys.exit(1)
    
    # Run analysis
    analyze_elbencho_traffic()
    
    # Check for HTTPS
    check_https_usage()
    
    # Show suggestions
    suggest_elbencho_test_commands()
    
    logger.info("\nFor more detailed debugging, run:")
    logger.info("  sudo python3 debug_s3_detection.py --all")


if __name__ == '__main__':
    main()
