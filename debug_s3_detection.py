#!/usr/bin/env python3
"""
Debug script for S3 traffic detection
This helps identify why certain S3 clients might not be detected
"""

import sys
import os
import time
import argparse
import subprocess
from pathlib import Path

# Add the s3slower module to path
sys.path.insert(0, str(Path(__file__).parent))

from s3slower.s3ops_enhanced import UniversalS3Monitor, EnhancedS3StatsCollector
from s3slower.logger import get_logger, COLORS

logger = get_logger("debug_s3", COLORS.cyan)


def check_process_syscalls(process_name: str):
    """Use strace to check what syscalls a process is using"""
    logger.info(f"Checking syscalls used by {process_name}...")
    
    try:
        # Find the process
        result = subprocess.run(['pgrep', '-f', process_name], 
                              capture_output=True, text=True)
        if not result.stdout.strip():
            logger.warning(f"Process '{process_name}' not found")
            return
        
        pids = result.stdout.strip().split('\n')
        logger.info(f"Found PIDs: {pids}")
        
        for pid in pids[:1]:  # Check first PID only
            logger.info(f"Running strace on PID {pid} for 5 seconds...")
            try:
                # Run strace for network-related syscalls
                strace_cmd = [
                    'sudo', 'strace', '-p', pid, '-e', 
                    'trace=write,writev,send,sendto,sendmsg,sendmmsg,read,readv,recv,recvfrom,recvmsg',
                    '-s', '512',  # Show 512 bytes of string data
                    '-f',  # Follow forks
                    '-T',  # Show time spent in syscalls
                ]
                
                proc = subprocess.Popen(strace_cmd, 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.STDOUT,
                                      text=True)
                
                # Collect output for 5 seconds
                time.sleep(5)
                proc.terminate()
                output, _ = proc.communicate(timeout=1)
                
                # Analyze output
                logger.info("Syscall analysis:")
                syscall_counts = {}
                http_detected = False
                s3_patterns = []
                
                for line in output.split('\n'):
                    # Count syscalls
                    for syscall in ['write', 'writev', 'send', 'sendto', 'sendmsg', 
                                   'read', 'readv', 'recv', 'recvfrom', 'recvmsg']:
                        if f'{syscall}(' in line:
                            syscall_counts[syscall] = syscall_counts.get(syscall, 0) + 1
                            
                            # Check for HTTP patterns
                            if any(method in line for method in ['GET ', 'PUT ', 'POST ', 'DELETE ', 'HEAD ']):
                                http_detected = True
                                logger.debug(f"HTTP detected: {line[:200]}")
                            
                            # Check for S3 patterns
                            if 'x-amz-' in line or 'AWS4-HMAC-SHA256' in line:
                                s3_patterns.append(line[:200])
                
                logger.info(f"Syscall counts: {syscall_counts}")
                logger.info(f"HTTP detected: {http_detected}")
                if s3_patterns:
                    logger.info(f"S3 patterns found: {len(s3_patterns)}")
                    for pattern in s3_patterns[:3]:
                        logger.debug(f"  {pattern}")
                
            except subprocess.TimeoutExpired:
                logger.warning("strace timeout")
            except Exception as e:
                logger.error(f"Error running strace: {e}")
                
    except Exception as e:
        logger.error(f"Error checking process: {e}")


def test_detection_modes():
    """Test different detection modes to see what works"""
    logger.info("Testing different detection modes...")
    
    # Test 1: Original mode
    logger.info("\n=== Test 1: Original detection mode ===")
    args1 = argparse.Namespace(pid=None, min_latency_ms=0, enhanced=False, 
                              s3_only=False, debug=True)
    
    try:
        collector1 = EnhancedS3StatsCollector(args1)
        probes1 = collector1.attach()
        logger.info(f"Original mode attached {len(probes1)} probes: {probes1}")
        collector1.start()
        time.sleep(3)
        collector1.stop()
        logger.info(f"Captured {len(collector1.events)} events in original mode")
    except Exception as e:
        logger.error(f"Original mode error: {e}")
    
    # Test 2: Enhanced mode
    logger.info("\n=== Test 2: Enhanced detection mode ===")
    args2 = argparse.Namespace(pid=None, min_latency_ms=0, enhanced=True, 
                              s3_only=False, debug=True)
    
    try:
        collector2 = EnhancedS3StatsCollector(args2)
        probes2 = collector2.attach()
        logger.info(f"Enhanced mode attached {len(probes2)} probes: {probes2}")
        collector2.start()
        time.sleep(3)
        collector2.stop()
        logger.info(f"Captured {len(collector2.events)} events in enhanced mode")
        
        # Show event details
        for i, event in enumerate(collector2.events[:5]):
            logger.info(f"Event {i}: {event.comm} {event.http_method.name if hasattr(event, 'http_method') else event.method} "
                       f"{event.url} (S3: {getattr(event, 'is_s3', 'N/A')})")
            
    except Exception as e:
        logger.error(f"Enhanced mode error: {e}")


def monitor_with_diagnostics(duration: int = 30):
    """Run monitoring with detailed diagnostics"""
    logger.info(f"Starting diagnostic monitoring for {duration} seconds...")
    
    with UniversalS3Monitor(enhanced=True, debug=True) as monitor:
        logger.info("Monitor started. Detailed event logging enabled.")
        logger.info("Run your S3 workload now (elbencho, warp, etc.)")
        
        start_time = time.time()
        last_event_count = 0
        
        while time.time() - start_time < duration:
            time.sleep(2)
            
            events = monitor.get_events()
            new_events = len(events) - last_event_count
            
            if new_events > 0:
                logger.info(f"Captured {new_events} new events (total: {len(events)})")
                
                # Show recent events
                for event in events[last_event_count:last_event_count+5]:
                    if hasattr(event, 'is_s3') and event.is_s3:
                        logger.info(f"  S3: {event.comm} {event.s3_operation} "
                                   f"{event.bucket}/{event.key} "
                                   f"latency: {event.latency_ms:.1f}ms")
                    else:
                        method = event.http_method.name if hasattr(event, 'http_method') else event.method
                        logger.info(f"  HTTP: {event.comm} {method} {event.url} "
                                   f"latency: {event.latency_ms:.1f}ms")
                
                last_event_count = len(events)
            else:
                logger.debug("No new events captured")
        
        # Final summary
        logger.info("\n=== Final Summary ===")
        stats = monitor.get_stats(duration)
        
        if not stats.empty:
            logger.info(f"Total unique operations: {len(stats)}")
            
            # Group by application
            apps = stats.groupby('COMM').agg({
                'REQUEST_COUNT': 'sum',
                'AVG_LATENCY_MS': 'mean'
            })
            
            logger.info("\nRequests by application:")
            for comm, row in apps.iterrows():
                logger.info(f"  {comm}: {row['REQUEST_COUNT']} requests, "
                           f"avg latency: {row['AVG_LATENCY_MS']:.1f}ms")
            
            # S3 vs non-S3
            if 'IS_S3' in stats.columns:
                s3_stats = stats[stats['IS_S3'] == True]
                non_s3_stats = stats[stats['IS_S3'] == False]
                
                logger.info(f"\nS3 requests: {s3_stats['REQUEST_COUNT'].sum()}")
                logger.info(f"Non-S3 HTTP requests: {non_s3_stats['REQUEST_COUNT'].sum()}")
        else:
            logger.warning("No statistics collected")
            logger.info("\nTroubleshooting tips:")
            logger.info("1. Make sure you're running as root/sudo")
            logger.info("2. Check if HTTP traffic is being generated")
            logger.info("3. Try running with --debug for more details")
            logger.info("4. Check if the application uses HTTPS (not supported yet)")


def main():
    parser = argparse.ArgumentParser(description='Debug S3 detection issues')
    parser.add_argument('--check-process', type=str, 
                       help='Check syscalls used by a process (requires sudo)')
    parser.add_argument('--test-modes', action='store_true',
                       help='Test different detection modes')
    parser.add_argument('--monitor', type=int, default=0,
                       help='Run diagnostic monitoring for N seconds')
    parser.add_argument('--all', action='store_true',
                       help='Run all diagnostic tests')
    
    args = parser.parse_args()
    
    if not any([args.check_process, args.test_modes, args.monitor, args.all]):
        parser.print_help()
        return
    
    logger.info("S3 Detection Diagnostic Tool")
    logger.info("=" * 50)
    
    if args.all or args.test_modes:
        test_detection_modes()
    
    if args.all or args.check_process:
        if args.check_process:
            check_process_syscalls(args.check_process)
        else:
            # Check common S3 tools
            for tool in ['elbencho', 'warp', 'aws']:
                logger.info(f"\nChecking {tool}...")
                check_process_syscalls(tool)
    
    if args.all or args.monitor:
        duration = args.monitor if args.monitor > 0 else 30
        monitor_with_diagnostics(duration)


if __name__ == '__main__':
    main()
