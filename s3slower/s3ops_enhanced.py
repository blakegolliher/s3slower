# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

"""
Enhanced S3 Operations Monitor with Universal Detection

This module implements an improved S3 latency monitoring functionality that can
detect traffic from various S3 clients including elbencho, warp, AWS CLI, etc.
It uses multiple detection layers for comprehensive coverage.
"""

import os
import re
import socket
import argparse
from threading import Thread
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import pandas as pd
from bcc import BPF
from enum import IntEnum

from s3slower.logger import get_logger, COLORS
from s3slower.utils import extract_method_url

logger = get_logger("s3ops_enhanced", COLORS.magenta)


class HttpMethod(IntEnum):
    """HTTP method enumeration matching BPF program"""
    UNKNOWN = 0
    GET = 1
    PUT = 2
    POST = 3
    DELETE = 4
    HEAD = 5
    OPTIONS = 6
    PATCH = 7
    CONNECT = 8
    TRACE = 9


# Enhanced metrics for S3 operations
STATKEYS = {
    "REQUEST_COUNT": "Number of S3 requests",
    "REQUEST_ERRORS": "Number of S3 request errors", 
    "TOTAL_LATENCY_MS": "Total S3 request latency (in milliseconds)",
    "MIN_LATENCY_MS": "Minimum S3 request latency (in milliseconds)",
    "MAX_LATENCY_MS": "Maximum S3 request latency (in milliseconds)",
    "REQUEST_BYTES": "Total S3 request bytes",
    "RESPONSE_BYTES": "Total S3 response bytes",
    "PARTIAL_REQUESTS": "Number of multi-part S3 requests",
    "FRAGMENTED_REQUESTS": "Number of fragmented HTTP requests",
    "S3_REQUESTS": "Number of confirmed S3 requests",
    "NON_S3_REQUESTS": "Number of non-S3 HTTP requests",
}


class EnhancedS3Event:
    """Represents an enhanced S3 request/response event with more details"""
    
    def __init__(self, raw_event):
        self.timestamp = raw_event.ts_us
        self.latency_us = raw_event.latency_us
        self.latency_ms = float(raw_event.latency_us) / 1000.0
        self.pid = raw_event.pid
        self.tid = raw_event.tid
        self.fd = raw_event.fd
        self.comm = raw_event.comm.decode('utf-8', 'replace')
        self.req_size = raw_event.req_size
        self.resp_size = raw_event.resp_size
        self.http_method = HttpMethod(raw_event.http_method)
        self.is_s3 = bool(raw_event.is_s3)
        self.num_segments = raw_event.num_segments
        self.raw_data = bytes(raw_event.data)
        
        # Extract URL from event
        self.url = raw_event.url.decode('utf-8', 'replace').rstrip('\x00')
        self.s3_operation = raw_event.s3_operation.decode('utf-8', 'replace').rstrip('\x00')
        
        # If s3_operation wasn't determined by BPF, try to determine it
        if self.is_s3 and not self.s3_operation:
            self.s3_operation = self._determine_s3_operation()
        
        # Parse additional S3 details from URL
        self._parse_s3_details()
    
    def _determine_s3_operation(self) -> str:
        """Determine S3 operation from method and URL patterns"""
        method_name = self.http_method.name
        
        # Basic mapping
        operation_map = {
            HttpMethod.GET: "GetObject",
            HttpMethod.PUT: "PutObject",
            HttpMethod.DELETE: "DeleteObject",
            HttpMethod.HEAD: "HeadObject",
        }
        
        if self.http_method in operation_map:
            op = operation_map[self.http_method]
            
            # Special cases for GET
            if self.http_method == HttpMethod.GET:
                if "?list-type=2" in self.url or "?prefix=" in self.url:
                    op = "ListObjectsV2"
                elif "?acl" in self.url:
                    op = "GetObjectAcl"
                elif "?tagging" in self.url:
                    op = "GetObjectTagging"
            
            # Special cases for PUT
            elif self.http_method == HttpMethod.PUT:
                if "?partNumber=" in self.url:
                    op = "UploadPart"
                elif "?acl" in self.url:
                    op = "PutObjectAcl"
                elif "?tagging" in self.url:
                    op = "PutObjectTagging"
            
            # Special cases for POST
            elif self.http_method == HttpMethod.POST:
                if "?uploads" in self.url:
                    op = "CreateMultipartUpload"
                elif "?uploadId=" in self.url:
                    op = "CompleteMultipartUpload"
                elif "?delete" in self.url:
                    op = "DeleteObjects"
            
            return op
        
        return f"{method_name}Request"
    
    def _parse_s3_details(self):
        """Parse bucket and key from URL"""
        self.bucket = ""
        self.key = ""
        
        # Simple URL parsing - format: /bucket/key or /bucket/path/to/key
        if self.url and self.url.startswith('/'):
            parts = self.url.split('?')[0].split('/')
            if len(parts) >= 2:
                self.bucket = parts[1]
                if len(parts) > 2:
                    self.key = '/'.join(parts[2:])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for storage/processing"""
        return {
            'timestamp': pd.Timestamp(self.timestamp, unit='us'),
            'latency_ms': self.latency_ms,
            'pid': self.pid,
            'tid': self.tid,
            'comm': self.comm,
            'method': self.http_method.name,
            'url': self.url,
            's3_operation': self.s3_operation,
            'bucket': self.bucket,
            'key': self.key,
            'req_size': self.req_size,
            'resp_size': self.resp_size,
            'is_s3': self.is_s3,
            'num_segments': self.num_segments,
        }


class EnhancedS3StatsCollector:
    """
    Enhanced collector with multi-layer detection capabilities
    """
    
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.hostname = os.getenv("HOSTNAME", socket.gethostname())
        self.events: List[EnhancedS3Event] = []
        self.b = None
        self._thread = None
        self._stop_collection = False
        self.use_enhanced = getattr(args, 'enhanced', True)
        
        # Load and prepare BPF program
        self._load_bpf_program()
    
    def _load_bpf_program(self):
        """Load and configure the enhanced BPF program"""
        base_path = Path(__file__).parent.parent
        
        # Choose BPF program based on mode
        if self.use_enhanced:
            bpf_file = base_path / "s3slower_enhanced.c"
            if not bpf_file.exists():
                logger.warning("Enhanced BPF not found, falling back to original")
                bpf_file = base_path / "s3slower.c"
                self.use_enhanced = False
        else:
            bpf_file = base_path / "s3slower.c"
        
        if not bpf_file.exists():
            raise FileNotFoundError(f"BPF program not found: {bpf_file}")
        
        logger.info(f"Using {'enhanced' if self.use_enhanced else 'original'} BPF program")
        
        # Read BPF program text
        with open(bpf_file, 'r') as f:
            bpf_text = f.read()
        
        # Configure BPF program with user settings
        target_pid = getattr(self.args, 'pid', 0) or 0
        min_latency_us = getattr(self.args, 'min_latency_ms', 0) * 1000
        
        # Replace configuration placeholders
        bpf_text = bpf_text.replace('TARGET_PID 0', f'TARGET_PID {target_pid}')
        bpf_text = bpf_text.replace('MIN_LATENCY_US 0', f'MIN_LATENCY_US {min_latency_us}')
        
        if getattr(self.args, 'debug', False):
            logger.debug("BPF Program:\n" + bpf_text)
        
        # Initialize BPF
        self.b = BPF(text=bpf_text)
        logger.info("BPF program loaded successfully")
    
    def attach(self):
        """Attach eBPF probes to syscalls and kernel functions"""
        if not self.b:
            raise RuntimeError("BPF program not loaded")
        
        attached_probes = []
        
        if self.use_enhanced:
            # Enhanced mode: attach to multiple syscalls and tcp functions
            
            # Write-related syscalls
            write_funcs = [
                ("write", "trace_write", ["ksys_write", "__x64_sys_write"]),
                ("send", "trace_send", ["__sys_sendto"]),
                ("sendto", "trace_sendto", ["__sys_sendto"]),
                ("sendmsg", "trace_sendmsg", ["__sys_sendmsg"]),
            ]
            
            for func_name, bpf_func, syscalls in write_funcs:
                for syscall in syscalls:
                    try:
                        self.b.attach_kprobe(event=syscall, fn_name=bpf_func)
                        attached_probes.append(f"kprobe:{syscall}")
                        logger.debug(f"✓ Attached {bpf_func} to {syscall}")
                    except Exception as e:
                        logger.debug(f"✗ Failed to attach {bpf_func} to {syscall}: {e}")
            
            # TCP-level probes
            try:
                self.b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
                attached_probes.append("kprobe:tcp_sendmsg")
                logger.debug("✓ Attached to tcp_sendmsg")
            except Exception as e:
                logger.debug(f"✗ Failed to attach to tcp_sendmsg: {e}")
            
            # Read-related syscalls
            read_funcs = [
                ("read", "trace_read", ["ksys_read", "__x64_sys_read"]),
                ("recv", "trace_recv", ["__sys_recvfrom"]),
                ("recvfrom", "trace_recvfrom", ["__sys_recvfrom"]),
            ]
            
            for func_name, bpf_func, syscalls in read_funcs:
                for syscall in syscalls:
                    try:
                        self.b.attach_kprobe(event=syscall, fn_name=bpf_func)
                        attached_probes.append(f"kprobe:{syscall}")
                        logger.debug(f"✓ Attached {bpf_func} to {syscall}")
                    except Exception as e:
                        logger.debug(f"✗ Failed to attach {bpf_func} to {syscall}: {e}")
        
        else:
            # Original mode: basic write/read syscalls only
            write_syscalls = ["ksys_write", "__x64_sys_write"]
            for syscall in write_syscalls:
                try:
                    self.b.attach_kprobe(event=syscall, fn_name="trace_write")
                    attached_probes.append(f"kprobe:{syscall}")
                    logger.debug(f"✓ Attached to {syscall}")
                except Exception as e:
                    logger.debug(f"✗ Failed to attach to {syscall}: {e}")
            
            read_syscalls = ["ksys_read", "__x64_sys_read"]
            for syscall in read_syscalls:
                try:
                    self.b.attach_kprobe(event=syscall, fn_name="trace_read")
                    attached_probes.append(f"kprobe:{syscall}")
                    logger.debug(f"✓ Attached to {syscall}")
                except Exception as e:
                    logger.debug(f"✗ Failed to attach to {syscall}: {e}")
        
        if not attached_probes:
            raise RuntimeError("Failed to attach to any syscalls")
        
        logger.info(f"Successfully attached to {len(attached_probes)} probes")
        return attached_probes
    
    def start(self):
        """Start collecting events"""
        if not self.b:
            raise RuntimeError("BPF program not loaded")
        
        self.b["events"].open_perf_buffer(self._handle_event)
        self._stop_collection = False
        self._thread = Thread(target=self._collection_loop, daemon=True)
        self._thread.start()
        logger.info("Enhanced S3 event collection started")
    
    def stop(self):
        """Stop collecting events"""
        self._stop_collection = True
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Enhanced S3 event collection stopped")
    
    def _handle_event(self, cpu, data, size):
        """Handle incoming events from eBPF"""
        try:
            raw_event = self.b["events"].event(data)
            
            if self.use_enhanced:
                event = EnhancedS3Event(raw_event)
                
                # Apply additional filtering if needed
                if getattr(self.args, 's3_only', False) and not event.is_s3:
                    return
                
                self.events.append(event)
                
                if event.is_s3:
                    logger.debug(f"Captured S3 {event.s3_operation} "
                               f"[{event.bucket}/{event.key}] "
                               f"latency: {event.latency_ms:.1f}ms "
                               f"(segments: {event.num_segments})")
                else:
                    logger.debug(f"Captured HTTP {event.http_method.name} {event.url} "
                               f"latency: {event.latency_ms:.1f}ms")
            else:
                # Use original event handling for compatibility
                from s3slower.s3ops import S3Event
                event = S3Event(raw_event)
                if event.method != "?" and event.url != "?":
                    self.events.append(event)
                    logger.debug(f"Captured {event.method} latency: {event.latency_ms:.1f}ms")
                    
        except Exception as e:
            logger.debug(f"Error processing event: {e}")
    
    def _collection_loop(self):
        """Main event collection loop"""
        while not self._stop_collection:
            try:
                self.b.perf_buffer_poll(timeout_ms=100)
            except Exception as e:
                if not self._stop_collection:
                    logger.error(f"Error in collection loop: {e}")
                break
    
    def collect_stats(self, interval: int, clear_events: bool = True) -> pd.DataFrame:
        """
        Collect and aggregate statistics from captured events
        """
        if not self.events:
            return pd.DataFrame()
        
        # Convert events to DataFrame
        event_data = [event.to_dict() for event in self.events]
        df = pd.DataFrame(event_data)
        
        if clear_events:
            self.events.clear()
        
        # Group by relevant fields
        group_fields = ['comm', 's3_operation', 'method']
        if self.use_enhanced:
            group_fields.extend(['is_s3', 'bucket'])
        
        # Aggregate statistics
        agg_dict = {
            'latency_ms': ['count', 'sum', 'min', 'max'],
            'req_size': 'sum',
            'resp_size': 'sum',
            'pid': 'first',
        }
        
        if self.use_enhanced:
            agg_dict['num_segments'] = 'mean'
            agg_dict['is_s3'] = 'first'
        
        agg_stats = df.groupby(group_fields).agg(agg_dict).reset_index()
        
        # Flatten column names
        columns = ['COMM', 'S3_OPERATION', 'METHOD']
        if self.use_enhanced:
            columns.extend(['IS_S3', 'BUCKET'])
        
        columns.extend([
            'REQUEST_COUNT', 'TOTAL_LATENCY_MS', 'MIN_LATENCY_MS', 'MAX_LATENCY_MS',
            'REQUEST_BYTES', 'RESPONSE_BYTES', 'PID'
        ])
        
        if self.use_enhanced:
            columns.append('AVG_SEGMENTS')
        
        agg_stats.columns = columns
        
        # Add metadata
        timestamp = pd.Timestamp.utcnow().astimezone(None).floor("s")
        agg_stats['TIMESTAMP'] = timestamp
        agg_stats['HOSTNAME'] = self.hostname
        agg_stats['INTERVAL'] = interval
        
        # Add computed metrics
        agg_stats['AVG_LATENCY_MS'] = agg_stats['TOTAL_LATENCY_MS'] / agg_stats['REQUEST_COUNT']
        agg_stats['REQUEST_ERRORS'] = 0  # TODO: Implement error detection
        
        if self.use_enhanced:
            # Count S3 vs non-S3 requests
            s3_mask = agg_stats['IS_S3'] == True
            agg_stats.loc[s3_mask, 'S3_REQUESTS'] = agg_stats.loc[s3_mask, 'REQUEST_COUNT']
            agg_stats.loc[~s3_mask, 'NON_S3_REQUESTS'] = agg_stats.loc[~s3_mask, 'REQUEST_COUNT']
            agg_stats.fillna(0, inplace=True)
        
        logger.debug(f"Collected {len(agg_stats)} aggregated statistics")
        
        return agg_stats


class UniversalS3Monitor:
    """
    High-level interface for universal S3 latency monitoring
    with fallback support for different detection methods
    """
    
    def __init__(self, 
                 pid: Optional[int] = None,
                 min_latency_ms: int = 0,
                 enhanced: bool = True,
                 s3_only: bool = False,
                 debug: bool = False):
        """
        Initialize universal S3 monitor
        
        Args:
            pid: Process ID to monitor (None for all processes)
            min_latency_ms: Minimum latency threshold in milliseconds
            enhanced: Use enhanced detection (default: True)
            s3_only: Only capture S3 traffic (default: False)
            debug: Enable debug logging
        """
        # Create arguments namespace
        args = argparse.Namespace()
        args.pid = pid
        args.min_latency_ms = min_latency_ms
        args.enhanced = enhanced
        args.s3_only = s3_only
        args.debug = debug
        
        self.collector = EnhancedS3StatsCollector(args)
        self._attached = False
    
    def start(self):
        """Start monitoring S3 operations"""
        if not self._attached:
            self.collector.attach()
            self._attached = True
        self.collector.start()
    
    def stop(self):
        """Stop monitoring S3 operations"""
        self.collector.stop()
    
    def get_stats(self, interval: int = 5) -> pd.DataFrame:
        """Get collected statistics"""
        return self.collector.collect_stats(interval)
    
    def get_events(self) -> List[EnhancedS3Event]:
        """Get raw events for detailed analysis"""
        return list(self.collector.events)
    
    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()


# Example usage function
def test_universal_s3_detection():
    """
    Test function to demonstrate universal S3 detection
    """
    import time
    
    print("Starting Universal S3 Monitor...")
    print("This will detect S3 traffic from:")
    print("- warp")
    print("- elbencho") 
    print("- AWS CLI")
    print("- Any S3-compatible client")
    print("")
    
    with UniversalS3Monitor(enhanced=True, debug=True) as monitor:
        print("Monitoring for 60 seconds...")
        print("Run your S3 workload now (warp, elbencho, etc.)")
        
        for i in range(12):  # 12 x 5 seconds = 60 seconds
            time.sleep(5)
            stats = monitor.get_stats(5)
            
            if not stats.empty:
                print(f"\n--- Stats at {i*5} seconds ---")
                for _, row in stats.iterrows():
                    if row.get('IS_S3', True):  # Default to True for backward compat
                        print(f"S3 {row['S3_OPERATION']} from {row['COMM']} "
                              f"[{row.get('BUCKET', 'N/A')}]: "
                              f"{row['REQUEST_COUNT']} requests, "
                              f"avg latency: {row['AVG_LATENCY_MS']:.1f}ms")
                    else:
                        print(f"HTTP {row['METHOD']} from {row['COMM']}: "
                              f"{row['REQUEST_COUNT']} requests, "
                              f"avg latency: {row['AVG_LATENCY_MS']:.1f}ms")
        
        print("\nFinal event summary:")
        events = monitor.get_events()
        s3_events = [e for e in events if e.is_s3]
        print(f"Total events captured: {len(events)}")
        print(f"S3 events: {len(s3_events)}")
        print(f"Non-S3 HTTP events: {len(events) - len(s3_events)}")
        
        if s3_events:
            print("\nS3 Operations by type:")
            op_counts = {}
            for event in s3_events:
                op_counts[event.s3_operation] = op_counts.get(event.s3_operation, 0) + 1
            
            for op, count in sorted(op_counts.items()):
                print(f"  {op}: {count}")


if __name__ == "__main__":
    test_universal_s3_detection()
