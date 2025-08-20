# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

"""
S3 Operations Monitor

This module implements the core S3 latency monitoring functionality using eBPF.
It tracks HTTP requests and responses to S3 services, extracting latency metrics
and S3 operation details.
"""

import os
import re
import socket
import argparse
from threading import Thread
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
from bcc import BPF

from s3slower.logger import get_logger, COLORS
from s3slower.utils import extract_method_url

logger = get_logger("s3ops", COLORS.magenta)


# Metrics that we collect for S3 operations
STATKEYS = {
    "REQUEST_COUNT": "Number of S3 requests",
    "REQUEST_ERRORS": "Number of S3 request errors", 
    "TOTAL_LATENCY_MS": "Total S3 request latency (in milliseconds)",
    "MIN_LATENCY_MS": "Minimum S3 request latency (in milliseconds)",
    "MAX_LATENCY_MS": "Maximum S3 request latency (in milliseconds)",
    "REQUEST_BYTES": "Total S3 request bytes",
    "RESPONSE_BYTES": "Total S3 response bytes",
    "PARTIAL_REQUESTS": "Number of multi-part S3 requests",
}


class S3Event:
    """Represents a single S3 request/response event"""
    
    # Client type constants
    CLIENT_TYPES = {
        0: "unknown",
        1: "warp", 
        2: "elbencho",
        3: "boto3",
        4: "s3cmd",
        5: "awscli"
    }
    
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
        self.actual_resp_bytes = raw_event.actual_resp_bytes
        self.is_partial = bool(raw_event.is_partial)
        self.client_type = self.CLIENT_TYPES.get(raw_event.client_type, "unknown")
        self.raw_data = bytes(raw_event.data[:64])
        
        # Extract HTTP method, URL, and S3 operation
        self.method, self.url, self.s3_operation = extract_method_url(self.raw_data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for storage/processing"""
        return {
            'timestamp': pd.Timestamp(self.timestamp, unit='us'),
            'latency_ms': self.latency_ms,
            'pid': self.pid,
            'tid': self.tid,
            'comm': self.comm,
            'client_type': self.client_type,
            'method': self.method,
            'url': self.url,
            's3_operation': self.s3_operation,
            'req_size': self.req_size,
            'resp_size': self.resp_size,
            'actual_resp_bytes': self.actual_resp_bytes,
            'is_partial': self.is_partial,
        }


class S3StatsCollector:
    """
    Main collector class that manages eBPF program and collects S3 statistics
    """
    
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.hostname = os.getenv("HOSTNAME", socket.gethostname())
        self.events: List[S3Event] = []
        self.b = None
        self._thread = None
        self._stop_collection = False
        
        # Load and prepare BPF program
        self._load_bpf_program()
    
    def _load_bpf_program(self):
        """Load and configure the eBPF program"""
        base_path = Path(__file__).parent.parent
        bpf_file = base_path / "s3slower.c"
        
        if not bpf_file.exists():
            raise FileNotFoundError(f"BPF program not found: {bpf_file}")
        
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
        """Attach eBPF probes to syscalls"""
        if self.b is None:
            raise RuntimeError("BPF program not loaded")
        
        attached_probes = []
        
        # Attach to write/send syscalls for detecting HTTP requests
        write_syscalls = ["ksys_write", "__x64_sys_write", "__x64_sys_sendto", "__sys_sendmsg"]
        for syscall in write_syscalls:
            try:
                self.b.attach_kprobe(event=syscall, fn_name="trace_write")
                attached_probes.append(f"kprobe:{syscall}")
                logger.debug(f"✓ Attached to {syscall}")
            except Exception as e:
                logger.debug(f"✗ Failed to attach to {syscall}: {e}")
        
        # Attach to read/recv syscalls for detecting HTTP responses
        read_syscalls = ["ksys_read", "__x64_sys_read", "__x64_sys_recvfrom", "__sys_recvmsg"] 
        for syscall in read_syscalls:
            try:
                self.b.attach_kprobe(event=syscall, fn_name="trace_read")
                self.b.attach_kretprobe(event=syscall, fn_name="trace_read_ret")
                attached_probes.append(f"kprobe:{syscall}")
                attached_probes.append(f"kretprobe:{syscall}")
                logger.debug(f"✓ Attached to {syscall} (entry and return)")
            except Exception as e:
                logger.debug(f"✗ Failed to attach to {syscall}: {e}")
        
        # NEW: Attach to tcp_sendmsg for elbencho/AWS SDK support
        try:
            self.b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
            attached_probes.append("kprobe:tcp_sendmsg")
            logger.info("✓ Attached to tcp_sendmsg for AWS SDK/elbencho support")
        except Exception as e:
            logger.warning(f"Could not attach to tcp_sendmsg - elbencho traffic may not be captured: {e}")
        
        if not attached_probes:
            raise RuntimeError("Failed to attach to any syscalls")
        
        logger.info(f"Successfully attached to {len(attached_probes)} probes")
        return attached_probes
    
    def start(self):
        """Start collecting events"""
        if self.b is None:
            raise RuntimeError("BPF program not loaded")
        
        self.b["events"].open_perf_buffer(self._handle_event)
        self._stop_collection = False
        self._thread = Thread(target=self._collection_loop, daemon=True)
        self._thread.start()
        logger.info("S3 event collection started")
    
    def stop(self):
        """Stop collecting events"""
        self._stop_collection = True
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("S3 event collection stopped")
    
    def _handle_event(self, cpu, data, size):
        """Handle incoming events from eBPF"""
        try:
            raw_event = self.b["events"].event(data)
            event = S3Event(raw_event)
            
            # Only process events with valid HTTP data
            if event.method != "?" and event.url != "?":
                self.events.append(event)
                logger.debug(f"Captured {event.client_type} S3 {event.s3_operation} latency: {event.latency_ms:.1f}ms")
        except Exception as e:
            logger.debug(f"Error processing event: {e}")
    
    def _collection_loop(self):
        """Main event collection loop"""
        while not self._stop_collection:
            try:
                # BCC API changed - timeout parameter name varies
                try:
                    self.b.perf_buffer_poll(timeout=100)
                except TypeError:
                    self.b.perf_buffer_poll(100)
            except Exception as e:
                if not self._stop_collection:
                    logger.error(f"Error in collection loop: {e}")
                break
    
    def collect_stats(self, interval: int, clear_events: bool = True) -> pd.DataFrame:
        """
        Collect and aggregate statistics from captured events
        
        Args:
            interval: Collection interval in seconds
            clear_events: Whether to clear events after collection
            
        Returns:
            DataFrame with aggregated S3 statistics
        """
        if not self.events:
            return pd.DataFrame()
        
        # Convert events to DataFrame
        event_data = [event.to_dict() for event in self.events]
        df = pd.DataFrame(event_data)
        
        if clear_events:
            self.events.clear()
        
        # Group by relevant fields and aggregate
        group_fields = ['comm', 'client_type', 's3_operation', 'method']
        
        # Aggregate statistics
        agg_stats = df.groupby(group_fields).agg({
            'latency_ms': ['count', 'sum', 'min', 'max'],
            'req_size': 'sum',
            'resp_size': 'sum', 
            'is_partial': 'sum',
            'pid': 'first',  # Take first PID for the group
        }).reset_index()
        
        # Flatten column names
        agg_stats.columns = [
            'COMM', 'CLIENT_TYPE', 'S3_OPERATION', 'METHOD',
            'REQUEST_COUNT', 'TOTAL_LATENCY_MS', 'MIN_LATENCY_MS', 'MAX_LATENCY_MS',
            'REQUEST_BYTES', 'RESPONSE_BYTES', 'PARTIAL_REQUESTS', 'PID'
        ]
        
        # Add metadata
        timestamp = pd.Timestamp.utcnow().astimezone(None).floor("s")
        agg_stats['TIMESTAMP'] = timestamp
        agg_stats['HOSTNAME'] = self.hostname
        agg_stats['INTERVAL'] = interval
        
        # Add computed metrics
        agg_stats['AVG_LATENCY_MS'] = agg_stats['TOTAL_LATENCY_MS'] / agg_stats['REQUEST_COUNT']
        agg_stats['REQUEST_ERRORS'] = 0  # TODO: Implement error detection
        
        logger.debug(f"Collected {len(agg_stats)} aggregated statistics")
        
        return agg_stats


class S3LatencyMonitor:
    """
    High-level interface for S3 latency monitoring
    
    This class provides a simple interface for monitoring S3 latency
    and can be used directly or through the driver architecture.
    """
    
    def __init__(self, 
                 pid: Optional[int] = None,
                 min_latency_ms: int = 0,
                 debug: bool = False):
        """
        Initialize S3 latency monitor
        
        Args:
            pid: Process ID to monitor (None for all processes)
            min_latency_ms: Minimum latency threshold in milliseconds
            debug: Enable debug logging
        """
        # Create arguments namespace
        args = argparse.Namespace()
        args.pid = pid
        args.min_latency_ms = min_latency_ms
        args.debug = debug
        
        self.collector = S3StatsCollector(args)
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
    
    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()


# For backwards compatibility and simple usage
def monitor_s3_latency(pid: Optional[int] = None, 
                      min_latency_ms: int = 0,
                      duration: int = 60) -> List[Dict[str, Any]]:
    """
    Simple function to monitor S3 latency for a specified duration
    
    Args:
        pid: Process ID to monitor (None for all processes)
        min_latency_ms: Minimum latency threshold in milliseconds  
        duration: Duration to monitor in seconds
        
    Returns:
        List of event dictionaries
        
    Example:
        >>> events = monitor_s3_latency(pid=1234, min_latency_ms=100, duration=30)
        >>> print(f"Captured {len(events)} slow S3 operations")
    """
    import time
    
    with S3LatencyMonitor(pid=pid, min_latency_ms=min_latency_ms) as monitor:
        time.sleep(duration)
        stats = monitor.get_stats(duration)
        return stats.to_dict('records') if not stats.empty else [] 