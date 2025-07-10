# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

import os
import argparse
import time
from threading import Lock
from collections import deque

# Disable Prometheus created series for cleaner metrics
os.environ['PROMETHEUS_DISABLE_CREATED_SERIES'] = "1"

import prometheus_client as prom
try:
    from prometheus_client.registry import Collector
except ImportError:
    from prometheus_client.registry import CollectorRegistry as Collector
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, HistogramMetricFamily

from s3slower.drivers.base import DriverBase
from s3slower.s3ops import STATKEYS


class PrometheusDriver(DriverBase, Collector):
    """Prometheus exporter driver for S3Slower metrics"""
    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--prom-exporter-host", default="::",
        help="Prometheus exporter host."
    )
    parser.add_argument(
        "--prom-exporter-port", default=9000, type=int,
        help="Prometheus exporter port."
    )
    parser.add_argument(
        "--buffer-size", default=1000, type=int,
        help="Number of samples stored locally for processing by the Prometheus exporter. "
             "If the number of samples exceeds this value, the oldest samples will be discarded."
    )

    def __str__(self):
        return (
            f"{self.__class__.__name__}"
            f"(prom_exporter_host={self.prom_exporter_host},"
            f" prom_exporter_port={self.prom_exporter_port},"
            f" buffer_size={self.buffer_size})"
        )

    async def setup(self, args=(), namespace=None):
        args = await super().setup(args, namespace)
        self.lock = Lock()
        self.prom_exporter_host = args.prom_exporter_host
        self.prom_exporter_port = args.prom_exporter_port
        self.buffer_size = args.buffer_size
        self.local_buffer = deque(maxlen=self.buffer_size)

        # Clean up default Prometheus collectors
        prom.REGISTRY.unregister(prom.PROCESS_COLLECTOR)
        prom.REGISTRY.unregister(prom.PLATFORM_COLLECTOR)
        prom.REGISTRY.unregister(prom.GC_COLLECTOR)
        
        # Register our custom collector
        prom.REGISTRY.register(self)
        
        # Start HTTP server
        exporter = prom.start_http_server(
            port=self.prom_exporter_port, 
            addr=self.prom_exporter_host
        )
        if exporter:
            self.exporter = exporter[0]
        
        self.logger.info(f"{self} has been initialized.")

    async def teardown(self):
        if hasattr(self, "exporter"):
            self.logger.info("Shutting down Prometheus exporter.")
            self.exporter.shutdown()

    async def store_sample(self, data):
        """Store a sample in the local buffer for Prometheus scraping"""
        self.local_buffer.append(data)
        buffer_max_size = self.local_buffer.maxlen
        buffer_usage_percent = (len(self.local_buffer) / buffer_max_size) * 100
        
        # Check if buffer usage exceeds 80%
        if buffer_usage_percent > 80:
            self.logger.warning(
                f"Buffer usage is at {buffer_usage_percent:.2f}%. "
                "Prometheus is taking samples too slowly."
            )

    def _create_gauge(self, name, help_text, labels, value):
        """Create a Prometheus gauge metric"""
        gauge = GaugeMetricFamily(name, help_text, labels=labels.keys())
        gauge.add_metric(labels.values(), value)
        return gauge
    
    def _create_counter(self, name, help_text, labels, value):
        """Create a Prometheus counter metric"""
        counter = CounterMetricFamily(name, help_text, labels=labels.keys())
        counter.add_metric(labels.values(), value)
        return counter

    def collect(self):
        """Collect metrics for Prometheus scraping"""
        # Make sure only 1 prometheus request can be processed at a time
        with self.lock:
            samples_count = len(self.local_buffer)
            if samples_count == 0:
                return
            
            self.logger.debug(f"Found {samples_count} sample(s).")
            
            while self.local_buffer:
                data = self.local_buffer.popleft()
                
                # Process each row in the DataFrame
                for _, entry in data.iterrows():
                    # Create labels for metrics
                    labels_kwargs = {
                        "hostname": entry.HOSTNAME,
                        "comm": entry.COMM,
                        "s3_operation": entry.S3_OPERATION,
                        "method": entry.METHOD,
                        "pid": str(entry.PID),
                    }
                    
                    # Export core metrics
                    yield self._create_counter(
                        "s3slower_requests_total",
                        "Total number of S3 requests",
                        labels_kwargs,
                        entry.REQUEST_COUNT
                    )
                    
                    yield self._create_counter(
                        "s3slower_request_errors_total",
                        "Total number of S3 request errors",
                        labels_kwargs,
                        entry.REQUEST_ERRORS
                    )
                    
                    yield self._create_gauge(
                        "s3slower_request_duration_ms",
                        "S3 request duration in milliseconds",
                        labels_kwargs,
                        entry.AVG_LATENCY_MS
                    )
                    
                    yield self._create_gauge(
                        "s3slower_request_duration_min_ms",
                        "Minimum S3 request duration in milliseconds",
                        labels_kwargs,
                        entry.MIN_LATENCY_MS
                    )
                    
                    yield self._create_gauge(
                        "s3slower_request_duration_max_ms",
                        "Maximum S3 request duration in milliseconds",
                        labels_kwargs,
                        entry.MAX_LATENCY_MS
                    )
                    
                    yield self._create_counter(
                        "s3slower_request_bytes_total",
                        "Total S3 request bytes",
                        labels_kwargs,
                        entry.REQUEST_BYTES
                    )
                    
                    yield self._create_counter(
                        "s3slower_response_bytes_total",
                        "Total S3 response bytes",
                        labels_kwargs,
                        entry.RESPONSE_BYTES
                    )
                    
                    yield self._create_counter(
                        "s3slower_partial_requests_total",
                        "Total number of multi-part S3 requests",
                        labels_kwargs,
                        entry.PARTIAL_REQUESTS
                    )
                    
                    # Create a summary of latency distribution
                    yield self._create_gauge(
                        "s3slower_latency_summary_ms",
                        "Summary of S3 request latency in milliseconds",
                        {**labels_kwargs, "quantile": "0.5"},  # median approximation
                        entry.AVG_LATENCY_MS
                    ) 