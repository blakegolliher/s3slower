# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

import argparse
from datetime import datetime

from s3slower.drivers.base import DriverBase


class ScreenDriver(DriverBase):
    """Screen/console output driver for S3Slower metrics"""
    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--table-format", action="store_true", default=True,
        help="Display statistics in a tabular format."
    )
    parser.add_argument(
        "--max-url-length", type=int, default=50,
        help="Maximum length for URL display before truncation."
    )

    def __str__(self):
        return f"{self.__class__.__name__}(table_format={self.table_format})"

    async def setup(self, args=(), namespace=None):
        args = await super().setup(args, namespace)
        self.table_format = args.table_format
        self.max_url_length = args.max_url_length
        self._header_printed = False
        return args

    async def store_sample(self, data):
        """Display S3 statistics to console"""
        if data.empty:
            return
        
        if self.table_format:
            await self._print_table_format(data)
        else:
            await self._print_simple_format(data)

    async def _print_table_format(self, data):
        """Print data in tabular format"""
        if not self._header_printed:
            self._print_table_header()
            self._header_printed = True
        
        for _, row in data.iterrows():
            # Format timestamp
            timestamp = row.TIMESTAMP.strftime("%H:%M:%S")
            
            # Truncate command name if too long
            comm = row.COMM[:12] if len(row.COMM) > 12 else row.COMM
            
            # Format S3 operation
            s3_op = row.S3_OPERATION[:16] if len(row.S3_OPERATION) > 16 else row.S3_OPERATION
            
            print(f"{timestamp:<8} {comm:<12} {row.PID:<6} {s3_op:<16} "
                  f"{row.REQUEST_COUNT:<6} {row.AVG_LATENCY_MS:<8.1f} "
                  f"{row.MIN_LATENCY_MS:<8.1f} {row.MAX_LATENCY_MS:<8.1f} "
                  f"{row.REQUEST_BYTES:<10} {row.RESPONSE_BYTES:<10}")

    def _print_table_header(self):
        """Print table header"""
        print()
        print(f"Tracing S3 operations... Output every {self.common_args.interval} seconds")
        print()
        print(f"{'TIME':<8} {'COMM':<12} {'PID':<6} {'S3_OPERATION':<16} "
              f"{'COUNT':<6} {'AVG_MS':<8} {'MIN_MS':<8} {'MAX_MS':<8} "
              f"{'REQ_BYTES':<10} {'RESP_BYTES':<10}")
        print("-" * 90)

    async def _print_simple_format(self, data):
        """Print data in simple format"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{timestamp}] S3 Operations Summary:")
        print("-" * 50)
        
        for _, row in data.iterrows():
            print(f"  Process: {row.COMM} (PID: {row.PID})")
            print(f"  Operation: {row.S3_OPERATION} ({row.METHOD})")
            print(f"  Requests: {row.REQUEST_COUNT}")
            print(f"  Latency: avg={row.AVG_LATENCY_MS:.1f}ms, "
                  f"min={row.MIN_LATENCY_MS:.1f}ms, max={row.MAX_LATENCY_MS:.1f}ms")
            print(f"  Bytes: req={row.REQUEST_BYTES}, resp={row.RESPONSE_BYTES}")
            if row.PARTIAL_REQUESTS > 0:
                print(f"  Multi-part requests: {row.PARTIAL_REQUESTS}")
            print()

    async def teardown(self):
        """No cleanup needed for screen driver"""
        pass 