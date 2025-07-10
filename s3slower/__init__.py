# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

"""
S3 Slower - Monitor S3 client latency using eBPF

A production-ready tool for monitoring S3 client-side latency without 
SDK instrumentation. Uses eBPF to trace HTTP requests and responses 
from S3 clients, providing detailed metrics via Prometheus and other exporters.
"""

__version__ = "1.0.0"
__author__ = "S3Slower Development Team" 