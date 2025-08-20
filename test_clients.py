#!/usr/bin/env python3
"""
Test script to simulate different S3 clients for testing s3slower detection
"""

import os
import sys
import subprocess
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def test_boto3_pattern():
    """Simulate boto3 HTTP requests"""
    print("Testing boto3-like HTTP patterns...")
    try:
        # This is just HTTP traffic that looks like S3 API calls
        # Using httpbin.org for testing (not actual S3, but HTTP patterns)
        response = requests.get("http://httpbin.org/get", timeout=5)
        print(f"boto3-like test: {response.status_code}")
    except Exception as e:
        print(f"boto3-like test failed: {e}")

def test_curl_pattern():
    """Simulate s3cmd/curl-like HTTP requests"""
    print("Testing curl-like HTTP patterns...")
    try:
        # Test with curl command to generate HTTP traffic
        result = subprocess.run([
            "curl", "-s", "-X", "GET", 
            "http://httpbin.org/get",
            "-H", "User-Agent: s3cmd-test"
        ], capture_output=True, text=True, timeout=10)
        print(f"curl-like test: status {result.returncode}")
    except Exception as e:
        print(f"curl-like test failed: {e}")

def test_warp_pattern():
    """Simulate warp-like HTTP requests"""
    print("Testing warp-like HTTP patterns...")
    # For this test, we'll just rename the process temporarily
    try:
        response = requests.get("http://httpbin.org/get", timeout=5)
        print(f"warp-like test: {response.status_code}")
    except Exception as e:
        print(f"warp-like test failed: {e}")

def main():
    print("Starting S3 client detection tests...")
    print("Make sure s3slower is running to capture this traffic!")
    
    # Run tests concurrently to generate more traffic
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(test_boto3_pattern),
            executor.submit(test_curl_pattern), 
            executor.submit(test_warp_pattern)
        ]
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Test failed: {e}")
    
    print("Tests completed. Check s3slower output for detected traffic.")

if __name__ == "__main__":
    main()