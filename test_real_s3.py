#!/usr/bin/env python3
"""
Test s3slower with real HTTP endpoints that will respond
"""
import time
import urllib.request
import urllib.error

def make_http_request(url, method="GET"):
    """Make HTTP request"""
    try:
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 's3slower-test')
        
        # Add method override if needed
        if method != "GET":
            req.get_method = lambda: method
            
        with urllib.request.urlopen(req, timeout=5) as response:
            data = response.read()
            print(f"  {method} {url} - Status: {response.status}, Size: {len(data)} bytes")
            return True
    except Exception as e:
        print(f"  {method} {url} - Error: {type(e).__name__}: {e}")
        return False

def test_http_operations():
    """Generate HTTP traffic to test s3slower"""
    print("\n=== Generating HTTP traffic for s3slower testing ===\n")
    
    # Use httpbin.org which provides testing endpoints
    test_urls = [
        # These will actually work and generate real HTTP traffic
        ("GET", "http://httpbin.org/get"),
        ("GET", "http://httpbin.org/status/200"),
        ("GET", "http://httpbin.org/bytes/1024"),
        ("GET", "http://httpbin.org/delay/1"),  # 1 second delay
        
        # S3-like paths (will still reach httpbin)
        ("GET", "http://httpbin.org/anything/bucket/object.txt"),
        ("GET", "http://httpbin.org/anything/bucket/file.zip?uploadId=123"),
        ("GET", "http://httpbin.org/anything/bucket?uploads"),
    ]
    
    for method, url in test_urls:
        print(f"Testing {method} request:")
        make_http_request(url, method)
        time.sleep(0.5)  # Small delay between requests
    
    print("\n=== HTTP traffic generation complete ===\n")

if __name__ == "__main__":
    test_http_operations()