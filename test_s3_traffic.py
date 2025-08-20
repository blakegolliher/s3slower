#!/usr/bin/env python3
"""
Test script to generate S3-like HTTP traffic for testing s3slower
"""

import socket
import time
import threading

def send_s3_like_request(host="127.0.0.1", port=8080):
    """Send an HTTP request that looks like S3 API traffic"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Try to connect to a local server
        sock.connect((host, port))
        
        # Send S3-like HTTP request
        request = (
            "GET /test-bucket/test-object.txt HTTP/1.1\r\n"
            "Host: s3.amazonaws.com\r\n"
            "User-Agent: boto3/1.26.137 Python/3.11.2\r\n"
            "Authorization: AWS4-HMAC-SHA256 Credential=...\r\n"
            "x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\n"
            "x-amz-date: 20231201T120000Z\r\n"
            "\r\n"
        )
        
        sock.send(request.encode())
        
        # Try to receive response
        response = sock.recv(4096)
        print(f"Sent S3-like request, received {len(response)} bytes")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"Failed to send request to {host}:{port}: {e}")
        return False

def start_simple_server(port=8080):
    """Start a simple HTTP server to respond to our requests"""
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('127.0.0.1', port))
        server_sock.listen(1)
        server_sock.settimeout(10)  # 10 second timeout
        
        print(f"Simple server listening on port {port}")
        
        while True:
            try:
                client_sock, addr = server_sock.accept()
                print(f"Connection from {addr}")
                
                # Read request
                request = client_sock.recv(4096)
                print(f"Received {len(request)} bytes")
                
                # Send S3-like response
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/xml\r\n"
                    "Content-Length: 100\r\n"
                    "x-amz-request-id: 123456789\r\n"
                    "x-amz-id-2: abcdef\r\n"
                    "\r\n"
                    "<Contents><Key>test-object.txt</Key><Size>1024</Size></Contents>" + " " * 47
                )
                
                client_sock.send(response.encode())
                client_sock.close()
                
            except socket.timeout:
                break
            except Exception as e:
                print(f"Server error: {e}")
                break
                
    except Exception as e:
        print(f"Server startup error: {e}")
    finally:
        server_sock.close()

def main():
    print("Starting S3-like traffic test...")
    
    # Start server in background thread
    server_thread = threading.Thread(target=start_simple_server, daemon=True)
    server_thread.start()
    
    # Give server time to start
    time.sleep(1)
    
    # Send multiple requests to generate traffic
    for i in range(5):
        print(f"Sending request {i+1}/5...")
        send_s3_like_request()
        time.sleep(0.5)
    
    print("Traffic generation completed. Check s3slower output.")

if __name__ == "__main__":
    main()