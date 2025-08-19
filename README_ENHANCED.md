# Enhanced S3 Latency Monitor - Universal Detection

This enhanced version of s3slower provides near-universal detection of S3 traffic from various clients including elbencho, warp, AWS CLI, and others.

## Key Improvements

### 1. **Larger Buffer Size (512 bytes vs 64 bytes)**
   - Captures more of the HTTP request, including headers
   - Better detection of S3-specific headers like `x-amz-*`

### 2. **Multi-Segment HTTP Detection**
   - Tracks up to 8 segments of fragmented HTTP requests
   - State machine tracks partial headers across multiple write() calls
   - Reassembles fragmented requests for analysis

### 3. **Comprehensive Syscall Coverage**
   - `write()` - Traditional write syscall
   - `send()` - Socket send operations  
   - `sendto()` - UDP and connection-less sends
   - `sendmsg()` - Advanced socket operations
   - `tcp_sendmsg()` - TCP-level detection
   - Similar coverage for read operations

### 4. **S3-Specific Pattern Detection**
   - Detects `x-amz-*` headers
   - Recognizes `AWS4-HMAC-SHA256` authorization
   - Identifies S3 URL patterns (`?partNumber=`, `?uploadId=`)
   - Determines S3 operation type (GetObject, PutObject, etc.)

### 5. **Enhanced HTTP Method Support**
   - GET, PUT, POST, DELETE, HEAD
   - OPTIONS, PATCH, CONNECT, TRACE
   - Partial method matching for fragmented requests

## Usage

### Basic Usage

```python
from s3slower.s3ops_enhanced import UniversalS3Monitor

# Monitor all S3 traffic
with UniversalS3Monitor(enhanced=True) as monitor:
    time.sleep(60)  # Monitor for 60 seconds
    stats = monitor.get_stats(60)
    print(stats)
```

### Monitor Specific Process

```python
# Monitor only elbencho
elbencho_pid = 12345  # Get from pgrep
with UniversalS3Monitor(pid=elbencho_pid, enhanced=True) as monitor:
    # ... monitoring code
```

### S3-Only Mode

```python
# Filter to show only S3 traffic (ignore other HTTP)
with UniversalS3Monitor(enhanced=True, s3_only=True) as monitor:
    # ... monitoring code
```

### Debugging Mode

```python
# Enable debug logging
with UniversalS3Monitor(enhanced=True, debug=True) as monitor:
    # ... monitoring code
```

## Testing with Different S3 Clients

### elbencho
```bash
# Make sure to use HTTP (not HTTPS)
elbencho --s3endpoints http://localhost:9000 \
         --s3accesskey minioadmin \
         --s3secretkey minioadmin \
         -b testbucket -n 10 -N 10 -s 1M -t 4 -w
```

### warp
```bash
warp mixed --host=localhost:9000 \
            --access-key=minioadmin \
            --secret-key=minioadmin \
            --bucket=testbucket \
            --duration=60s
```

### AWS CLI
```bash
# Configure for HTTP
aws configure set default.s3.signature_version s3v4
aws --endpoint-url http://localhost:9000 s3 ls s3://testbucket/
```

## Troubleshooting

### No Events Detected

1. **Check if using HTTPS**: Currently only HTTP is supported
   ```bash
   # Check connections
   sudo ss -tpn | grep elbencho
   ```

2. **Verify BPF is working**: 
   ```bash
   sudo python3 debug_s3_detection.py --test-modes
   ```

3. **Check syscalls being used**:
   ```bash
   sudo python3 debug_s3_detection.py --check-process elbencho
   ```

### Partial Detection

If you see HTTP traffic but no S3 operations:
- Application might not be using standard S3 headers
- Requests might be too fragmented
- Could be using a non-standard S3 implementation

## Debug Tools

### Comprehensive Debugging
```bash
sudo python3 debug_s3_detection.py --all
```

### Test elbencho Specifically
```bash
sudo python3 test_elbencho_detection.py
```

### Monitor with Diagnostics
```bash
sudo python3 debug_s3_detection.py --monitor 60
```

## Architecture

```
Application (elbencho/warp/etc.)
    |
    v
[System Calls]
    |
    +---> write() ----+
    |                 |
    +---> send() -----+
    |                 |
    +---> sendto() ---+---> Enhanced BPF Program
    |                 |     - Large buffer (512B)
    +---> sendmsg() --+     - Multi-segment tracking
    |                 |     - State machine
    +---> tcp_sendmsg +     - S3 pattern detection
                      |
                      v
                 [Event Buffer]
                      |
                      v
              Python User Space
              - Event processing
              - S3 operation detection
              - Statistics aggregation
```

## Performance Considerations

- Enhanced mode has slightly higher overhead due to:
  - Larger buffer copies (512B vs 64B)
  - Multiple syscall hooks
  - Pattern matching for S3 detection
  
- For production use with high-traffic systems:
  - Consider using PID filtering
  - Set appropriate minimum latency thresholds
  - Use original mode if S3-specific detection not needed

## Limitations

1. **HTTPS Not Supported**: Only plaintext HTTP is detected
2. **Kernel Version**: Requires kernel 4.15+ for all features
3. **Root Required**: BPF requires root/CAP_SYS_ADMIN
4. **HTTP/2 Not Supported**: Only HTTP/1.x is detected

## Future Improvements

1. **HTTPS Support**: 
   - Parse TLS SNI for hostname detection
   - eBPF uprobe on SSL_write/SSL_read
   
2. **HTTP/2 Support**:
   - Detect HTTP/2 connection preface
   - Parse HTTP/2 frames
   
3. **Better Correlation**:
   - Track request/response pairs
   - Connection pooling awareness
   
4. **More S3 Operations**:
   - Multipart upload tracking
   - Batch operations
   - S3 Select/Glacier operations
