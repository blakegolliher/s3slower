# Testing Guide for Enhanced S3 Detection

## Quick Start on Linux

After pulling the changes, here's how to test the enhanced S3 detection:

### 1. Basic Test - Compare Detection Modes
```bash
sudo python3 example_usage.py
```
This will run both original and enhanced modes to show the differences.

### 2. Test with elbencho
```bash
# Terminal 1: Start elbencho with HTTP endpoint
elbencho --s3endpoints http://localhost:9000 \
         --s3accesskey minioadmin \
         --s3secretkey minioadmin \
         -b testbucket -n 10 -N 10 -s 1M -t 4 -w

# Terminal 2: Run the elbencho-specific test
sudo python3 test_elbencho_detection.py
```

### 3. Test with warp
```bash
# Terminal 1: Start warp
warp mixed --host=localhost:9000 \
           --access-key=minioadmin \
           --secret-key=minioadmin \
           --bucket=testbucket \
           --duration=60s

# Terminal 2: Monitor with enhanced mode
sudo python3 -c "
from s3slower.s3ops_enhanced import UniversalS3Monitor
import time

with UniversalS3Monitor(enhanced=True, debug=True) as monitor:
    print('Monitoring warp traffic...')
    time.sleep(30)
    stats = monitor.get_stats(30)
    print(stats)
"
```

### 4. Comprehensive Debugging
```bash
# Run all diagnostic tests
sudo python3 debug_s3_detection.py --all

# Check specific process
sudo python3 debug_s3_detection.py --check-process elbencho

# Monitor with diagnostics for 60 seconds
sudo python3 debug_s3_detection.py --monitor 60
```

## Key Points to Remember

1. **Use HTTP, not HTTPS**: The current implementation only detects HTTP traffic
   - ✅ `--s3endpoints http://localhost:9000`
   - ❌ `--s3endpoints https://localhost:9000`

2. **Run as root/sudo**: BPF requires elevated privileges

3. **Check kernel compatibility**: Requires kernel 4.15+
   ```bash
   uname -r
   ```

4. **Verify BPF is working**:
   ```bash
   sudo bpftool prog list
   ```

## Expected Results

### With warp
- Should detect operations like GetObject, PutObject, DeleteObject
- Should show bucket and object names
- Should capture multi-segment requests

### With elbencho
- Might use different syscalls (sendmsg instead of write)
- May buffer requests differently
- Should still be detected with enhanced mode

### Troubleshooting

If no events are captured:
1. Verify the application is using HTTP (check with `ss -tpn`)
2. Try the original mode to see if basic detection works
3. Check dmesg for BPF errors: `sudo dmesg | tail -20`
4. Use strace to see what syscalls are being used

## Integration into s3slower

To use the enhanced mode in your existing s3slower setup:

```python
# In your driver or main code
from s3slower.s3ops_enhanced import EnhancedS3StatsCollector

# Replace the original collector
collector = EnhancedS3StatsCollector(args)
collector.attach()
collector.start()
# ... rest of your code
```

The enhanced collector is backward compatible and provides the same interface as the original.
