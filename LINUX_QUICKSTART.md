# Linux Quick Start - Testing Enhanced S3 Detection

## 1. Pull Latest Changes
```bash
git pull
```

## 2. Run Basic Test First
This verifies the BPF program compiles correctly:
```bash
sudo python3 test_basic.py
```

If this passes, the BPF compilation issue is fixed!

## 3. Test with Real S3 Traffic

### Option A: Test with elbencho
```bash
# Terminal 1: Start elbencho (use HTTP!)
elbencho --s3endpoints http://localhost:9000 \
         --s3accesskey minioadmin \
         --s3secretkey minioadmin \
         -b testbucket --list

# Terminal 2: Monitor
sudo python3 test_elbencho_detection.py
```

### Option B: Test with warp
```bash
# Terminal 1: Start warp
warp mixed --host=localhost:9000 \
           --access-key=minioadmin \
           --secret-key=minioadmin \
           --bucket=testbucket

# Terminal 2: Run example
sudo python3 example_usage.py
```

## 4. If Still Having Issues

### Check minimal functionality:
```bash
sudo python3 test_minimal.py
```

### Run comprehensive debug:
```bash
sudo python3 debug_s3_detection.py --all
```

### Check what syscalls elbencho uses:
```bash
# Start elbencho, then:
sudo python3 debug_s3_detection.py --check-process elbencho
```

## Notes
- The "sh: 1: Syntax error" message can be ignored - it's non-critical
- If you get a "memcpy is not supported" error, the program will automatically retry with a compatibility version
- Make sure to use HTTP (not HTTPS) endpoints
- Run all scripts with sudo for BPF access

## Expected Output
When working correctly with elbencho, you should see:
```
✓ Successfully detected elbencho S3 traffic!

S3 Operations detected:
  GetObject: 10
  PutObject: 5
  ListObjectsV2: 2
```
