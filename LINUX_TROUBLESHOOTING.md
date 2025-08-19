# Linux Troubleshooting Guide

## Testing Order

If `example_usage.py` fails, try these in order:

### 1. Test All BPF Versions
```bash
sudo python3 test_bpf_versions.py
```
This will show which BPF versions compile on your system.

### 2. Force Simple Version
```bash
sudo python3 test_force_simple.py
```
This bypasses the fallback mechanism and directly uses the simplest BPF program.

### 3. Test Basic Functionality
```bash
sudo python3 test_basic.py
```

## Common Issues and Solutions

### "memcpy is not supported" Error
- **Cause**: BPF verifier doesn't support memcpy on your kernel
- **Solution**: The system should automatically fallback to compatibility version
- **Manual Fix**: Use `test_force_simple.py` to force simple version

### "memset is not supported" Error
- **Cause**: Zero initialization creates implicit memset calls
- **Solution**: We've removed all `= {}` initializations
- **Status**: Fixed in latest version

### "loop not unrolled" Warnings
- **Cause**: BPF verifier can't unroll loops with variable bounds
- **Solution**: We've changed all loops to have constant bounds
- **Note**: These warnings are harmless if compilation succeeds

### "sh: 1: Syntax error" Messages
- **Cause**: Unrelated shell subprocess (possibly from system)
- **Solution**: Can be safely ignored
- **Note**: Happens before BPF loads, not related to our code

## Kernel Compatibility

Different kernels have different BPF capabilities:

| Kernel Version | Expected Support |
|----------------|------------------|
| 5.4+           | All versions should work |
| 4.19 - 5.3     | Simple version likely needed |
| 4.15 - 4.18    | Original mode may be required |
| < 4.15         | May not work |

## Manual Version Selection

If automatic fallback isn't working:

```python
from s3slower.s3ops_enhanced import UniversalS3Monitor

# Force simple version
monitor = UniversalS3Monitor(enhanced=True)
monitor.collector.args.use_simple = True
monitor.collector.args.use_compat = False
monitor.collector._load_bpf_program()

# Or use original mode
monitor = UniversalS3Monitor(enhanced=False)
```

## Debugging Steps

1. **Check kernel version**: 
   ```bash
   uname -r
   ```

2. **Check BCC version**:
   ```bash
   dpkg -l | grep bcc
   # or
   rpm -qa | grep bcc
   ```

3. **Check kernel headers**:
   ```bash
   ls /lib/modules/$(uname -r)/build
   ```

4. **Test BPF capability**:
   ```bash
   sudo bpftool prog list
   ```

## If Nothing Works

1. Try original mode only:
   ```python
   from s3slower.s3ops import S3LatencyMonitor
   monitor = S3LatencyMonitor()  # Uses original 64-byte detection
   ```

2. Check dmesg for errors:
   ```bash
   sudo dmesg | tail -50 | grep -i bpf
   ```

3. Update kernel headers:
   ```bash
   # Ubuntu/Debian
   sudo apt install linux-headers-$(uname -r)
   
   # RHEL/CentOS
   sudo yum install kernel-devel-$(uname -r)
   ```

## Contact

If you're still having issues after trying these steps, please report:
- Kernel version (`uname -r`)
- Distribution and version
- Output of `sudo python3 test_bpf_versions.py`
- Any error messages from dmesg
