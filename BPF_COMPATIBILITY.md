# BPF Compatibility Notes

## memcpy Error

If you encounter this error:
```
error: /virtual/main.c:238:13: in function trace_write i32 (ptr): A call to built-in function 'memcpy' is not supported.
```

The enhanced BPF program will automatically fallback to a compatibility version that doesn't use memcpy.

## What's Different in Compatibility Mode?

The compatibility BPF program (`s3slower_enhanced_compat.c`):
- Uses manual byte-by-byte copying instead of memcpy
- Uses fixed loop bounds with early exit conditions
- May have slightly higher overhead but works on more kernel versions

## Manual Override

To force compatibility mode from the start:
```python
from s3slower.s3ops_enhanced import UniversalS3Monitor

# Force compatibility mode
monitor = UniversalS3Monitor(enhanced=True)
monitor.collector.args.use_compat = True
```

## Kernel Version Support

- **Enhanced version**: Works best on kernel 5.0+
- **Compatibility version**: Works on kernel 4.15+
- **Original version**: Works on kernel 4.9+

## Performance Impact

The compatibility version may have slightly higher CPU usage due to:
- Manual byte copying loops
- More verbose string operations

However, the impact is typically negligible compared to the I/O operations being monitored.

## Troubleshooting

If both enhanced versions fail:
1. Check kernel version: `uname -r`
2. Try original mode: `enhanced=False`
3. Check BCC/BPF tools version: `dpkg -l | grep bcc`
4. Update kernel headers if needed: `sudo apt install linux-headers-$(uname -r)`
