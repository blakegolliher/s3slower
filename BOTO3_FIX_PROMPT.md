# Fix s3slower to Capture boto3 HTTPS Traffic

## Current Problem
The `s3slower` eBPF-based S3 latency tracer is NOT capturing ANY traffic from boto3 when using HTTPS. The tool successfully attaches to boto3 processes but no events are output.

### Test Commands That Should Work But Don't:
```bash
# Terminal 1 - Start s3slower
sudo ./s3slower.py --watch-config /etc/s3slower/targets.yaml --prometheus-port 0

# Terminal 2 - Run boto3 test
./scripts/boto3-s3-test.py --iterations 10 --protocol https
```

Expected: s3slower should display S3 operations (PUT, GET, DELETE, etc.)
Actual: s3slower shows "No S3-like HTTP traffic captured" despite successful attachment

## Root Cause Analysis

### The Core Issue: HTTP 100 Continue Response Handling
1. boto3 sends a PUT request over SSL
2. Server responds with "HTTP/1.1 100 Continue" (interim response)
3. boto3 sends the request body
4. Server responds with "HTTP/1.1 200 OK" (final response)

The BPF code in `/home/vastdata/projects/s3slower/s3slower/core.py` has a bug in `ssl_read_exit()` function (around line 475-508):
- When the 100 Continue arrives, the request is marked as `responded=1`
- When the 200 OK arrives, the code searches for requests with `responded=0`
- The request is never found, so no event is emitted

### What Works
- curl with HTTPS: 100% capture rate
- aws CLI with HTTPS: 100% capture rate
- boto3 with HTTP: Works (but we need HTTPS)
- SSL_write probes ARE capturing boto3's PUT requests (verified independently)
- The BPF probes ARE attaching successfully

### What's Broken
- boto3 with HTTPS: 0% capture rate
- The response matching logic in the BPF code
- Events are never submitted to the perf buffer (`events.perf_submit` never called)

## Previous Fix Attempts (Failed)

### Attempt 1: Changed request lookup to accept any responded state
```c
// Around line 483 - This broke everything
if (vp) {  // Instead of: if (vp && !vp->responded)
    break;
}
```
Result: No events captured at all, even for curl

### Attempt 2: Don't mark 100 Continue as responded
```c
// Around line 503
if (status_code >= 100 && status_code < 200) {
    // Don't set responded=1, just ignore
    read_args.delete(&tid);
    return 0;
}
```
Result: Still no events captured

## Your Mission

Fix the BPF code in `/home/vastdata/projects/s3slower/s3slower/core.py` so that:

1. **boto3 HTTPS operations are captured correctly** (especially PUT operations)
2. **HTTP 100 Continue responses are handled properly**
3. **The fix doesn't break curl or aws CLI** (they must continue working)
4. **Code remains simple and readable**

### Suggested Approach

1. **Understand the current flow:**
   - Read the BPF code in `ssl_read_exit()` function
   - Trace how requests are stored in `ssl_write_enter()`
   - Understand how responses are matched to requests
   - See how `responded` field is used

2. **Fix the 100 Continue handling:**
   - Option A: Use a different field/state for 100 Continue (e.g., `seen_continue`)
   - Option B: Allow matching already-responded requests for final responses
   - Option C: Track response count instead of boolean
   - Choose the simplest approach that works

3. **Test thoroughly:**
   ```bash
   # Kill any running s3slower
   sudo pkill -f s3slower.py

   # Start fresh
   sudo ./s3slower.py --watch-config /etc/s3slower/targets.yaml --prometheus-port 0

   # In another terminal, test boto3
   ./scripts/boto3-s3-test.py --iterations 10 --protocol https
   ```

   You should see output like:
   ```
   TIME     PID    COMM             TARGET     OP           LAT(ms)   STATUS BUCKET               ENDPOINT             PATH
   17:32:45 12345  python3          boto3      PUT          45.123    200    s3slower-boto3       main.selab-var204... /test.txt
   ```

4. **Verify correlation:**
   ```bash
   ./scripts/s3slower_correlate.py \
     --ops /tmp/s3boto3/boto3-ops.log \
     --trace /opt/s3slower/s3slower.log \
     --expected-target boto3
   ```
   Should show: "No missing operations"

## Key Files

- **Main BPF code**: `/home/vastdata/projects/s3slower/s3slower/core.py`
  - Focus on `ssl_read_exit()` function (lines 413-530)
  - Check `ssl_write_enter()` function (lines 321-382)
  - Look for `events.perf_submit()` calls

- **Test script**: `/home/vastdata/projects/s3slower/scripts/boto3-s3-test.py`
  - Runs various S3 operations (PUT, GET, DELETE, etc.)
  - Has pre-warming logic to ensure attachment

- **Configuration**: `/etc/s3slower/targets.yaml`
  - Defines how to identify and attach to boto3 processes

## Success Criteria

1. Running the test commands above shows boto3 operations in s3slower output
2. All operation types are captured (PUT_SMALL, PUT_LARGE, GET, DELETE, HEAD)
3. The correlation script shows 100% capture rate
4. curl and aws CLI continue to work correctly

## Important Constraints

- **Keep the fix simple** - Don't over-engineer
- **Preserve existing functionality** - Don't break what works
- **Stay within eBPF limits** - BPF verifier has strict rules about:
  - Stack size (512 bytes max)
  - Loop bounds (must be bounded)
  - Memory access (must be bounds-checked)
- **Test incrementally** - Make small changes and test each one

## Debugging Tips

1. Add debug output to see what's happening:
   ```c
   // In BPF code (be careful, this goes to kernel log)
   bpf_trace_printk("DEBUG: status_code=%d responded=%d\\n", status_code, vp->responded);
   ```
   Then check: `sudo cat /sys/kernel/debug/tracing/trace`

2. Use the test script to verify SSL_write is working:
   ```bash
   python3 test_single_put.py
   ```

3. Check if events are being generated but filtered:
   - Add debug output in Python `_handle_event()` function
   - Check if `restrict_to_attached` is filtering correctly

## Background Context

This tool uses eBPF to trace S3 operations by:
1. Attaching uprobes to OpenSSL functions (SSL_write, SSL_read)
2. Parsing HTTP headers to identify S3 operations
3. Matching responses to requests to calculate latency
4. Outputting events when a request completes

The issue is specifically in step 3 - response matching fails for boto3 due to 100 Continue responses.

Good luck! The fix should be relatively small once you understand the issue. Focus on making the 100 Continue handling work without breaking the existing logic for other cases.