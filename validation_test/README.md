# S3slower E2E Validation Test Suite

Runs controlled S3 workloads (AWS CLI, boto3, and elbencho) and validates that s3slower captures 100% of operations with correct metadata.

## Prerequisites

- **Root access** (eBPF requires it)
- **AWS CLI** (`aws s3api`)
- **Python 3** with **boto3** installed
- **elbencho** with S3 support (built with `--s3` feature)
- **s3slower binary** built (`make build`)
- **Reachable S3 endpoint** with valid credentials

## Quick Start

```bash
# Set credentials
export AWS_ACCESS_KEY_ID=<your-key>
export AWS_SECRET_ACCESS_KEY=<your-secret>
export S3_ENDPOINT=https://172.200.202.1   # optional, this is the default

# Build + run
make test-validate

# Or run directly
sudo -E S3SLOWER_BIN=build/s3slower validation_test/run_validation.sh
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `S3_ENDPOINT` | `https://172.200.202.1` | S3 endpoint URL |
| `AWS_ACCESS_KEY_ID` | *(required)* | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | *(required)* | AWS secret key |
| `S3SLOWER_BIN` | `build/s3slower` | Path to s3slower binary |
| `S3_NO_VERIFY_SSL` | `true` | Set `false` to require valid certs |

## What It Does

1. Starts s3slower in JSON capture mode
2. Runs 19 S3 operations via AWS CLI (each is a separate PID)
3. Runs the same 19 operations via boto3 (single PID)
4. Runs S3 operations via elbencho (single PID, includes multipart upload)
5. Stops s3slower
6. Compares workload logs against capture output

### Operations Tested

**AWS CLI** (19 ops): create-bucket, head-bucket, put-object (1KB), put-object (1MB), head-object, get-object, list-objects-v2, list-objects-v2 with prefix, copy-object, delete-object, create-multipart-upload, upload-part (5MB), complete-multipart-upload, create-multipart-upload (for abort), abort-multipart-upload, delete-object x3 (cleanup), delete-bucket

**boto3** (19 ops): Same as AWS CLI but from a single Python process.

**elbencho** (~17 ops): create-bucket, head-bucket, put-object x2 (1KB), multipart upload (10MB as 2x5MB parts: create + 2 parts + complete), head-object x2, get-object x2, list-objects, delete-object x3 (cleanup), delete-bucket

## Reading the Results

All output lands in a temp directory printed at the end:

```
/tmp/s3slower-validation-XXXXX/
  workload_awscli.jsonl    # What the CLI workload did
  workload_boto3.jsonl     # What the boto3 workload did
  workload_elbencho.jsonl  # What the elbencho workload did
  s3slower_capture.jsonl   # What s3slower captured
  s3slower_stderr.log      # s3slower diagnostic output
  validation_report.json   # Detailed pass/fail results
```

### It Worked

You'll see:

```
PASS: 55/55 operations captured (100%), all accuracy checks passed
[INFO]  VALIDATION PASSED
```

The exit code is **0**.

### It Failed

You'll see one or both of:

**Missing captures** (s3slower didn't see the operation):
```
  MISS: seq=6 GET_OBJECT pid=12345 GET test/small.txt
FAIL: 50/55 operations captured (91%), all accuracy checks FAILED
```

**Accuracy failures** (captured but wrong metadata):
```
  FAIL: seq=3 PUT_OBJECT - ['bucket_match', 'put_has_request_size']
FAIL: 55/55 operations captured (100%), all accuracy checks FAILED
```

The exit code is **1**.

### Digging Deeper

```bash
# Pretty-print the full report
cat /tmp/s3slower-validation-*/validation_report.json | python3 -m json.tool

# Check what s3slower actually captured
cat /tmp/s3slower-validation-*/s3slower_capture.jsonl | python3 -m json.tool

# Check s3slower startup/error output
cat /tmp/s3slower-validation-*/s3slower_stderr.log
```

The `validation_report.json` has per-operation detail:
- `summary.pass` - overall pass/fail boolean
- `summary.capture_rate_pct` - percentage of operations matched
- `per_operation[].checks` - field-by-field accuracy (pid, method, operation, bucket, key, latency, status, sizes)
- `per_operation[].failed_checks` - which checks failed (only present on failures)
- `unmatched_workload` - operations s3slower missed
- `extra_captures_sample` - captures not tied to any workload operation (retries, STS calls, etc. -- these are fine)

## Cleanup

The orchestrator's EXIT trap automatically:
- Kills s3slower if still running
- Force-removes test buckets and aborts lingering multipart uploads

The temp directory under `/tmp/` is kept for inspection. Delete it manually when done.
