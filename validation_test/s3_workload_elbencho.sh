#!/usr/bin/env bash
# s3_workload_elbencho.sh - Elbencho workload generator for s3slower validation
#
# Runs deterministic S3 operations using elbencho and logs each phase as JSONL.
# Elbencho is a single-process S3 client (using the AWS C++ SDK), so all
# operations share one PID.
#
# Usage: s3_workload_elbencho.sh <output_jsonl> <endpoint_url> <bucket_name>
#
# Elbencho operations mapped to s3slower detection:
#   -d (mkdirs)        → CREATE_BUCKET (PUT /<bucket>)
#   --s3statdirs       → HEAD_BUCKET   (HEAD /<bucket>)
#   -w (write)         → PUT_OBJECT    (PUT /<bucket>/<key>)
#   --stat             → HEAD_OBJECT   (HEAD /<bucket>/<key>)
#   -r (read)          → GET_OBJECT    (GET /<bucket>/<key>)
#   --s3listobj        → LIST_PREFIX   (GET /<bucket>?list-type=2)
#   -F (delfiles)      → DELETE_OBJECT (DELETE /<bucket>/<key>)
#   -D (deldirs)       → DELETE_BUCKET (DELETE /<bucket>)
#
# Note: elbencho multipart is automatic when object size > block size.
# We use -s 10m -b 5m to force a 2-part multipart upload.

set -euo pipefail

OUTPUT="$1"
ENDPOINT="$2"
BUCKET="$3"

SEQ=0
TMPDIR_ELBENCHO=$(mktemp -d)
trap 'rm -rf "$TMPDIR_ELBENCHO"' EXIT

# S3 credentials come from environment (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
S3_COMMON="--s3endpoints $ENDPOINT --s3region us-east-1"

log_op() {
    local operation="$1" method="$2" key="$3" size="$4" exit_code="$5"
    SEQ=$((SEQ + 1))
    local ts pid
    ts=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    pid=$(get_elbencho_pid)
    printf '{"seq":%d,"timestamp":"%s","pid":%d,"client":"elbencho","operation":"%s","method":"%s","bucket":"%s","key":"%s","size":%d,"exit_code":%d}\n' \
        "$SEQ" "$ts" "$pid" "$operation" "$method" "$BUCKET" "$key" "$size" "$exit_code" >> "$OUTPUT"
}

ELBENCHO_PID_FILE="$TMPDIR_ELBENCHO/elbencho.pid"

run_elbencho() {
    # Run elbencho in background to capture its PID, then wait for it.
    # Elbencho prints stats to stdout; redirect to stderr so only exit code is captured.
    # PID is written to a file since $() subshell loses variable assignments.
    local exit_code=0
    elbencho $S3_COMMON "$@" >&2 &
    local pid=$!
    echo "$pid" > "$ELBENCHO_PID_FILE"
    wait $pid || exit_code=$?
    echo "$exit_code"
}

get_elbencho_pid() {
    cat "$ELBENCHO_PID_FILE" 2>/dev/null || echo "0"
}

echo "=== Elbencho workload starting (bucket: $BUCKET) ===" >&2

# 1. Create bucket
ec=$(run_elbencho -d "$BUCKET" 2>/dev/null)
log_op "CREATE_BUCKET" "PUT" "" 0 "$ec"
echo "  [1/11] create-bucket: exit=$ec (pid=$(get_elbencho_pid))" >&2

# 2. Head bucket (s3statdirs)
ec=$(run_elbencho --s3statdirs "$BUCKET" 2>/dev/null)
log_op "HEAD_BUCKET" "HEAD" "" 0 "$ec"
echo "  [2/11] head-bucket (s3statdirs): exit=$ec (pid=$(get_elbencho_pid))" >&2

# 3. Write small objects (1KB, single-part PUT)
# -t1 -n0 -N1 = 1 thread, no subdirs, 1 object → creates <bucket>/0/0
# Using -n0 -N2 to create 2 objects at root: 0 and 1
ec=$(run_elbencho -w -t1 -n0 -N2 -s 1k -b 1m --s3objprefix "test/" "$BUCKET" 2>/dev/null)
# This creates test/0 and test/1 (each 1KB, single PUT)
log_op "PUT_OBJECT" "PUT" "test/0" 1024 "$ec"
log_op "PUT_OBJECT" "PUT" "test/1" 1024 "$ec"
echo "  [3-4/11] put-object 1KB x2: exit=$ec (pid=$(get_elbencho_pid))" >&2

# 4. Write large object (10MB with 5MB block = multipart upload)
# This triggers: CreateMultipartUpload + 2x UploadPart + CompleteMultipartUpload
ec=$(run_elbencho -w -t1 -n0 -N1 -s 10m -b 5m --s3objprefix "mpu/" "$BUCKET" 2>/dev/null)
log_op "MPU_CREATE" "POST" "mpu/0" 0 "$ec"
log_op "MPU_PART" "PUT" "mpu/0" 5242880 "$ec"
log_op "MPU_PART" "PUT" "mpu/0" 5242880 "$ec"
log_op "MPU_COMPLETE" "POST" "mpu/0" 0 "$ec"
echo "  [5-8/11] multipart-upload 10MB (2 parts): exit=$ec (pid=$(get_elbencho_pid))" >&2

# 5. Stat objects (HEAD)
ec=$(run_elbencho --stat -t1 -n0 -N2 --s3objprefix "test/" "$BUCKET" 2>/dev/null)
log_op "HEAD_OBJECT" "HEAD" "test/0" 0 "$ec"
log_op "HEAD_OBJECT" "HEAD" "test/1" 0 "$ec"
echo "  [9/11] head-object x2: exit=$ec (pid=$(get_elbencho_pid))" >&2

# 6. Read objects (GET)
ec=$(run_elbencho -r -t1 -n0 -N2 -s 1k -b 1m --s3objprefix "test/" "$BUCKET" 2>/dev/null)
log_op "GET_OBJECT" "GET" "test/0" 0 "$ec"
log_op "GET_OBJECT" "GET" "test/1" 0 "$ec"
echo "  [10/11] get-object x2: exit=$ec (pid=$(get_elbencho_pid))" >&2

# 7. List objects
ec=$(run_elbencho --s3listobj 100 "$BUCKET" 2>/dev/null)
log_op "LIST_PREFIX" "GET" "" 0 "$ec"
echo "  [11/11] list-objects: exit=$ec (pid=$(get_elbencho_pid))" >&2

# 8. Delete small objects
ec=$(run_elbencho -F -t1 -n0 -N2 --s3objprefix "test/" "$BUCKET" 2>/dev/null)
log_op "DELETE_OBJECT" "DELETE" "test/0" 0 "$ec"
log_op "DELETE_OBJECT" "DELETE" "test/1" 0 "$ec"
echo "  [cleanup] delete test objects: exit=$ec" >&2

# 9. Delete multipart object
ec=$(run_elbencho -F -t1 -n0 -N1 --s3objprefix "mpu/" "$BUCKET" 2>/dev/null)
log_op "DELETE_OBJECT" "DELETE" "mpu/0" 0 "$ec"
echo "  [cleanup] delete mpu object: exit=$ec" >&2

# 10. Delete bucket
ec=$(run_elbencho -D "$BUCKET" 2>/dev/null)
log_op "DELETE_BUCKET" "DELETE" "" 0 "$ec"
echo "  [cleanup] delete-bucket: exit=$ec" >&2

echo "=== Elbencho workload complete ($SEQ operations logged) ===" >&2
