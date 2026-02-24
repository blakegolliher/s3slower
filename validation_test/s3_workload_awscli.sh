#!/usr/bin/env bash
# s3_workload_awscli.sh - AWS CLI workload generator for s3slower validation
#
# Runs 19 deterministic S3 operations using aws s3api and logs each one as JSONL.
#
# Usage: s3_workload_awscli.sh <output_jsonl> <endpoint_url> <bucket_name> [no-verify-ssl]

set -euo pipefail

OUTPUT="$1"
ENDPOINT="$2"
BUCKET="$3"
VERIFY_SSL="${4:-true}"

SSL_FLAG=""
if [ "$VERIFY_SSL" = "false" ] || [ "$VERIFY_SSL" = "no-verify-ssl" ]; then
    SSL_FLAG="--no-verify-ssl"
fi

SEQ=0
TMPDIR_WL=$(mktemp -d)
trap 'rm -rf "$TMPDIR_WL"' EXIT

# Create test data files
dd if=/dev/urandom of="$TMPDIR_WL/1kb.bin" bs=1024 count=1 2>/dev/null
dd if=/dev/urandom of="$TMPDIR_WL/1mb.bin" bs=1048576 count=1 2>/dev/null
dd if=/dev/urandom of="$TMPDIR_WL/5mb.bin" bs=5242880 count=1 2>/dev/null

log_op() {
    local pid="$1" operation="$2" method="$3" key="$4" size="$5" exit_code="$6"
    SEQ=$((SEQ + 1))
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    printf '{"seq":%d,"timestamp":"%s","pid":%d,"client":"awscli","operation":"%s","method":"%s","bucket":"%s","key":"%s","size":%d,"exit_code":%d}\n' \
        "$SEQ" "$ts" "$pid" "$operation" "$method" "$BUCKET" "$key" "$size" "$exit_code" >> "$OUTPUT"
}

run_s3api() {
    # Run aws s3api command in background to capture PID, then wait for it
    local exit_code=0
    aws --endpoint-url "$ENDPOINT" $SSL_FLAG s3api "$@" &
    local cmd_pid=$!
    wait $cmd_pid || exit_code=$?
    echo "$cmd_pid:$exit_code"
}

echo "=== AWS CLI workload starting (bucket: $BUCKET) ===" >&2

# 1. create-bucket
result=$(run_s3api create-bucket --bucket "$BUCKET" 2>/dev/null)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "CREATE_BUCKET" "PUT" "" 0 "$ec"
echo "  [1/19] create-bucket: exit=$ec" >&2

# 2. head-bucket
result=$(run_s3api head-bucket --bucket "$BUCKET" 2>/dev/null)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "HEAD_BUCKET" "HEAD" "" 0 "$ec"
echo "  [2/19] head-bucket: exit=$ec" >&2

# 3. put-object (1KB)
result=$(run_s3api put-object --bucket "$BUCKET" --key "test/small.txt" --body "$TMPDIR_WL/1kb.bin" 2>/dev/null)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "PUT_OBJECT" "PUT" "test/small.txt" 1024 "$ec"
echo "  [3/19] put-object 1KB: exit=$ec" >&2

# 4. put-object (1MB)
result=$(run_s3api put-object --bucket "$BUCKET" --key "test/medium.bin" --body "$TMPDIR_WL/1mb.bin" 2>/dev/null)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "PUT_OBJECT" "PUT" "test/medium.bin" 1048576 "$ec"
echo "  [4/19] put-object 1MB: exit=$ec" >&2

# 5. head-object
result=$(run_s3api head-object --bucket "$BUCKET" --key "test/small.txt" 2>/dev/null)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "HEAD_OBJECT" "HEAD" "test/small.txt" 0 "$ec"
echo "  [5/19] head-object: exit=$ec" >&2

# 6. get-object
result=$(run_s3api get-object --bucket "$BUCKET" --key "test/small.txt" "$TMPDIR_WL/downloaded.txt" 2>/dev/null)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "GET_OBJECT" "GET" "test/small.txt" 0 "$ec"
echo "  [6/19] get-object: exit=$ec" >&2

# 7. list-objects-v2 (no prefix)
result=$(run_s3api list-objects-v2 --bucket "$BUCKET" 2>/dev/null)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "LIST_PREFIX" "GET" "" 0 "$ec"
echo "  [7/19] list-objects-v2: exit=$ec" >&2

# 8. list-objects-v2 (with prefix)
result=$(run_s3api list-objects-v2 --bucket "$BUCKET" --prefix "test/" 2>/dev/null)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "LIST_PREFIX" "GET" "test/" 0 "$ec"
echo "  [8/19] list-objects-v2 --prefix: exit=$ec" >&2

# 9. copy-object (copy = PUT internally)
result=$(run_s3api copy-object --bucket "$BUCKET" --key "test/copy.txt" --copy-source "$BUCKET/test/small.txt" 2>/dev/null)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "PUT_OBJECT" "PUT" "test/copy.txt" 0 "$ec"
echo "  [9/19] copy-object: exit=$ec" >&2

# 10. delete-object
result=$(run_s3api delete-object --bucket "$BUCKET" --key "test/copy.txt" 2>/dev/null)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "DELETE_OBJECT" "DELETE" "test/copy.txt" 0 "$ec"
echo "  [10/19] delete-object: exit=$ec" >&2

# 11. create-multipart-upload
mpu_output=$(aws --endpoint-url "$ENDPOINT" $SSL_FLAG s3api create-multipart-upload --bucket "$BUCKET" --key "test/multipart.bin" 2>/dev/null &
CMD_PID=$!
wait $CMD_PID || true
echo "PID:$CMD_PID"
)
# The output is interleaved - extract upload ID from JSON and PID from our marker
UPLOAD_ID=$(echo "$mpu_output" | grep -o '"UploadId": *"[^"]*"' | head -1 | cut -d'"' -f4)
MPU_PID=$(echo "$mpu_output" | grep "^PID:" | cut -d: -f2)
# Fallback: capture PID more reliably
if [ -z "$MPU_PID" ]; then MPU_PID=0; fi
log_op "$MPU_PID" "MPU_CREATE" "POST" "test/multipart.bin" 0 0
echo "  [11/19] create-multipart-upload: upload_id=$UPLOAD_ID" >&2

# 12. upload-part (5MB)
etag_output=$(aws --endpoint-url "$ENDPOINT" $SSL_FLAG s3api upload-part \
    --bucket "$BUCKET" --key "test/multipart.bin" \
    --upload-id "$UPLOAD_ID" --part-number 1 \
    --body "$TMPDIR_WL/5mb.bin" 2>/dev/null &
CMD_PID=$!
wait $CMD_PID || true
echo "PID:$CMD_PID"
)
ETAG=$(echo "$etag_output" | grep -o '"ETag": *"[^"]*"' | head -1 | cut -d'"' -f4)
PART_PID=$(echo "$etag_output" | grep "^PID:" | cut -d: -f2)
if [ -z "$PART_PID" ]; then PART_PID=0; fi
log_op "$PART_PID" "MPU_PART" "PUT" "test/multipart.bin" 5242880 0
echo "  [12/19] upload-part: etag=$ETAG" >&2

# 13. complete-multipart-upload
MPU_JSON="{\"Parts\":[{\"PartNumber\":1,\"ETag\":\"$ETAG\"}]}"
result=$(aws --endpoint-url "$ENDPOINT" $SSL_FLAG s3api complete-multipart-upload \
    --bucket "$BUCKET" --key "test/multipart.bin" \
    --upload-id "$UPLOAD_ID" \
    --multipart-upload "$MPU_JSON" >/dev/null 2>&1 &
CMD_PID=$!
wait $CMD_PID || true
echo "$CMD_PID:$?"
)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "MPU_COMPLETE" "POST" "test/multipart.bin" 0 "$ec"
echo "  [13/19] complete-multipart-upload: exit=$ec" >&2

# 14. create-multipart-upload (for abort)
mpu_output2=$(aws --endpoint-url "$ENDPOINT" $SSL_FLAG s3api create-multipart-upload --bucket "$BUCKET" --key "test/abort-me.bin" 2>/dev/null &
CMD_PID=$!
wait $CMD_PID || true
echo "PID:$CMD_PID"
)
UPLOAD_ID2=$(echo "$mpu_output2" | grep -o '"UploadId": *"[^"]*"' | head -1 | cut -d'"' -f4)
MPU_PID2=$(echo "$mpu_output2" | grep "^PID:" | cut -d: -f2)
if [ -z "$MPU_PID2" ]; then MPU_PID2=0; fi
log_op "$MPU_PID2" "MPU_CREATE" "POST" "test/abort-me.bin" 0 0
echo "  [14/19] create-multipart-upload (for abort): upload_id=$UPLOAD_ID2" >&2

# 15. abort-multipart-upload
result=$(aws --endpoint-url "$ENDPOINT" $SSL_FLAG s3api abort-multipart-upload \
    --bucket "$BUCKET" --key "test/abort-me.bin" \
    --upload-id "$UPLOAD_ID2" >/dev/null 2>&1 &
CMD_PID=$!
wait $CMD_PID || true
echo "$CMD_PID:$?"
)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "MPU_ABORT" "DELETE" "test/abort-me.bin" 0 "$ec"
echo "  [15/19] abort-multipart-upload: exit=$ec" >&2

# 16-18. delete-object (cleanup)
for key in "test/small.txt" "test/medium.bin" "test/multipart.bin"; do
    SEQ_DISPLAY=$((SEQ + 1))
    result=$(run_s3api delete-object --bucket "$BUCKET" --key "$key" 2>/dev/null)
    pid=${result%%:*}; ec=${result##*:}
    log_op "$pid" "DELETE_OBJECT" "DELETE" "$key" 0 "$ec"
    echo "  [$SEQ/19] delete-object $key: exit=$ec" >&2
done

# 19. delete-bucket
result=$(run_s3api delete-bucket --bucket "$BUCKET" 2>/dev/null)
pid=${result%%:*}; ec=${result##*:}
log_op "$pid" "DELETE_BUCKET" "DELETE" "" 0 "$ec"
echo "  [$SEQ/19] delete-bucket: exit=$ec" >&2

echo "=== AWS CLI workload complete ($SEQ operations) ===" >&2
