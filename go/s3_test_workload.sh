#!/bin/bash

ENDPOINT="https://172.200.202.1"
BUCKET="ciscowritetput"
LOG_DIR="./s3_test_logs"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/s3_ops_$(date +%Y%m%d_%H%M%S).log"

aws_cmd() {
    echo "$(date '+%H:%M:%S') $1" | tee -a $LOG
    aws $2 --endpoint-url $ENDPOINT --no-verify-ssl 2>/dev/null
}

echo "S3 Test Workload - logging to $LOG" | tee $LOG

# Create test files
echo "small test data" > /tmp/small.txt
dd if=/dev/urandom of=/tmp/medium.bin bs=1024 count=100 2>/dev/null
dd if=/dev/urandom of=/tmp/large.bin bs=1024 count=1024 2>/dev/null

END=$((SECONDS + 60))
i=0

while [ $SECONDS -lt $END ]; do
    ((i++))
    echo "--- Iteration $i ---" | tee -a $LOG

    # ListBuckets
    aws_cmd "ListBuckets" "s3 ls"

    # ListObjects
    aws_cmd "ListObjects" "s3 ls s3://$BUCKET/"

    # ListObjectsWithPrefix
    aws_cmd "ListObjectsPrefix" "s3 ls s3://$BUCKET/test_"

    # PutObject (small)
    aws_cmd "PutObject-small" "s3 cp /tmp/small.txt s3://$BUCKET/test_${i}_small.txt"

    # PutObject (medium 100KB)
    aws_cmd "PutObject-100KB" "s3 cp /tmp/medium.bin s3://$BUCKET/test_${i}_medium.bin"

    # HeadObject
    aws_cmd "HeadObject" "s3api head-object --bucket $BUCKET --key test_${i}_small.txt"

    # GetObject
    aws_cmd "GetObject" "s3 cp s3://$BUCKET/test_${i}_small.txt /tmp/dl_${i}.txt"

    # CopyObject
    aws_cmd "CopyObject" "s3 cp s3://$BUCKET/test_${i}_small.txt s3://$BUCKET/test_${i}_copy.txt"

    # GetObjectAcl
    aws_cmd "GetObjectAcl" "s3api get-object-acl --bucket $BUCKET --key test_${i}_small.txt"

    # DeleteObject
    aws_cmd "DeleteObject" "s3 rm s3://$BUCKET/test_${i}_copy.txt"

    # Every 3rd iteration: large file + multipart
    if [ $((i % 3)) -eq 0 ]; then
        aws_cmd "PutObject-1MB" "s3 cp /tmp/large.bin s3://$BUCKET/test_${i}_large.bin"
        aws_cmd "GetObject-1MB" "s3 cp s3://$BUCKET/test_${i}_large.bin /tmp/dl_large_${i}.bin"
    fi

    sleep 2
done

# Cleanup
echo "--- Cleanup ---" | tee -a $LOG
aws_cmd "DeleteAll" "s3 rm s3://$BUCKET/test_ --recursive"

echo "$(date '+%H:%M:%S') Done - $i iterations" | tee -a $LOG
echo "Log: $LOG"
