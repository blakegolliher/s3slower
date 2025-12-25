#!/bin/bash

ENDPOINT="https://172.200.202.1"
BUCKET="ciscowritetput"
LOG="s3_ops.log"

aws_cmd() {
    echo "$(date '+%H:%M:%S') $1" | tee -a $LOG
    aws $2 --endpoint-url $ENDPOINT --no-verify-ssl 2>/dev/null
}

echo "Starting S3 test - logging to $LOG" | tee $LOG
echo "testdata" > /tmp/testfile.txt

END=$((SECONDS + 60))
i=0

while [ $SECONDS -lt $END ]; do
    ((i++))

    aws_cmd "list-buckets" "s3 ls"
    aws_cmd "list-objects" "s3 ls s3://$BUCKET"
    aws_cmd "put-object test_$i.txt" "s3 cp /tmp/testfile.txt s3://$BUCKET/test_$i.txt"
    aws_cmd "head-object test_$i.txt" "s3api head-object --bucket $BUCKET --key test_$i.txt"
    aws_cmd "get-object test_$i.txt" "s3 cp s3://$BUCKET/test_$i.txt /tmp/downloaded_$i.txt"
    aws_cmd "delete-object test_$i.txt" "s3 rm s3://$BUCKET/test_$i.txt"

    sleep 2
done

echo "$(date '+%H:%M:%S') Done - $i iterations" | tee -a $LOG
