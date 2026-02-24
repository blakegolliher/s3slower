#!/usr/bin/env python3
"""Boto3 workload generator for s3slower validation.

Runs 19 deterministic S3 operations using boto3 and logs each one as JSONL.
"""

import argparse
import json
import os
import sys
import time
import urllib3
from datetime import datetime, timezone

# Suppress InsecureRequestWarning when --no-verify-ssl is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def log_op(f, seq, operation, method, bucket, key, size, exit_code):
    """Write a JSONL entry for one operation."""
    entry = {
        "seq": seq,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "pid": os.getpid(),
        "client": "boto3",
        "operation": operation,
        "method": method,
        "bucket": bucket,
        "key": key,
        "size": size,
        "exit_code": exit_code,
    }
    f.write(json.dumps(entry) + "\n")
    f.flush()


def main():
    parser = argparse.ArgumentParser(description="Boto3 S3 workload generator")
    parser.add_argument("--output", required=True, help="JSONL output path")
    parser.add_argument("--endpoint", required=True, help="S3 endpoint URL")
    parser.add_argument("--bucket", required=True, help="Bucket name")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()

    import boto3
    from botocore.config import Config as BotoConfig

    verify = not args.no_verify_ssl
    client = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        verify=verify,
        config=BotoConfig(
            retries={"max_attempts": 1, "mode": "standard"},
            signature_version="s3v4",
        ),
    )

    bucket = args.bucket
    seq = 0
    pid = os.getpid()
    print(f"=== Boto3 workload starting (bucket: {bucket}, pid: {pid}) ===", file=sys.stderr)

    # Create test data
    data_1kb = os.urandom(1024)
    data_1mb = os.urandom(1048576)
    data_5mb = os.urandom(5242880)

    with open(args.output, "w") as f:

        def do_op(label, operation, method, key, size, func):
            nonlocal seq
            seq += 1
            ec = 0
            try:
                func()
            except Exception as e:
                ec = 1
                print(f"  [{seq}/19] {label}: ERROR {e}", file=sys.stderr)
            else:
                print(f"  [{seq}/19] {label}: OK", file=sys.stderr)
            log_op(f, seq, operation, method, bucket, key, size, ec)
            time.sleep(1)  # 1s between operations for timestamp disambiguation

        # 1. create-bucket
        do_op("create-bucket", "CREATE_BUCKET", "PUT", "", 0,
              lambda: client.create_bucket(Bucket=bucket))

        # 2. head-bucket
        do_op("head-bucket", "HEAD_BUCKET", "HEAD", "", 0,
              lambda: client.head_bucket(Bucket=bucket))

        # 3. put-object (1KB)
        do_op("put-object 1KB", "PUT_OBJECT", "PUT", "test/small.txt", 1024,
              lambda: client.put_object(Bucket=bucket, Key="test/small.txt", Body=data_1kb))

        # 4. put-object (1MB)
        do_op("put-object 1MB", "PUT_OBJECT", "PUT", "test/medium.bin", 1048576,
              lambda: client.put_object(Bucket=bucket, Key="test/medium.bin", Body=data_1mb))

        # 5. head-object
        do_op("head-object", "HEAD_OBJECT", "HEAD", "test/small.txt", 0,
              lambda: client.head_object(Bucket=bucket, Key="test/small.txt"))

        # 6. get-object
        def get_object():
            resp = client.get_object(Bucket=bucket, Key="test/small.txt")
            resp["Body"].read()
        do_op("get-object", "GET_OBJECT", "GET", "test/small.txt", 0, get_object)

        # 7. list-objects-v2 (no prefix)
        do_op("list-objects-v2", "LIST_PREFIX", "GET", "", 0,
              lambda: client.list_objects_v2(Bucket=bucket))

        # 8. list-objects-v2 (with prefix)
        do_op("list-objects-v2 prefix", "LIST_PREFIX", "GET", "test/", 0,
              lambda: client.list_objects_v2(Bucket=bucket, Prefix="test/"))

        # 9. copy-object (PUT internally)
        do_op("copy-object", "PUT_OBJECT", "PUT", "test/copy.txt", 0,
              lambda: client.copy_object(
                  Bucket=bucket, Key="test/copy.txt",
                  CopySource=f"{bucket}/test/small.txt"))

        # 10. delete-object
        do_op("delete-object copy", "DELETE_OBJECT", "DELETE", "test/copy.txt", 0,
              lambda: client.delete_object(Bucket=bucket, Key="test/copy.txt"))

        # 11. create-multipart-upload
        mpu = {}
        def create_mpu():
            nonlocal mpu
            mpu = client.create_multipart_upload(Bucket=bucket, Key="test/multipart.bin")
        do_op("create-multipart-upload", "MPU_CREATE", "POST", "test/multipart.bin", 0,
              create_mpu)
        upload_id = mpu.get("UploadId", "")

        # 12. upload-part (5MB)
        part_etag = {}
        def upload_part():
            nonlocal part_etag
            resp = client.upload_part(
                Bucket=bucket, Key="test/multipart.bin",
                UploadId=upload_id, PartNumber=1, Body=data_5mb)
            part_etag["ETag"] = resp["ETag"]
        do_op("upload-part", "MPU_PART", "PUT", "test/multipart.bin", 5242880,
              upload_part)

        # 13. complete-multipart-upload
        do_op("complete-multipart-upload", "MPU_COMPLETE", "POST", "test/multipart.bin", 0,
              lambda: client.complete_multipart_upload(
                  Bucket=bucket, Key="test/multipart.bin",
                  UploadId=upload_id,
                  MultipartUpload={"Parts": [
                      {"PartNumber": 1, "ETag": part_etag.get("ETag", "")}
                  ]}))

        # 14. create-multipart-upload (for abort)
        mpu2 = {}
        def create_mpu2():
            nonlocal mpu2
            mpu2 = client.create_multipart_upload(Bucket=bucket, Key="test/abort-me.bin")
        do_op("create-multipart-upload (abort)", "MPU_CREATE", "POST", "test/abort-me.bin", 0,
              create_mpu2)
        upload_id2 = mpu2.get("UploadId", "")

        # 15. abort-multipart-upload
        do_op("abort-multipart-upload", "MPU_ABORT", "DELETE", "test/abort-me.bin", 0,
              lambda: client.abort_multipart_upload(
                  Bucket=bucket, Key="test/abort-me.bin",
                  UploadId=upload_id2))

        # 16-18. delete-object (cleanup)
        for key in ["test/small.txt", "test/medium.bin", "test/multipart.bin"]:
            do_op(f"delete-object {key}", "DELETE_OBJECT", "DELETE", key, 0,
                  lambda k=key: client.delete_object(Bucket=bucket, Key=k))

        # 19. delete-bucket
        do_op("delete-bucket", "DELETE_BUCKET", "DELETE", "", 0,
              lambda: client.delete_bucket(Bucket=bucket))

    print(f"=== Boto3 workload complete ({seq} operations) ===", file=sys.stderr)


if __name__ == "__main__":
    main()
