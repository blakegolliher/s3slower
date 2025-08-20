#!/usr/bin/env python3
"""
Simple boto3 test to see if the original s3slower catches boto3 traffic
"""

import boto3
import time
import sys

print("Testing boto3 S3 operations...")
print("Make sure s3slower is running in another terminal!")
print("")

# Configure boto3 client
endpoint_url = "http://172.200.201.1:80"
access_key = "supercools3accesskey"
secret_key = "SuperCoolS3SecretAccessKeyItReallyIsCool"

print(f"Connecting to S3 endpoint: {endpoint_url}")

try:
    # Create S3 client
    s3 = boto3.client(
        's3',
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    
    print("\n1. Listing buckets...")
    response = s3.list_buckets()
    buckets = response.get('Buckets', [])
    print(f"   Found {len(buckets)} buckets")
    for bucket in buckets[:5]:  # Show first 5
        print(f"   - {bucket['Name']}")
    
    time.sleep(1)
    
    # If warp-benchmark-bucket exists, try some operations
    bucket_name = "warp-benchmark-bucket"
    if any(b['Name'] == bucket_name for b in buckets):
        print(f"\n2. Listing objects in {bucket_name}...")
        response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
        objects = response.get('Contents', [])
        print(f"   Found {len(objects)} objects (showing first 10)")
        for obj in objects[:5]:  # Show first 5
            print(f"   - {obj['Key']} ({obj['Size']} bytes)")
        
        time.sleep(1)
        
        # Try a small PUT
        print(f"\n3. Putting a test object...")
        test_key = f"test-boto3-{int(time.time())}.txt"
        s3.put_object(
            Bucket=bucket_name,
            Key=test_key,
            Body=b"Hello from boto3 test!"
        )
        print(f"   Created {test_key}")
        
        time.sleep(1)
        
        # Try a GET
        print(f"\n4. Getting the test object back...")
        response = s3.get_object(Bucket=bucket_name, Key=test_key)
        data = response['Body'].read()
        print(f"   Retrieved: {data.decode('utf-8')}")
        
        time.sleep(1)
        
        # Clean up
        print(f"\n5. Deleting test object...")
        s3.delete_object(Bucket=bucket_name, Key=test_key)
        print(f"   Deleted {test_key}")
    
    print("\nDone! Check s3slower output.")
    
except Exception as e:
    print(f"\nError: {e}")
    print("\nMake sure:")
    print("1. The S3 endpoint is accessible")
    print("2. The credentials are correct")
    print("3. The bucket exists")
    sys.exit(1)
