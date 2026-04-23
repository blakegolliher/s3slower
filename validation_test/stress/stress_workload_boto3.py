#!/usr/bin/env python3
"""Long-running boto3 stress workload for s3slower validation.

Runs continuously, performing weighted-random S3 operations against a single
bucket. Logs every operation as JSONL (same schema as validation workloads).

Usage:
    stress_workload_boto3.py --output FILE --endpoint URL --bucket NAME
                             [--no-verify-ssl] [--max-data-gb N]
"""

import argparse
import json
import os
import random
import signal
import sys
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
SHUTDOWN = False
SEQ = 0
PID = os.getpid()
CLIENT = "boto3"

SIZES = [1024, 4096, 65536, 1048576, 16777216, 67108864]  # 1K..64M
OPERATION_WEIGHTS = [
    ("PUT_SINGLE", 25),
    ("PUT_MPU",    10),
    ("GET_FULL",   20),
    ("GET_RANGE",  10),
    ("HEAD",       10),
    ("LIST",       10),
    ("DELETE",     10),
    ("COPY",        5),
]
_WEIGHT_CUM = []
_WEIGHT_TOTAL = 0


def _build_weights():
    global _WEIGHT_CUM, _WEIGHT_TOTAL
    cum = 0
    for op, w in OPERATION_WEIGHTS:
        cum += w
        _WEIGHT_CUM.append((op, cum))
    _WEIGHT_TOTAL = cum

_build_weights()


def pick_operation():
    r = random.randint(1, _WEIGHT_TOTAL)
    for op, cum in _WEIGHT_CUM:
        if r <= cum:
            return op
    return _WEIGHT_CUM[-1][0]


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------
def _sig_handler(signum, frame):
    global SHUTDOWN
    SHUTDOWN = True
    print(f"[{datetime.now(timezone.utc).isoformat()}] Shutdown signal received",
          file=sys.stderr)

signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ---------------------------------------------------------------------------
# Object registry (in-memory)
# ---------------------------------------------------------------------------
class ObjectRegistry:
    def __init__(self):
        self._objects = {}  # key -> (size, timestamp)

    def add(self, key, size):
        self._objects[key] = (size, time.time())

    def remove(self, key):
        self._objects.pop(key, None)

    def count(self):
        return len(self._objects)

    def total_bytes(self):
        return sum(s for s, _ in self._objects.values())

    def random_object(self):
        """Return (key, size) or None if empty."""
        if not self._objects:
            return None
        key = random.choice(list(self._objects.keys()))
        size, _ = self._objects[key]
        return key, size

    def oldest_keys(self, n):
        """Return the n oldest keys."""
        items = sorted(self._objects.items(), key=lambda kv: kv[1][1])
        return [k for k, _ in items[:n]]


# ---------------------------------------------------------------------------
# JSONL logging
# ---------------------------------------------------------------------------
def log_op(f, operation, method, bucket, key, size, exit_code):
    global SEQ
    SEQ += 1
    entry = {
        "seq": SEQ,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pid": PID,
        "client": CLIENT,
        "operation": operation,
        "method": method,
        "bucket": bucket,
        "key": key,
        "size": size,
        "exit_code": exit_code,
    }
    f.write(json.dumps(entry) + "\n")
    f.flush()


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------
def do_put_single(s3, bucket, registry, logf):
    size = random.choice(SIZES)
    key = f"stress/{int(time.time())}-{random.randint(0, 99999)}"
    data = os.urandom(size)
    ec = 0
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=data)
        registry.add(key, size)
    except Exception as e:
        print(f"  PUT_SINGLE error: {e}", file=sys.stderr)
        ec = 1
    log_op(logf, "PUT_OBJECT", "PUT", bucket, key, size, ec)


def do_put_mpu(s3, bucket, registry, logf):
    key = f"stress/mpu-{int(time.time())}-{random.randint(0, 99999)}"
    part_size = 5 * 1024 * 1024  # 5MB
    num_parts = random.randint(7, 14)  # 35-70MB total
    total_size = part_size * num_parts

    # Create the MPU first in its own try so failures here don't need aborting.
    try:
        mpu = s3.create_multipart_upload(Bucket=bucket, Key=key)
    except Exception as e:
        print(f"  MPU_CREATE error: {e}", file=sys.stderr)
        log_op(logf, "MPU_CREATE", "POST", bucket, key, 0, 1)
        return
    upload_id = mpu["UploadId"]
    log_op(logf, "MPU_CREATE", "POST", bucket, key, 0, 0)

    # Any failure in parts/complete leaves an in-progress MPU on the server.
    # Abort it explicitly so the bucket stays clean over long runs (matches
    # the awscli stress workload behavior).
    try:
        parts = []
        for i in range(1, num_parts + 1):
            data = os.urandom(part_size)
            resp = s3.upload_part(
                Bucket=bucket, Key=key, UploadId=upload_id,
                PartNumber=i, Body=data,
            )
            parts.append({"ETag": resp["ETag"], "PartNumber": i})
            log_op(logf, "MPU_PART", "PUT", bucket, key, part_size, 0)

        s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
        log_op(logf, "MPU_COMPLETE", "POST", bucket, key, 0, 0)
        registry.add(key, total_size)
    except Exception as e:
        print(f"  PUT_MPU error: {e}", file=sys.stderr)
        try:
            s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
            log_op(logf, "MPU_ABORT", "POST", bucket, key, 0, 0)
        except Exception as abort_err:
            print(f"  MPU_ABORT error: {abort_err}", file=sys.stderr)
            log_op(logf, "MPU_ABORT", "POST", bucket, key, 0, 1)


def do_get_full(s3, bucket, registry, logf):
    obj = registry.random_object()
    if obj is None:
        return
    key, size = obj
    ec = 0
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        resp["Body"].read()
    except Exception as e:
        print(f"  GET_FULL error: {e}", file=sys.stderr)
        ec = 1
    log_op(logf, "GET_OBJECT", "GET", bucket, key, size, ec)


def do_get_range(s3, bucket, registry, logf):
    obj = registry.random_object()
    if obj is None:
        return
    key, size = obj
    if size < 2:
        return
    start = random.randint(0, size // 2)
    end = random.randint(start + 1, min(start + 1048576, size - 1))
    range_size = end - start + 1
    ec = 0
    try:
        resp = s3.get_object(Bucket=bucket, Key=key,
                             Range=f"bytes={start}-{end}")
        resp["Body"].read()
    except Exception as e:
        print(f"  GET_RANGE error: {e}", file=sys.stderr)
        ec = 1
    log_op(logf, "GET_OBJECT", "GET", bucket, key, range_size, ec)


def do_head(s3, bucket, registry, logf):
    obj = registry.random_object()
    if obj is None:
        return
    key, size = obj
    ec = 0
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except Exception as e:
        print(f"  HEAD error: {e}", file=sys.stderr)
        ec = 1
    log_op(logf, "HEAD_OBJECT", "HEAD", bucket, key, 0, ec)


def do_list(s3, bucket, registry, logf):
    max_keys = random.choice([10, 100, 1000])
    prefix = random.choice(["stress/", "stress/mpu-", ""])
    ec = 0
    try:
        s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=max_keys)
    except Exception as e:
        print(f"  LIST error: {e}", file=sys.stderr)
        ec = 1
    log_op(logf, "LIST_PREFIX", "GET", bucket, prefix, 0, ec)


def do_delete(s3, bucket, registry, logf):
    obj = registry.random_object()
    if obj is None:
        return
    key, size = obj
    ec = 0
    try:
        s3.delete_object(Bucket=bucket, Key=key)
        registry.remove(key)
    except Exception as e:
        print(f"  DELETE error: {e}", file=sys.stderr)
        ec = 1
    log_op(logf, "DELETE_OBJECT", "DELETE", bucket, key, 0, ec)


def do_copy(s3, bucket, registry, logf):
    obj = registry.random_object()
    if obj is None:
        return
    src_key, size = obj
    dst_key = f"stress/copy-{int(time.time())}-{random.randint(0, 99999)}"
    ec = 0
    try:
        s3.copy_object(
            Bucket=bucket, Key=dst_key,
            CopySource={"Bucket": bucket, "Key": src_key},
        )
        registry.add(dst_key, size)
    except Exception as e:
        print(f"  COPY error: {e}", file=sys.stderr)
        ec = 1
    log_op(logf, "PUT_OBJECT", "PUT", bucket, dst_key, size, ec)


DISPATCH = {
    "PUT_SINGLE": do_put_single,
    "PUT_MPU":    do_put_mpu,
    "GET_FULL":   do_get_full,
    "GET_RANGE":  do_get_range,
    "HEAD":       do_head,
    "LIST":       do_list,
    "DELETE":     do_delete,
    "COPY":       do_copy,
}


# ---------------------------------------------------------------------------
# Garbage collection
# ---------------------------------------------------------------------------
def gc_if_needed(s3, bucket, registry, max_gb):
    max_bytes = max_gb * (1024 ** 3)
    total = registry.total_bytes()
    if total <= max_bytes:
        return
    print(f"[{datetime.now(timezone.utc).isoformat()}] GC: "
          f"{total} bytes > {max_bytes}, deleting oldest 100", file=sys.stderr)
    for key in registry.oldest_keys(100):
        if SHUTDOWN:
            break
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except Exception:
            pass
        registry.remove(key)
    print(f"[{datetime.now(timezone.utc).isoformat()}] GC: "
          f"{registry.count()} objects remaining", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def create_client(endpoint, no_verify_ssl):
    import boto3
    from botocore.config import Config as BotoConfig
    session = boto3.session.Session()
    return session.client(
        "s3",
        endpoint_url=endpoint,
        verify=not no_verify_ssl,
        config=BotoConfig(
            retries={"max_attempts": 2, "mode": "standard"},
            connect_timeout=30,
            read_timeout=60,
        ),
    )


def main():
    parser = argparse.ArgumentParser(description="Boto3 stress workload")
    parser.add_argument("--output", required=True, help="JSONL output file")
    parser.add_argument("--endpoint", required=True, help="S3 endpoint URL")
    parser.add_argument("--bucket", required=True, help="Bucket name")
    parser.add_argument("--no-verify-ssl", action="store_true")
    parser.add_argument("--max-data-gb", type=int, default=250)
    parser.add_argument("--cycle-min-s", type=int, default=30)
    parser.add_argument("--cycle-max-s", type=int, default=120)
    parser.add_argument("--ops-min", type=int, default=1)
    parser.add_argument("--ops-max", type=int, default=5)
    args = parser.parse_args()

    s3 = create_client(args.endpoint, args.no_verify_ssl)
    registry = ObjectRegistry()
    client_created = time.time()
    cycle = 0

    print(f"[{datetime.now(timezone.utc).isoformat()}] boto3 stress workload "
          f"started (PID {PID}, bucket={args.bucket})", file=sys.stderr)

    with open(args.output, "a") as logf:
        while not SHUTDOWN:
            cycle += 1

            # Recreate client every 6 hours to avoid stale connections
            if time.time() - client_created > 6 * 3600:
                print(f"[{datetime.now(timezone.utc).isoformat()}] "
                      f"Recreating boto3 client", file=sys.stderr)
                s3 = create_client(args.endpoint, args.no_verify_ssl)
                client_created = time.time()

            # Random number of operations per cycle
            num_ops = random.randint(args.ops_min, args.ops_max)
            for _ in range(num_ops):
                if SHUTDOWN:
                    break

                op = pick_operation()
                # Operations that need existing objects fall back to PUT if
                # the registry is empty
                needs_objects = op in ("GET_FULL", "GET_RANGE", "HEAD",
                                       "DELETE", "COPY")
                if needs_objects and registry.count() == 0:
                    op = "PUT_SINGLE"

                try:
                    DISPATCH[op](s3, args.bucket, registry, logf)
                except Exception as e:
                    print(f"  Unhandled error in {op}: {e}", file=sys.stderr)

            # Periodic status
            if cycle % 10 == 0:
                print(f"[{datetime.now(timezone.utc).isoformat()}] "
                      f"boto3 cycle={cycle} objects={registry.count()} "
                      f"bytes={registry.total_bytes()} seq={SEQ}",
                      file=sys.stderr)

            # Garbage collection
            gc_if_needed(s3, args.bucket, registry, args.max_data_gb)

            # Random sleep between cycles
            sleep_secs = random.randint(args.cycle_min_s, args.cycle_max_s)
            # Sleep in small increments to allow shutdown
            for _ in range(sleep_secs):
                if SHUTDOWN:
                    break
                time.sleep(1)

    print(f"[{datetime.now(timezone.utc).isoformat()}] boto3 stress workload "
          f"exiting (seq={SEQ}, objects={registry.count()})", file=sys.stderr)


if __name__ == "__main__":
    main()
