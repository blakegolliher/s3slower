#!/usr/bin/env python3
"""
Generate S3 traffic using boto3 over http/https for correlation with s3slower.

Usage:
  ./scripts/boto3-s3-test.py --iterations 10 --protocol https
  ./scripts/boto3-s3-test.py --iterations 50 --protocol http
  ./scripts/boto3-s3-test.py --iterations 100 --protocol both

Environment defaults:
  ENDPOINT_HOST (required)
  AWS_REGION (default: us-east-1)
  BUCKET (default: s3slower-boto3)
  PREFIX (default: s3slower-boto3)
  TMPDIR (default: /tmp/s3boto3)
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
import warnings
from pathlib import Path
from typing import List, Optional

import boto3
from botocore.config import Config
import urllib3

# Suppress SSL warnings when not verifying certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def log(msg: str) -> None:
    """Print timestamped log message to stderr."""
    ts = time.strftime("%F %T")
    print(f"{ts} {msg}", file=sys.stderr)


def write_op(ops_path: Path, protocol: str, op_name: str, http_method: str,
             bucket: str, target: str) -> None:
    """Write operation to ops log file."""
    ops_path.parent.mkdir(parents=True, exist_ok=True)
    with ops_path.open("a", encoding="utf-8") as f:
        f.write(f"{int(time.time())}\t{protocol}\t{op_name}\t"
                f"{http_method}\t{bucket}\t{target}\n")


def random_key(prefix: str) -> str:
    """Generate a random object key."""
    return f"{prefix}/file-{random.randint(0, 999999):06d}.bin"


class S3TestClient:
    """Wrapper for S3 client with key tracking."""

    def __init__(self, client, bucket: str, prefix: str, tmpdir: Path,
                 protocol: str, ops_path: Path):
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.tmpdir = tmpdir
        self.protocol = protocol
        self.ops_path = ops_path
        self.keys_file = tmpdir / "keys.txt"
        self.max_objects = 100
        self._load_keys()

    def _load_keys(self) -> None:
        """Load existing keys from file or S3."""
        self.keys: List[str] = []

        # Try loading from local file first
        if self.keys_file.exists():
            with self.keys_file.open("r") as f:
                self.keys = [line.strip() for line in f if line.strip()]

        # If empty, check S3
        if not self.keys:
            try:
                resp = self.client.list_objects_v2(
                    Bucket=self.bucket,
                    Prefix=self.prefix + "/",
                    MaxKeys=1000
                )
                for obj in resp.get("Contents", []):
                    self.keys.append(obj["Key"])
                self._save_keys()
            except Exception:
                pass  # Bucket might not exist yet

    def _save_keys(self) -> None:
        """Save current keys to file."""
        self.keys_file.parent.mkdir(parents=True, exist_ok=True)
        with self.keys_file.open("w") as f:
            for key in self.keys:
                f.write(f"{key}\n")

    def _add_key(self, key: str) -> None:
        """Add a key and save."""
        self.keys.append(key)
        self._save_keys()

    def _remove_key(self, key: str) -> None:
        """Remove a key and save."""
        self.keys = [k for k in self.keys if k != key]
        self._save_keys()

    def _pick_random_key(self) -> Optional[str]:
        """Pick a random existing key."""
        if not self.keys:
            return None
        return random.choice(self.keys)

    def _cleanup_if_needed(self) -> None:
        """Delete old objects if we have too many."""
        if len(self.keys) > self.max_objects:
            to_delete = len(self.keys) - self.max_objects + 10
            log(f"Cleanup: trimming {to_delete} objects")
            for _ in range(to_delete):
                self.delete_object(skip_log=True)

    def pre_warm(self) -> None:
        """Pre-warm s3slower attachment with dummy operations."""
        log("Pre-warming s3slower attachment...")
        try:
            # Do a list to trigger initial attachment
            self.client.list_objects_v2(Bucket=self.bucket, MaxKeys=1)
        except Exception:
            pass  # Bucket might not exist, that's OK

        # Do multiple dummy PUTs to ensure SSL_write probes are attached
        for i in range(3):
            try:
                dummy_key = f"{self.prefix}/.prewarm-{random.randint(0, 999999)}.tmp"
                self.client.put_object(Bucket=self.bucket, Key=dummy_key, Body=b"prewarm")
                # Clean up the dummy object
                self.client.delete_object(Bucket=self.bucket, Key=dummy_key)
                if i == 0:
                    time.sleep(1)  # Extra wait after first PUT
            except Exception:
                pass  # Ignore errors in pre-warming

        time.sleep(2)  # Wait for attachment to complete
        log("Pre-warming complete, starting actual test...")

    def ensure_bucket(self) -> None:
        """Create bucket if it doesn't exist."""
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except Exception:
            try:
                self.client.create_bucket(Bucket=self.bucket)
                log(f"Created bucket {self.bucket}")
            except Exception:
                pass  # Might already exist

    def seed_initial_objects(self, count: int = 5) -> None:
        """Seed initial objects if none exist."""
        if not self.keys:
            log(f"No existing keys, seeding with {count} PUTs")
            for i in range(count):
                self.put_small()

    def put_small(self, skip_log: bool = False) -> None:
        """PUT a small object (1MB)."""
        self._cleanup_if_needed()
        key = random_key(self.prefix)
        data = os.urandom(1024 * 1024)

        self.client.put_object(Bucket=self.bucket, Key=key, Body=data)
        self._add_key(key)

        if not skip_log:
            write_op(self.ops_path, self.protocol, "PUT_SMALL", "PUT",
                    self.bucket, key)

    def put_large(self, skip_log: bool = False) -> None:
        """PUT a large object (8MB, may trigger multipart)."""
        self._cleanup_if_needed()
        key = random_key(self.prefix)
        data = os.urandom(8 * 1024 * 1024)

        self.client.put_object(Bucket=self.bucket, Key=key, Body=data)
        self._add_key(key)

        if not skip_log:
            write_op(self.ops_path, self.protocol, "PUT_LARGE", "PUT",
                    self.bucket, key)

    def get_full(self) -> None:
        """GET a complete object."""
        key = self._pick_random_key()
        if not key:
            log("GET: no keys yet")
            return

        resp = self.client.get_object(Bucket=self.bucket, Key=key)
        resp["Body"].read()

        write_op(self.ops_path, self.protocol, "GET_FULL", "GET",
                self.bucket, key)

    def get_range(self) -> None:
        """GET a byte range from an object."""
        key = self._pick_random_key()
        if not key:
            log("RANGE: no keys yet")
            return

        resp = self.client.get_object(
            Bucket=self.bucket,
            Key=key,
            Range="bytes=0-1048575"
        )
        resp["Body"].read()

        write_op(self.ops_path, self.protocol, "GET_RANGE", "GET",
                self.bucket, key)

    def head_object(self) -> None:
        """HEAD an object."""
        key = self._pick_random_key()
        if not key:
            log("HEAD: no keys yet")
            return

        self.client.head_object(Bucket=self.bucket, Key=key)

        write_op(self.ops_path, self.protocol, "HEAD_OBJECT", "HEAD",
                self.bucket, key)

    def list_prefix(self) -> None:
        """LIST objects with prefix."""
        self.client.list_objects_v2(
            Bucket=self.bucket,
            Prefix=self.prefix + "/",
            MaxKeys=100
        )

        write_op(self.ops_path, self.protocol, "LIST_PREFIX", "GET",
                self.bucket, self.prefix)

    def delete_object(self, skip_log: bool = False) -> None:
        """DELETE an object."""
        key = self._pick_random_key()
        if not key:
            if not skip_log:
                log("DELETE: no keys yet")
            return

        self.client.delete_object(Bucket=self.bucket, Key=key)
        self._remove_key(key)

        if not skip_log:
            write_op(self.ops_path, self.protocol, "DELETE_OBJECT", "DELETE",
                    self.bucket, key)


def run_test(protocol: str, iterations: int, endpoint_host: str,
             region: str, bucket: str, prefix: str, tmpdir: Path,
             verify_ssl: bool) -> None:
    """Run test for a specific protocol."""

    ops_path = tmpdir / f"boto3-ops.log"

    # Configure boto3 client
    cfg = Config(
        signature_version="s3v4",
        retries={"max_attempts": 2, "mode": "standard"},
        s3={'addressing_style': 'path'}  # Explicitly use path-style addressing
    )

    client = boto3.client(
        "s3",
        endpoint_url=f"{protocol}://{endpoint_host}",
        region_name=region,
        config=cfg,
        use_ssl=(protocol == "https"),
        verify=verify_ssl,
    )

    log(f"Starting boto3 ops against {protocol}://{endpoint_host}, bucket {bucket}")
    log(f"Prefix={prefix} ; Running {iterations} iterations")

    # Create test client wrapper
    test_client = S3TestClient(client, bucket, prefix, tmpdir, protocol, ops_path)

    # Pre-warm to trigger s3slower attachment
    test_client.pre_warm()

    # Ensure bucket exists
    test_client.ensure_bucket()

    # Seed initial objects if needed
    test_client.seed_initial_objects()

    # Run random operations
    operations = [
        test_client.put_small,
        test_client.put_large,
        test_client.get_full,
        test_client.get_range,
        test_client.head_object,
        test_client.list_prefix,
        test_client.delete_object,
    ]

    # Weighted operations (more PUTs and GETs, fewer HEADs and LISTs)
    op_weights = [3, 1, 3, 2, 1, 1, 2]  # Adjust weights as needed
    weighted_ops = []
    for op, weight in zip(operations, op_weights):
        weighted_ops.extend([op] * weight)

    for i in range(iterations):
        op_func = random.choice(weighted_ops)
        op_func()

    log(f"Done. Ops log: {ops_path}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate S3 traffic with boto3 for s3slower correlation"
    )
    ap.add_argument("--iterations", type=int, default=10,
                    help="Number of operations to perform (default: 10)")
    ap.add_argument("--protocol", choices=["http", "https", "both"],
                    default="https",
                    help="Which protocol(s) to test (default: https)")
    ap.add_argument("--verify", action="store_true",
                    help="Verify TLS certificates (default: disabled)")
    args = ap.parse_args()

    # Get configuration from environment
    endpoint_host = os.environ.get("ENDPOINT_HOST")
    if not endpoint_host:
        print("ERROR: ENDPOINT_HOST must be set", file=sys.stderr)
        sys.exit(1)

    region = os.environ.get("AWS_REGION", "us-east-1")
    bucket = os.environ.get("BUCKET", "s3slower-boto3")
    prefix = os.environ.get("PREFIX", "s3slower-boto3")
    tmpdir = Path(os.environ.get("TMPDIR", "/tmp/s3boto3"))

    # Clear ops log at start
    ops_log = tmpdir / "boto3-ops.log"
    if ops_log.exists():
        ops_log.unlink()

    # Run tests for selected protocols
    protocols = ["http", "https"] if args.protocol == "both" else [args.protocol]

    for proto in protocols:
        run_test(
            protocol=proto,
            iterations=args.iterations,
            endpoint_host=endpoint_host,
            region=region,
            bucket=bucket,
            prefix=prefix,
            tmpdir=tmpdir,
            verify_ssl=args.verify
        )


if __name__ == "__main__":
    main()