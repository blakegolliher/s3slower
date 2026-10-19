#!/usr/bin/env python3
"""AI-pipeline-shaped S3 workload for s3slower demos (boto3).

One "epoch" runs the phases of a typical training pipeline:

  ingest      parallel PUTs of dataset shards
  checkpoint  multipart uploads of large checkpoint files (s3transfer)
  promote     server-side copy of the newest checkpoint to latest.pt
  list        paginated ListObjectsV2 over the dataset prefix
  load        data-loader reads: full GETs, random ranged GETs, footer reads
  restore     checkpoint download (s3transfer: HEAD + parallel ranged GETs)
  head        metadata checks, plus a few misses (404) for absent checkpoints
  cleanup     batch DeleteObjects, single DeleteObject, one aborted MPU

Credentials come from the standard AWS chain (environment variables,
AWS_PROFILE / --profile, ~/.aws). Everything is written under
--prefix and removed at the end of each epoch.

With --truth FILE, every HTTP request botocore actually sends is logged as
JSONL so a capture can be reconciled 1:1 with demo/reconcile.py.
"""
import argparse
import io
import json
import os
import random
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError

_lock = threading.Lock()
_truth = None


def classify(method, path, query, headers):
    """Expected s3slower operation for a request botocore sends."""
    keys = {kv.split("=", 1)[0].lower() for kv in query.split("&") if kv}
    path_parts = [p for p in path.split("/") if p]
    if method == "PUT":
        if "partnumber" in keys:
            return "MPU_PART"
        return "COPY_OBJECT" if "x-amz-copy-source" in {h.lower() for h in headers} else "PUT_OBJECT"
    if method == "POST":
        if "uploads" in keys:
            return "MPU_CREATE"
        if "uploadid" in keys:
            return "MPU_COMPLETE"
        if "delete" in keys:
            return "DELETE_OBJECTS"
        return "UNKNOWN"
    if method == "DELETE":
        return "MPU_ABORT" if "uploadid" in keys else "DELETE_OBJECT"
    if method == "HEAD":
        return "HEAD_OBJECT" if len(path_parts) > 1 else "HEAD_BUCKET"
    if method == "GET":
        if "list-type" in keys or "prefix" in keys:
            return "LIST_PREFIX"
        if len(path_parts) <= 1:
            return "LIST_OBJECTS"
        return "GET_OBJECT_RANGE" if "Range" in headers else "GET_OBJECT"
    return "UNKNOWN"


def log_request(request, **kwargs):
    u = urlsplit(request.url)
    hdrs = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in request.headers.items()}
    rec = {
        "ts": time.time(),
        "tid": threading.get_native_id(),
        "method": request.method,
        "path": u.path + ("?" + u.query if u.query else ""),
        "range": hdrs.get("Range"),
        # botocore 1.36+ sends uploads aws-chunked: the body size is in
        # X-Amz-Decoded-Content-Length and Content-Length may be absent.
        "content_length": int(hdrs.get("X-Amz-Decoded-Content-Length")
                              or hdrs.get("Content-Length") or 0),
        "op": classify(request.method, u.path, u.query, hdrs),
    }
    with _lock:
        _truth.write(json.dumps(rec) + "\n")


def make_client(args):
    cfg = Config(
        max_pool_connections=max(args.threads, 16) * 2,
        retries={"max_attempts": 3, "mode": "standard"},
        s3={"addressing_style": "path"},
    )
    sess = boto3.session.Session(profile_name=args.profile) if args.profile else boto3.session.Session()
    c = sess.client("s3", endpoint_url=args.endpoint, config=cfg,
                    verify=(False if args.no_verify_ssl else None))
    if _truth:
        c.meta.events.register("before-send.s3.*", log_request)
    return c


def phase(name):
    print(f"[{time.strftime('%H:%M:%S')}] {name}", flush=True)


def run_epoch(c, args, epoch):
    b, pfx = args.bucket, f"{args.prefix}/epoch-{epoch}"
    rnd = random.Random(epoch)
    shard = os.urandom(args.shard_kib * 1024)
    shard_keys = [f"{pfx}/data/shard-{i:05d}.tar" for i in range(args.shards)]
    pool = ThreadPoolExecutor(args.threads)
    tc = TransferConfig(multipart_threshold=8 * 2**20, multipart_chunksize=8 * 2**20,
                        max_concurrency=args.threads)

    try:
        phase(f"ingest: PUT {len(shard_keys)} x {args.shard_kib} KiB shards")
        list(pool.map(lambda k: c.put_object(Bucket=b, Key=k, Body=shard), shard_keys))

        ckpt_keys = [f"{pfx}/ckpt/step-{s:06d}.pt" for s in range(args.ckpts)]
        if ckpt_keys:
            phase(f"checkpoint: multipart upload {len(ckpt_keys)} x {args.ckpt_mib} MiB")
            ckpt = os.urandom(args.ckpt_mib * 2**20)
            for k in ckpt_keys:
                c.upload_fileobj(io.BytesIO(ckpt), b, k, Config=tc)

            phase("promote: server-side copy to latest.pt")
            latest = f"{pfx}/ckpt/latest.pt"
            try:
                c.copy_object(Bucket=b, Key=latest, CopySource={"Bucket": b, "Key": ckpt_keys[-1]})
                ckpt_keys.append(latest)
            except ClientError as e:
                print(f"  copy_object failed ({e.response['Error'].get('Code')}); skipping", flush=True)

        phase(f"list: paginated ListObjectsV2 (page size {args.page_size})")
        pages = c.get_paginator("list_objects_v2").paginate(
            Bucket=b, Prefix=f"{pfx}/data/", PaginationConfig={"PageSize": args.page_size})
        listed = sum(len(p.get("Contents", [])) for p in pages)

        phase(f"load: {args.reads} reads (full GET, {args.range_kib} KiB ranged GET, footer)")
        size = args.shard_kib * 1024
        span = args.range_kib * 1024

        def reader(i):
            k = rnd.choice(shard_keys)
            kind = i % 4
            if kind == 0:
                c.get_object(Bucket=b, Key=k)["Body"].read()
            elif kind == 3 or size <= span:
                c.get_object(Bucket=b, Key=k, Range="bytes=-8192")["Body"].read()
            else:
                off = rnd.randrange(0, size - span)
                c.get_object(Bucket=b, Key=k, Range=f"bytes={off}-{off + span - 1}")["Body"].read()

        list(pool.map(reader, range(args.reads)))

        if ckpt_keys:
            phase("restore: checkpoint download")
            for k in ckpt_keys[:1]:
                c.download_fileobj(b, k, io.BytesIO(), Config=tc)

        phase(f"head: {args.heads} HEADs + {args.misses} misses")
        list(pool.map(lambda k: c.head_object(Bucket=b, Key=k), shard_keys[: args.heads]))

        def miss(i):
            try:
                c.head_object(Bucket=b, Key=f"{pfx}/ckpt/missing-{i}.pt")
            except ClientError:
                pass  # 404 expected: "is there a checkpoint to resume from?"

        list(pool.map(miss, range(args.misses)))

        phase("cleanup: DeleteObjects batches, DeleteObject, aborted MPU")
        for i in range(0, len(shard_keys), 1000):
            c.delete_objects(Bucket=b, Delete={"Objects": [{"Key": k} for k in shard_keys[i:i + 1000]],
                                               "Quiet": True})
        for k in ckpt_keys:
            c.delete_object(Bucket=b, Key=k)
        aborted = f"{pfx}/ckpt/aborted.pt"
        up = c.create_multipart_upload(Bucket=b, Key=aborted)
        c.upload_part(Bucket=b, Key=aborted, UploadId=up["UploadId"], PartNumber=1,
                      Body=os.urandom(5 * 2**20))
        c.abort_multipart_upload(Bucket=b, Key=aborted, UploadId=up["UploadId"])
        return listed
    finally:
        # On Ctrl-C or an error, drop queued requests and wait for the ones
        # in flight so cleanup does not race them.
        pool.shutdown(wait=True, cancel_futures=True)


def cleanup_prefix(c, bucket, prefix):
    """Delete every object and abort every multipart upload under prefix."""
    removed = 0
    for page in c.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix + "/"):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            c.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
            removed += len(objs)
    for up in c.list_multipart_uploads(Bucket=bucket, Prefix=prefix + "/").get("Uploads", []):
        c.abort_multipart_upload(Bucket=bucket, Key=up["Key"], UploadId=up["UploadId"])
    return removed


def main():
    global _truth
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoint", default=os.environ.get("S3_ENDPOINT"),
                    help="S3 endpoint URL (default: $S3_ENDPOINT)")
    ap.add_argument("--bucket", default=os.environ.get("S3_BUCKET"),
                    help="existing bucket to use (default: $S3_BUCKET)")
    ap.add_argument("--profile", help="AWS profile name")
    ap.add_argument("--prefix", default="s3slower-demo/boto3", help="key prefix for all objects")
    ap.add_argument("--no-verify-ssl", action="store_true", help="skip TLS certificate verification")
    ap.add_argument("--threads", type=int, default=8, help="concurrent requests")
    ap.add_argument("--shards", type=int, default=200, help="dataset shards per epoch")
    ap.add_argument("--shard-kib", type=int, default=1024, help="shard size")
    ap.add_argument("--ckpts", type=int, default=2, help="checkpoints per epoch (0 = no MPU/copy)")
    ap.add_argument("--ckpt-mib", type=int, default=64, help="checkpoint size")
    ap.add_argument("--reads", type=int, default=400, help="data-loader reads per epoch")
    ap.add_argument("--range-kib", type=int, default=64, help="ranged read size")
    ap.add_argument("--heads", type=int, default=50, help="HEADs of existing shards")
    ap.add_argument("--misses", type=int, default=5, help="HEADs of absent keys (404s)")
    ap.add_argument("--page-size", type=int, default=50, help="ListObjectsV2 page size")
    ap.add_argument("--epochs", type=int, default=0, help="epochs to run; 0 = until Ctrl-C")
    ap.add_argument("--pause", type=float, default=0, help="seconds to sleep between epochs")
    ap.add_argument("--truth", help="log every request sent to this JSONL file")
    args = ap.parse_args()
    if not args.endpoint or not args.bucket:
        ap.error("--endpoint and --bucket (or $S3_ENDPOINT and $S3_BUCKET) are required")

    if args.no_verify_ssl:
        import urllib3
        urllib3.disable_warnings()
    if args.truth:
        _truth = open(args.truth, "w", buffering=1)
    c = make_client(args)

    # SIGTERM (e.g. from a supervisor) stops like Ctrl-C, including cleanup.
    def on_term(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, on_term)
    epoch = 0
    try:
        while args.epochs == 0 or epoch < args.epochs:
            t0 = time.time()
            listed = run_epoch(c, args, epoch)
            print(f"epoch {epoch} done in {time.time() - t0:.1f}s (listed {listed} keys)", flush=True)
            epoch += 1
            if args.pause:
                time.sleep(args.pause)
    except BaseException as e:
        why = "interrupted" if isinstance(e, KeyboardInterrupt) else f"failed ({e})"
        print(f"\n{why}; cleaning up s3://{args.bucket}/{args.prefix}/", flush=True)
        print(f"removed {cleanup_prefix(c, args.bucket, args.prefix)} objects", flush=True)
        if not isinstance(e, KeyboardInterrupt):
            raise
    finally:
        if _truth:
            _truth.close()


if __name__ == "__main__":
    main()
