#!/usr/bin/env python3
"""Randomized, ever-changing S3 workload for exploring the s3slower dashboard.

Worker threads pick weighted-random S3 operations against a bounded working
set under --prefix: PUTs of mixed sizes, multipart uploads, server-side
copies, full and ranged GETs, HEADs (some for absent keys), paginated LISTs,
single and batch deletes, aborted multipart uploads, and the occasional GET
of a missing key. Every 1-3 minutes the mix shifts to a new scenario
(ingest, training, checkpoint, evaluation, compaction, mixed) and the load
level drifts, so every panel keeps moving.

Credentials come from the standard AWS chain. Everything under --prefix is
deleted on exit (Ctrl-C, SIGTERM, or --duration elapsed).
"""
import argparse
import ctypes
import io
import math
import os
import random
import signal
import sys
import threading
import time
import uuid
from collections import Counter

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError

KiB, MiB = 1024, 1024 * 1024

# Operation weights per scenario. Absent keys mean weight 0.
SCENARIOS = {
    "ingest": dict(put=40, mpu=6, list=6, head=8, get=5, get_range=10, delete=5,
                   delete_batch=2, copy=2, head_miss=4, mpu_abort=1),
    "training": dict(get_range=45, get=20, head=10, list=6, put=6, head_miss=3,
                     get_miss=1, delete=3, delete_batch=1, mpu=1),
    "checkpoint": dict(mpu=18, put=15, copy=6, get_range=20, get=10, head=10, list=6,
                       delete=6, mpu_abort=3, head_miss=6),
    "evaluation": dict(get=35, get_range=25, head=15, head_miss=8, get_miss=3, list=8,
                       put=4, delete=2),
    "compaction": dict(list=15, get=15, put=20, copy=10, delete=18, delete_batch=6,
                       head=8, get_range=6, head_miss=2),
    "mixed": dict(get=15, get_range=20, put=15, mpu=4, copy=3, head=12, head_miss=4,
                  get_miss=1, list=8, delete=8, delete_batch=2, mpu_abort=1),
}
DIRS = [f"data/part-{i:02d}" for i in range(16)] + ["eval", "features"]


class Registry:
    """Thread-safe set of objects the workload has written."""

    def __init__(self):
        self.lock = threading.Lock()
        self.keys, self.index, self.sizes = [], {}, {}
        self.bytes = 0

    def add(self, key, size):
        with self.lock:
            if key in self.index:
                return
            self.index[key] = len(self.keys)
            self.keys.append(key)
            self.sizes[key] = size
            self.bytes += size

    def pick(self, remove=False):
        with self.lock:
            if not self.keys:
                return None, 0
            key = random.choice(self.keys)
            size = self.sizes[key]
            if remove:
                self._remove(key)
            return key, size

    def take(self, n):
        with self.lock:
            out = []
            for _ in range(min(n, len(self.keys))):
                key = random.choice(self.keys)
                out.append(key)
                self._remove(key)
            return out

    def _remove(self, key):
        i = self.index.pop(key)
        last = self.keys.pop()
        if last != key:
            self.keys[i] = last
            self.index[last] = i
        self.bytes -= self.sizes.pop(key)

    def stats(self):
        with self.lock:
            return len(self.keys), self.bytes


class Workload:
    def __init__(self, args):
        self.args = args
        cfg = Config(max_pool_connections=args.threads * 2 + 8,
                     retries={"max_attempts": 3, "mode": "standard"},
                     s3={"addressing_style": "path"})
        sess = boto3.session.Session(profile_name=args.profile) if args.profile else boto3.session.Session()
        self.s3 = sess.client("s3", endpoint_url=args.endpoint, config=cfg,
                              verify=(False if args.no_verify_ssl else None))
        self.tc = TransferConfig(multipart_threshold=8 * MiB, multipart_chunksize=8 * MiB,
                                 max_concurrency=4)
        self.reg = Registry()
        self.stop = threading.Event()
        self.counts, self.errors = Counter(), Counter()
        self.count_lock = threading.Lock()
        self.scenario = "mixed"
        self.active = args.threads
        self.data = os.urandom(96 * MiB)  # payload source; content does not matter

    # ---------- helpers ----------
    def key(self, folder):
        return f"{self.args.prefix}/{folder}/obj-{uuid.uuid4().hex[:16]}"

    def put_size(self):
        r = random.random()
        lo, hi = (4 * KiB, 256 * KiB) if r < 0.55 else (256 * KiB, 4 * MiB) if r < 0.9 else (4 * MiB, 16 * MiB)
        return int(math.exp(random.uniform(math.log(lo), math.log(hi))))

    def body(self, n):
        start = random.randrange(0, len(self.data) - n + 1)
        return self.data[start:start + n]

    def record(self, op, ok=True):
        with self.count_lock:
            self.counts[op] += 1
            if not ok:
                self.errors[op] += 1

    # ---------- operations ----------
    def op_put(self):
        n = self.put_size()
        k = self.key(random.choice(DIRS))
        self.s3.put_object(Bucket=self.args.bucket, Key=k, Body=self.body(n))
        self.reg.add(k, n)

    def op_mpu(self):
        n = random.randint(24, 80) * MiB
        k = self.key("ckpt")
        self.s3.upload_fileobj(io.BytesIO(self.body(n)), self.args.bucket, k, Config=self.tc)
        self.reg.add(k, n)

    def op_mpu_abort(self):
        k = self.key("ckpt")
        up = self.s3.create_multipart_upload(Bucket=self.args.bucket, Key=k)
        try:
            self.s3.upload_part(Bucket=self.args.bucket, Key=k, UploadId=up["UploadId"],
                                PartNumber=1, Body=self.body(5 * MiB))
        finally:
            self.s3.abort_multipart_upload(Bucket=self.args.bucket, Key=k, UploadId=up["UploadId"])

    def op_copy(self):
        src, size = self.reg.pick()
        if src is None:
            return self.op_put()
        k = self.key(random.choice(["eval", "features"]))
        self.s3.copy_object(Bucket=self.args.bucket, Key=k,
                            CopySource={"Bucket": self.args.bucket, "Key": src})
        self.reg.add(k, size)

    def op_get(self):
        k, size = self.reg.pick()
        if k is None:
            return self.op_put()
        if size > 32 * MiB:  # whole-object reads of large checkpoints go ranged instead
            return self.op_get_range()
        self.s3.get_object(Bucket=self.args.bucket, Key=k)["Body"].read()

    def op_get_range(self):
        k, size = self.reg.pick()
        if k is None:
            return self.op_put()
        if random.random() < 0.2:
            rng = f"bytes=-{min(size, random.choice([8 * KiB, 64 * KiB]))}"  # footer read
        else:
            span = min(size, random.choice([4 * KiB, 64 * KiB, 256 * KiB, 1 * MiB, 4 * MiB]))
            off = random.randrange(0, size - span + 1)
            rng = f"bytes={off}-{off + span - 1}"
        self.s3.get_object(Bucket=self.args.bucket, Key=k, Range=rng)["Body"].read()

    def op_head(self):
        k, _ = self.reg.pick()
        if k is None:
            return self.op_head_miss()
        self.s3.head_object(Bucket=self.args.bucket, Key=k)

    def op_head_miss(self):
        try:
            self.s3.head_object(Bucket=self.args.bucket, Key=self.key("ckpt") + ".missing")
        except ClientError:
            pass  # 404 expected

    def op_get_miss(self):
        try:
            self.s3.get_object(Bucket=self.args.bucket, Key=self.key("eval") + ".missing")
        except ClientError:
            pass  # 404 NoSuchKey expected

    def op_list(self):
        folder = random.choice(DIRS + ["ckpt", ""])
        prefix = f"{self.args.prefix}/{folder}" + ("/" if folder else "")
        kwargs = {"Bucket": self.args.bucket, "Prefix": prefix,
                  "PaginationConfig": {"PageSize": random.choice([50, 100, 250, 1000]),
                                       "MaxItems": 2000}}
        if random.random() < 0.3:
            kwargs["Delimiter"] = "/"
        for _ in self.s3.get_paginator("list_objects_v2").paginate(**kwargs):
            pass

    def op_delete(self):
        k, _ = self.reg.pick(remove=True)
        if k is None:
            return self.op_put()
        self.s3.delete_object(Bucket=self.args.bucket, Key=k)

    def op_delete_batch(self):
        keys = self.reg.take(random.randint(10, 200))
        if not keys:
            return self.op_put()
        self.s3.delete_objects(Bucket=self.args.bucket,
                               Delete={"Objects": [{"Key": k} for k in keys], "Quiet": True})

    # ---------- scheduling ----------
    def choose_op(self):
        weights = dict(SCENARIOS[self.scenario])
        n, nbytes = self.reg.stats()
        if n >= self.args.max_objects or nbytes >= self.args.max_gib * 1024 * MiB:
            for grow in ("put", "mpu", "copy"):
                weights.pop(grow, None)
            weights["delete"] = weights.get("delete", 0) + 20
            weights["delete_batch"] = weights.get("delete_batch", 0) + 10
        elif n < 100:
            weights["put"] = weights.get("put", 0) + 40
        ops = list(weights)
        return random.choices(ops, weights=[weights[o] for o in ops])[0]

    def worker(self, idx):
        while not self.stop.is_set():
            if idx >= self.active:
                self.stop.wait(0.5)
                continue
            op = self.choose_op()
            try:
                getattr(self, "op_" + op)()
                self.record(op)
            except ClientError as e:
                self.record(op, ok=False)
                if self.args.verbose:
                    print(f"  {op}: {e.response.get('Error', {}).get('Code')}", flush=True)
            except Exception as e:  # network blips etc. keep the workload alive
                self.record(op, ok=False)
                print(f"  {op}: {type(e).__name__}: {e}", flush=True)
                self.stop.wait(1)
            self.stop.wait(random.expovariate(1000.0 / self.args.think_ms))

    def conductor(self):
        """Shift the scenario every 1-3 minutes and drift the load level."""
        start, next_switch, period = time.time(), 0, random.uniform(480, 900)
        while not self.stop.is_set():
            now = time.time()
            if now >= next_switch:
                self.scenario = random.choice([s for s in SCENARIOS if s != self.scenario])
                next_switch = now + random.uniform(60, 180)
                print(f"[{time.strftime('%H:%M:%S')}] scenario -> {self.scenario}", flush=True)
            level = 0.6 + 0.3 * math.sin(2 * math.pi * (now - start) / period)
            if random.random() < 0.03:
                level = 1.0  # short burst
            self.active = max(1, round(self.args.threads * min(1.0, max(0.2, level))))
            self.stop.wait(5)

    def reporter(self):
        last = Counter()
        while not self.stop.wait(30):
            with self.count_lock:
                now = Counter(self.counts)
                errs = sum(self.errors.values())
            delta = now - last
            last = now
            n, nbytes = self.reg.stats()
            top = ", ".join(f"{k}={v}" for k, v in delta.most_common(6))
            print(f"[{time.strftime('%H:%M:%S')}] {self.scenario:<10} workers={self.active:<3} "
                  f"{sum(delta.values()) / 30:6.1f} ops/s  objects={n} ({nbytes / 1024**3:.2f} GiB)  "
                  f"errors={errs}  [{top}]", flush=True)

    def cleanup(self):
        print(f"cleaning up s3://{self.args.bucket}/{self.args.prefix}/ ...", flush=True)
        removed = 0
        pages = self.s3.get_paginator("list_objects_v2").paginate(
            Bucket=self.args.bucket, Prefix=self.args.prefix + "/")
        for page in pages:
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                self.s3.delete_objects(Bucket=self.args.bucket, Delete={"Objects": objs, "Quiet": True})
                removed += len(objs)
        uploads = self.s3.list_multipart_uploads(Bucket=self.args.bucket, Prefix=self.args.prefix + "/")
        for up in uploads.get("Uploads", []):
            self.s3.abort_multipart_upload(Bucket=self.args.bucket, Key=up["Key"], UploadId=up["UploadId"])
        print(f"removed {removed} objects", flush=True)

    def run(self):
        threads = [threading.Thread(target=self.worker, args=(i,), daemon=True)
                   for i in range(self.args.threads)]
        threads += [threading.Thread(target=self.conductor, daemon=True),
                    threading.Thread(target=self.reporter, daemon=True)]
        for t in threads:
            t.start()
        deadline = time.time() + self.args.duration if self.args.duration else None
        try:
            while not self.stop.is_set():
                if deadline and time.time() >= deadline:
                    print("duration reached", flush=True)
                    break
                self.stop.wait(1)
        finally:
            self.stop.set()
            for t in threads:
                t.join(timeout=120)
            self.cleanup()


def set_process_name(name):
    """Set the process (and inherited thread) name shown as the client label."""
    try:
        libc = ctypes.CDLL(None)
        libc.prctl(15, ctypes.c_char_p(name.encode()[:15]), 0, 0, 0)  # PR_SET_NAME
    except (OSError, AttributeError):
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoint", default=os.environ.get("S3_ENDPOINT"), help="default: $S3_ENDPOINT")
    ap.add_argument("--bucket", default=os.environ.get("S3_BUCKET"), help="default: $S3_BUCKET")
    ap.add_argument("--profile", help="AWS profile name")
    ap.add_argument("--prefix", default="s3slower-demo/mixed", help="key prefix for all objects")
    ap.add_argument("--no-verify-ssl", action="store_true", help="skip TLS certificate verification")
    ap.add_argument("--threads", type=int, default=16, help="maximum concurrent workers")
    ap.add_argument("--think-ms", type=float, default=40, help="mean pause between a worker's requests")
    ap.add_argument("--max-objects", type=int, default=3000, help="working-set object cap")
    ap.add_argument("--max-gib", type=float, default=8, help="working-set size cap in GiB")
    ap.add_argument("--duration", type=float, default=0, help="seconds to run; 0 = until stopped")
    ap.add_argument("--process-name", help="process name, shown as the dashboard client label")
    ap.add_argument("--verbose", action="store_true", help="print every S3 error")
    args = ap.parse_args()
    if not args.endpoint or not args.bucket:
        ap.error("--endpoint and --bucket (or $S3_ENDPOINT and $S3_BUCKET) are required")
    if args.no_verify_ssl:
        import urllib3
        urllib3.disable_warnings()
    if args.process_name:
        set_process_name(args.process_name)

    w = Workload(args)
    # SIGTERM stops like Ctrl-C, so a supervisor's stop still cleans up.
    signal.signal(signal.SIGTERM, lambda *_: w.stop.set())
    signal.signal(signal.SIGINT, lambda *_: w.stop.set())
    print(f"mixed workload: {args.threads} workers against s3://{args.bucket}/{args.prefix}/", flush=True)
    w.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
