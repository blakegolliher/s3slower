#!/usr/bin/env python3
"""
scripts/s3slower_correlate.py

Correlate aws-s3-test.sh operation logs with s3slower --log-file output to
validate that all expected S3 operations are observed by the tracer.

Usage:
  ./scripts/s3slower_correlate.py --ops /tmp/s3rand/aws-s3-ops.log --trace /tmp/s3slower-https.log

The aws-s3-test.sh OPS_LOG format (TSV) is:
  epoch_seconds  protocol  op_name  http_method  bucket  target

The s3slower --log-file format (TSV) is:
  ts_ns  time_str  pid  comm  method_bucket  lat_ms  status  bucket  endpoint  path
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
from urllib.parse import quote


@dataclass
class OpRecord:
    index: int
    epoch: int
    protocol: str
    op_name: str
    http_method: str
    bucket: str
    target: str


@dataclass
class TraceRecord:
    index: int
    ts_ns: int
    time_str: str
    pid: int
    comm: str
    method_bucket: str
    lat_ms: float
    status: str
    bucket: str
    endpoint: str
    path: str


@dataclass
class MultipartCheck:
    bucket: str
    key: str
    op_count: int
    create_count: int
    part_put_count: int
    complete_count: int

    @property
    def ok_create(self) -> bool:
        return self.create_count >= 1

    @property
    def ok_parts(self) -> bool:
        return self.part_put_count >= 1

    @property
    def ok_complete(self) -> bool:
        return self.complete_count >= 1

    @property
    def ok_all(self) -> bool:
        return self.ok_create and self.ok_parts and self.ok_complete


def parse_ops_log(path: str) -> List[OpRecord]:
    ops: List[OpRecord] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for _, line in enumerate(f):
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < 6:
                    continue
                try:
                    epoch = int(parts[0])
                except ValueError:
                    continue
                protocol, op_name, http_method, bucket, target = parts[1:6]
                ops.append(
                    OpRecord(
                        index=len(ops),
                        epoch=epoch,
                        protocol=protocol,
                        op_name=op_name,
                        http_method=http_method.upper(),
                        bucket=bucket,
                        target=target,
                    )
                )
    except OSError as e:
        print(f"ERROR: failed to read ops log {path}: {e}", file=sys.stderr)
        sys.exit(1)
    return ops


def parse_trace_log(path: str) -> List[TraceRecord]:
    traces: List[TraceRecord] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for _, line in enumerate(f):
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < 10:
                    continue
                try:
                    ts_ns = int(parts[0])
                    pid = int(parts[2])
                    lat_ms = float(parts[5])
                except ValueError:
                    continue
                time_str = parts[1]
                comm = parts[3]
                method_bucket = parts[4].upper()
                status = parts[6]
                bucket = parts[7]
                endpoint = parts[8]
                path = parts[9]
                traces.append(
                    TraceRecord(
                        index=len(traces),
                        ts_ns=ts_ns,
                        time_str=time_str,
                        pid=pid,
                        comm=comm,
                        method_bucket=method_bucket,
                        lat_ms=lat_ms,
                        status=status,
                        bucket=bucket,
                        endpoint=endpoint,
                        path=path,
                    )
                )
    except OSError as e:
        print(f"ERROR: failed to read trace log {path}: {e}", file=sys.stderr)
        sys.exit(1)
    return traces


def key_in_path(key: str, path: str) -> bool:
    """Return True if key (or its URL-encoded form) appears in the HTTP path."""
    if not key or not path:
        return False
    if key in path:
        return True
    encoded = quote(key, safe="/")
    if encoded in path:
        return True
    return False


def prefix_in_path(prefix: str, path: str) -> bool:
    """Return True if prefix (or its URL-encoded form) appears in the HTTP path."""
    if not prefix or not path:
        return False
    if prefix in path:
        return True
    encoded = quote(prefix, safe="/")
    if encoded in path:
        return True
    return False


def op_matches_trace(op: OpRecord, tr: TraceRecord) -> bool:
    # Bucket must match exactly.
    if tr.bucket != op.bucket:
        return False

    path = tr.path or ""
    method = tr.method_bucket.upper()

    # LIST_PREFIX: match GET on bucket/prefix listing
    if op.op_name == "LIST_PREFIX":
        if method != "GET":
            return False
        return prefix_in_path(op.target, path)

    # Key-based operations
    if not key_in_path(op.target, path):
        return False

    # Special handling for multipart PUTs:
    # - PUT_LARGE_MPU represents a full MPU lifecycle; we consider it
    #   matched by either MPU_CREATE or MPU_COMPLETE to keep a 1:1 anchor,
    #   while a separate summary validates the full pattern.
    if op.op_name == "PUT_LARGE_MPU":
        if op.http_method != "PUT":
            return False
        return method in ("MPU_CREATE", "MPU_COMPLETE")

    if op.http_method == "PUT":
        # Single PUT
        return method == "PUT"
    if op.http_method == "GET":
        return method == "GET"
    if op.http_method == "DELETE":
        return method in ("DELETE", "DEL")
    if op.http_method == "HEAD":
        return method == "HEAD"

    # Fallback: require at least method match
    return method == op.http_method


def correlate(
    ops: List[OpRecord],
    traces: List[TraceRecord],
) -> Tuple[Dict[int, int], List[int]]:
    """
    Greedy correlation: for each op in order, find the first unused trace
    record that matches bucket/method/key/prefix.

    Returns:
      - mapping: op_index -> trace_index
      - missing_ops: list of op indices that had no matching trace
    """
    mapping: Dict[int, int] = {}
    used = [False] * len(traces)
    missing: List[int] = []

    for op in ops:
        match_idx: Optional[int] = None
        for tr in traces:
            if used[tr.index]:
                continue
            if op_matches_trace(op, tr):
                match_idx = tr.index
                break
        if match_idx is None:
            missing.append(op.index)
        else:
            mapping[op.index] = match_idx
            used[match_idx] = True

    return mapping, missing


def build_multipart_checks(ops: List[OpRecord], traces: List[TraceRecord]) -> List[MultipartCheck]:
    """
    For each unique (bucket, key) used in PUT_LARGE_MPU ops, verify the
    presence of MPU_CREATE, part PUTs, and MPU_COMPLETE in the trace log.
    """
    # Aggregate MPU ops per (bucket, key)
    by_key: Dict[Tuple[str, str], MultipartCheck] = {}
    for op in ops:
        if op.op_name != "PUT_LARGE_MPU":
            continue
        key = (op.bucket, op.target)
        if key not in by_key:
            by_key[key] = MultipartCheck(
                bucket=op.bucket,
                key=op.target,
                op_count=0,
                create_count=0,
                part_put_count=0,
                complete_count=0,
            )
        by_key[key].op_count += 1

    if not by_key:
        return []

    entries = list(by_key.values())

    # For each entry, scan all traces and count matching MPU operations
    for entry in entries:
        for tr in traces:
            if tr.bucket != entry.bucket:
                continue
            if not key_in_path(entry.key, tr.path or ""):
                continue
            method = tr.method_bucket.upper()
            path = tr.path or ""
            if method == "MPU_CREATE":
                entry.create_count += 1
            elif method == "MPU_COMPLETE":
                entry.complete_count += 1
            elif method == "PUT" and "uploadId=" in path:
                entry.part_put_count += 1

    return entries


def summarize(
    ops: List[OpRecord],
    traces: List[TraceRecord],
    mapping: Dict[int, int],
    missing: List[int],
    mpu_checks: List[MultipartCheck],
) -> None:
    total_ops = len(ops)
    matched_ops = len(mapping)
    missing_ops = len(missing)
    total_traces = len(traces)
    used_traces = len(set(mapping.values()))
    unused_traces = total_traces - used_traces

    print("=== Correlation Summary ===")
    print(f"Ops log:      {total_ops} operations")
    print(f"Trace log:    {total_traces} events")
    print(f"Matched ops:  {matched_ops}")
    print(f"Missing ops:  {missing_ops}")
    print(f"Unused trace events (not matched to any op): {unused_traces}")

    # Breakdown by op_name
    by_op_total: Dict[str, int] = {}
    by_op_missing: Dict[str, int] = {}
    for op in ops:
        by_op_total[op.op_name] = by_op_total.get(op.op_name, 0) + 1
    for idx in missing:
        name = ops[idx].op_name
        by_op_missing[name] = by_op_missing.get(name, 0) + 1

    print("\nPer-op breakdown (missing / total):")
    for name in sorted(by_op_total.keys()):
        tot = by_op_total[name]
        mis = by_op_missing.get(name, 0)
        print(f"  {name:12s}: {mis:3d} / {tot:3d}")

    # Multipart PUT checks
    if mpu_checks:
        total_keys = len(mpu_checks)
        ok_all = sum(1 for c in mpu_checks if c.ok_all)
        print("\nMultipart PUT validation (per key):")
        print(f"  Keys with MPU ops:          {total_keys}")
        print(f"  Keys with full MPU pattern: {ok_all}")
        print(f"  Keys missing components:    {total_keys - ok_all}")


def print_missing_details(ops: List[OpRecord], missing: List[int], max_items: int) -> None:
    if not missing:
        print("\nNo missing operations.")
        return

    print(f"\nFirst {min(max_items, len(missing))} missing operations:")
    for idx in missing[:max_items]:
        op = ops[idx]
        print(
            f"- idx={op.index} time={op.epoch} proto={op.protocol} "
            f"op={op.op_name} method={op.http_method} "
            f"bucket={op.bucket} target={op.target}"
        )


def write_markdown_summary(
    path: str,
    ops: List[OpRecord],
    traces: List[TraceRecord],
    mapping: Dict[int, int],
    missing: List[int],
    mpu_checks: List[MultipartCheck],
) -> None:
    total_ops = len(ops)
    matched_ops = len(mapping)
    missing_ops = len(missing)
    total_traces = len(traces)
    used_traces = len(set(mapping.values()))
    unused_traces = total_traces - used_traces

    by_op_total: Dict[str, int] = {}
    by_op_missing: Dict[str, int] = {}
    for op in ops:
        by_op_total[op.op_name] = by_op_total.get(op.op_name, 0) + 1
    for idx in missing:
        name = ops[idx].op_name
        by_op_missing[name] = by_op_missing.get(name, 0) + 1

    with open(path, "w", encoding="utf-8") as f:
        f.write("# s3slower Correlation Summary\n\n")

        f.write("## Overall\n\n")
        f.write("| Metric | Value |\n")
        f.write("|--------|-------|\n")
        f.write(f"| Ops log operations | {total_ops} |\n")
        f.write(f"| Trace log events | {total_traces} |\n")
        f.write(f"| Matched operations | {matched_ops} |\n")
        f.write(f"| Missing operations | {missing_ops} |\n")
        f.write(f"| Unused trace events | {unused_traces} |\n\n")

        f.write("## Per Operation Type\n\n")
        f.write("| Operation | Total | Missing |\n")
        f.write("|-----------|-------|---------|\n")
        for name in sorted(by_op_total.keys()):
            tot = by_op_total[name]
            mis = by_op_missing.get(name, 0)
            f.write(f"| {name} | {tot} | {mis} |\n")
        f.write("\n")

        if mpu_checks:
            total_keys = len(mpu_checks)
            ok_all = sum(1 for c in mpu_checks if c.ok_all)
            f.write("## Multipart PUT Validation\n\n")
            f.write(f"- Keys with MPU ops: **{total_keys}**\n")
            f.write(f"- Keys with full MPU pattern (CREATE + PUT parts + COMPLETE): **{ok_all}**\n")
            f.write(f"- Keys missing components: **{total_keys - ok_all}**\n\n")

            f.write("| Bucket | Key | Ops | MPU_CREATE | PUT parts | MPU_COMPLETE | Status |\n")
            f.write("|--------|-----|-----|------------|-----------|--------------|--------|\n")
            for c in mpu_checks:
                status = "OK" if c.ok_all else "MISSING"
                f.write(
                    f"| {c.bucket} | {c.key} | {c.op_count} | "
                    f"{c.create_count} | {c.part_put_count} | {c.complete_count} | {status} |\n"
                )
            f.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Correlate aws-s3-test.sh ops log with s3slower --log-file output",
    )
    parser.add_argument("--ops", required=True, help="Path to aws-s3-test.sh OPS_LOG file")
    parser.add_argument("--trace", required=True, help="Path to s3slower --log-file output")
    parser.add_argument(
        "--max-missing",
        type=int,
        default=20,
        help="Maximum number of missing operations to list in detail (default: 20)",
    )
    parser.add_argument(
        "--md-out",
        help="If set, write a Markdown summary to this file",
    )

    args = parser.parse_args()

    ops = parse_ops_log(args.ops)
    traces = parse_trace_log(args.trace)

    if not ops:
        print(f"ERROR: no operations parsed from {args.ops}", file=sys.stderr)
        sys.exit(1)
    if not traces:
        print(f"ERROR: no trace events parsed from {args.trace}", file=sys.stderr)
        sys.exit(1)

    mapping, missing = correlate(ops, traces)
    mpu_checks = build_multipart_checks(ops, traces)
    summarize(ops, traces, mapping, missing, mpu_checks)
    print_missing_details(ops, missing, args.max_missing)

    if args.md_out:
        try:
            write_markdown_summary(args.md_out, ops, traces, mapping, missing, mpu_checks)
            print(f"\nMarkdown summary written to {args.md_out}")
        except OSError as e:
            print(f"ERROR: failed to write markdown summary {args.md_out}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()

