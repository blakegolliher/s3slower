#!/usr/bin/env python3
"""Validate s3slower capture against workload logs.

Compares workload JSONL logs against s3slower JSON capture output to verify
100% capture rate and field accuracy.
"""

import argparse
import json
import sys
from datetime import datetime
from urllib.parse import quote, unquote


def parse_timestamp(ts_str):
    """Parse ISO timestamp, tolerating various formats."""
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S.%f+00:00",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S+00:00",
    ]:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    # Try RFC3339Nano (Go format with timezone)
    try:
        # Handle nanosecond precision by truncating to microseconds
        if "." in ts_str:
            base, frac = ts_str.split(".", 1)
            # Strip timezone suffix
            tz_suffix = ""
            for tz in ["Z", "+00:00", "-00:00"]:
                if frac.endswith(tz):
                    frac = frac[: -len(tz)]
                    tz_suffix = tz
                    break
            # Truncate to 6 decimal places (microseconds)
            frac = frac[:6].ljust(6, "0")
            return datetime.strptime(f"{base}.{frac}Z", "%Y-%m-%dT%H:%M:%S.%fZ")
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass
    raise ValueError(f"Cannot parse timestamp: {ts_str}")


def load_jsonl(path, skip_errors=False):
    """Load JSONL file, optionally skipping non-JSON lines."""
    entries = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                if not skip_errors:
                    print(f"Warning: skipping non-JSON line {lineno} in {path}", file=sys.stderr)
    return entries


def match_workload_to_capture(workload_entries, capture_entries):
    """Match workload operations to capture events.

    Returns list of (workload_entry, capture_entry_or_None, match_score) tuples.
    """
    # Build PID whitelist from workload
    workload_pids = {e["pid"] for e in workload_entries}

    # Filter captures to only whitelisted PIDs
    relevant_captures = [c for c in capture_entries if c.get("pid") in workload_pids]

    # Track which capture entries have been used
    used_capture_indices = set()
    matches = []

    for wl in workload_entries:
        best_idx = None
        best_score = -1

        wl_pid = wl["pid"]
        wl_method = wl["method"]
        wl_op = wl["operation"]
        wl_bucket = wl["bucket"]
        wl_key = wl.get("key", "")
        wl_ts = parse_timestamp(wl["timestamp"])

        for i, cap in enumerate(relevant_captures):
            if i in used_capture_indices:
                continue

            # Must match PID and method
            if cap.get("pid") != wl_pid:
                continue
            if cap.get("method") != wl_method:
                continue

            score = 0

            # Operation match
            if cap.get("operation") == wl_op:
                score += 10

            # Bucket match
            if cap.get("bucket") == wl_bucket:
                score += 5

            # Key in path
            cap_path = cap.get("path", "")
            if wl_key and wl_key in cap_path:
                score += 3

            # Timestamp proximity (<30s)
            try:
                cap_ts = parse_timestamp(cap["timestamp"])
                delta = abs((cap_ts - wl_ts).total_seconds())
                if delta < 30:
                    score += 2
            except (KeyError, ValueError):
                pass

            if score > best_score:
                best_score = score
                best_idx = i

        if best_idx is not None and best_score >= 15:
            used_capture_indices.add(best_idx)
            matches.append((wl, relevant_captures[best_idx], best_score))
        else:
            matches.append((wl, None, best_score))

    # Collect unmatched captures
    extra_captures = [
        relevant_captures[i]
        for i in range(len(relevant_captures))
        if i not in used_capture_indices
    ]

    return matches, extra_captures


def verify_match(wl, cap):
    """Verify field accuracy for a matched pair. Returns dict of check results."""
    checks = {}

    # PID exact match
    checks["pid_match"] = cap.get("pid") == wl["pid"]

    # Method exact match
    checks["method_match"] = cap.get("method") == wl["method"]

    # Operation exact match
    checks["operation_match"] = cap.get("operation") == wl["operation"]

    # Bucket exact match
    checks["bucket_match"] = cap.get("bucket") == wl["bucket"]

    # Key appears in path (check both raw and URL-encoded forms)
    wl_key = wl.get("key", "")
    if wl_key:
        cap_path = cap.get("path", "")
        # Check raw key, URL-encoded key, and URL-decoded path
        checks["key_in_path"] = (
            wl_key in cap_path
            or quote(wl_key, safe="") in cap_path
            or wl_key in unquote(cap_path)
        )
    else:
        checks["key_in_path"] = True  # No key to check

    # Latency > 0
    checks["latency_positive"] = cap.get("latency_ms", 0) > 0

    # Status code 2xx (when present)
    status = cap.get("status_code", 0)
    if status > 0:
        checks["status_2xx"] = 200 <= status < 300
    else:
        checks["status_2xx"] = True  # Not present, skip

    # For PUT: request_size > 0 (only when workload logged a non-zero size)
    if wl["method"] == "PUT" and wl.get("size", 0) > 0:
        checks["put_has_request_size"] = cap.get("request_size", 0) > 0
    else:
        checks["put_has_request_size"] = True

    # For GET: response_size > 0
    if wl["method"] == "GET" and wl["operation"] == "GET_OBJECT":
        checks["get_has_response_size"] = cap.get("response_size", 0) > 0
    else:
        checks["get_has_response_size"] = True

    return checks


def main():
    parser = argparse.ArgumentParser(description="Validate s3slower capture")
    parser.add_argument("--capture", required=True, help="s3slower capture JSONL")
    parser.add_argument("--workload", nargs="+", required=True, help="Workload JSONL file(s)")
    parser.add_argument("--output", required=True, help="Validation report JSON output")
    args = parser.parse_args()

    # Step 1: Load workload files
    all_workload = []
    for wl_path in args.workload:
        entries = load_jsonl(wl_path)
        all_workload.extend(entries)
        print(f"Loaded {len(entries)} workload entries from {wl_path}", file=sys.stderr)

    # Filter to successful operations only
    successful_workload = [e for e in all_workload if e.get("exit_code", 0) == 0]
    print(f"Total workload operations: {len(all_workload)} ({len(successful_workload)} successful)",
          file=sys.stderr)

    # Step 2: Load capture file (skip non-JSON lines for robustness)
    capture_entries = load_jsonl(args.capture, skip_errors=True)
    print(f"Loaded {len(capture_entries)} capture entries from {args.capture}", file=sys.stderr)

    # Step 3-5: Match workload to capture
    matches, extra_captures = match_workload_to_capture(successful_workload, capture_entries)

    # Step 6: Verify matched pairs
    matched_count = 0
    unmatched = []
    all_checks_pass = True
    per_operation = []

    for wl, cap, score in matches:
        op_result = {
            "seq": wl.get("seq"),
            "client": wl.get("client"),
            "operation": wl["operation"],
            "method": wl["method"],
            "bucket": wl["bucket"],
            "key": wl.get("key", ""),
        }

        if cap is not None:
            matched_count += 1
            checks = verify_match(wl, cap)
            op_result["matched"] = True
            op_result["match_score"] = score
            op_result["checks"] = checks
            op_result["capture_pid"] = cap.get("pid")
            op_result["capture_operation"] = cap.get("operation")
            op_result["capture_latency_ms"] = cap.get("latency_ms")

            if not all(checks.values()):
                all_checks_pass = False
                failed = [k for k, v in checks.items() if not v]
                op_result["failed_checks"] = failed
                print(f"  FAIL: seq={wl.get('seq')} {wl['operation']} - {failed}", file=sys.stderr)
        else:
            op_result["matched"] = False
            op_result["match_score"] = score
            unmatched.append(op_result)
            print(f"  MISS: seq={wl.get('seq')} {wl['operation']} pid={wl['pid']} "
                  f"{wl['method']} {wl.get('key', '')}", file=sys.stderr)

        per_operation.append(op_result)

    # Step 7: Generate report
    total_expected = len(successful_workload)
    capture_rate = (matched_count / total_expected * 100) if total_expected > 0 else 0
    passed = matched_count == total_expected and all_checks_pass

    report = {
        "summary": {
            "pass": passed,
            "total_expected": total_expected,
            "total_matched": matched_count,
            "capture_rate_pct": round(capture_rate, 1),
            "all_checks_pass": all_checks_pass,
            "extra_captures": len(extra_captures),
            "total_capture_entries": len(capture_entries),
        },
        "per_operation": per_operation,
        "unmatched_workload": unmatched,
        "extra_captures_sample": extra_captures[:10],  # First 10 only
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    status = "PASS" if passed else "FAIL"
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"{status}: {matched_count}/{total_expected} operations captured "
          f"({capture_rate:.0f}%)", file=sys.stderr)
    if all_checks_pass:
        print("All accuracy checks passed", file=sys.stderr)
    else:
        failed_ops = [o for o in per_operation if o.get("failed_checks")]
        print(f"Accuracy check failures: {len(failed_ops)} operations", file=sys.stderr)
    if extra_captures:
        print(f"Extra captures (not in workload): {len(extra_captures)}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    # Also print to stdout for easy piping
    print(f"{status}: {matched_count}/{total_expected} operations captured "
          f"({capture_rate:.0f}%), all accuracy checks {'passed' if all_checks_pass else 'FAILED'}")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
