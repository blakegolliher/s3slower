#!/usr/bin/env python3
"""Validate s3slower Prometheus metrics against capture and workload logs.

Scrapes (or reads) the Prometheus /metrics endpoint and verifies:
1. Every captured operation appears in Prometheus metrics with matching counts
2. Duration histograms have observations for each operation type
3. Byte counters are non-zero where expected (PUT request bytes, GET response bytes)
4. Workload operation counts match what Prometheus recorded
"""

import argparse
import json
import re
import sys
from collections import defaultdict


def parse_prometheus_text(text):
    """Parse Prometheus text exposition format.

    Returns dict: metric_name -> list of (labels_dict, value)
    """
    metrics = defaultdict(list)
    for line in text.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Parse: metric_name{label1="val1",label2="val2"} value
        # or:    metric_name value  (no labels)
        match = re.match(r'^(\w+)(?:\{([^}]*)\})?\s+(.+)$', line)
        if not match:
            continue

        name = match.group(1)
        labels_str = match.group(2) or ""
        value_str = match.group(3)

        # Parse labels
        labels = {}
        if labels_str:
            for label_match in re.finditer(r'(\w+)="([^"]*)"', labels_str):
                labels[label_match.group(1)] = label_match.group(2)

        # Parse value
        try:
            value = float(value_str)
        except ValueError:
            continue

        metrics[name].append((labels, value))

    return metrics


def load_jsonl(path, skip_errors=False):
    """Load JSONL file."""
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
                    print(f"Warning: skipping non-JSON line {lineno} in {path}",
                          file=sys.stderr)
    return entries


def main():
    parser = argparse.ArgumentParser(
        description="Validate s3slower Prometheus metrics")
    parser.add_argument("--metrics-file", required=True,
                        help="Scraped Prometheus metrics text file")
    parser.add_argument("--capture", required=True,
                        help="s3slower capture JSONL")
    parser.add_argument("--workload", nargs="+", required=True,
                        help="Workload JSONL file(s)")
    parser.add_argument("--output", required=True,
                        help="Validation report JSON output")
    args = parser.parse_args()

    # Load capture entries
    capture_entries = load_jsonl(args.capture, skip_errors=True)
    print(f"Loaded {len(capture_entries)} capture entries", file=sys.stderr)

    # Load workload entries
    all_workload = []
    for wl_path in args.workload:
        entries = load_jsonl(wl_path)
        all_workload.extend(entries)
    successful_workload = [
        e for e in all_workload if e.get("exit_code", 0) == 0
    ]
    print(f"Loaded {len(successful_workload)} successful workload operations",
          file=sys.stderr)

    # Get PIDs from workload
    workload_pids = {e["pid"] for e in successful_workload}

    # Load metrics file
    with open(args.metrics_file) as f:
        metrics_text = f.read()

    if not metrics_text.strip():
        print("ERROR: Prometheus metrics file is empty", file=sys.stderr)
        report = {"summary": {"pass": False, "error": "empty metrics file"}}
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        return 1

    prom_metrics = parse_prometheus_text(metrics_text)
    total_metric_series = sum(len(v) for v in prom_metrics.values())
    print(f"Parsed {len(prom_metrics)} metric families, "
          f"{total_metric_series} series", file=sys.stderr)

    all_pass = True

    # ---------------------------------------------------------------
    # Check 1: Capture-to-Prometheus request count matching
    # ---------------------------------------------------------------
    print("\n--- Check 1: Capture vs Prometheus request counts ---",
          file=sys.stderr)

    # Group captures by (pid, operation, method) - only for workload PIDs
    capture_counts = defaultdict(int)
    for cap in capture_entries:
        pid = cap.get("pid")
        if pid not in workload_pids:
            continue
        key = (str(pid), cap.get("operation", ""), cap.get("method", ""))
        capture_counts[key] += 1

    # Group prometheus requests_total by (pid, s3_operation, method)
    prom_counts = {}
    for labels, value in prom_metrics.get("s3slower_requests_total", []):
        key = (labels.get("pid", ""),
               labels.get("s3_operation", ""),
               labels.get("method", ""))
        prom_counts[key] = value

    count_checks = []
    for key in sorted(set(capture_counts) | set(prom_counts)):
        pid, op, method = key
        # Skip PIDs not in workload
        if pid.isdigit() and int(pid) not in workload_pids:
            continue

        cap_count = capture_counts.get(key, 0)
        pm_count = prom_counts.get(key, 0)
        matched = abs(pm_count - cap_count) < 0.5  # float comparison

        if not matched:
            all_pass = False

        count_checks.append({
            "pid": pid,
            "operation": op,
            "method": method,
            "capture_count": cap_count,
            "prometheus_count": pm_count,
            "matched": matched,
        })

        status = "OK" if matched else "MISMATCH"
        print(f"  {status}: pid={pid} {method} {op}: "
              f"capture={cap_count} prom={pm_count}", file=sys.stderr)

    # ---------------------------------------------------------------
    # Check 2: Duration histogram has observations
    # ---------------------------------------------------------------
    print("\n--- Check 2: Duration histograms ---", file=sys.stderr)

    # Group by (s3_operation, method) from workload
    workload_ops = set()
    for wl in successful_workload:
        workload_ops.add((wl["operation"], wl["method"]))

    prom_histogram_counts = defaultdict(float)
    for labels, value in prom_metrics.get(
            "s3slower_request_duration_ms_count", []):
        pid_str = labels.get("pid", "")
        if pid_str.isdigit() and int(pid_str) in workload_pids:
            op_key = (labels.get("s3_operation", ""),
                      labels.get("method", ""))
            prom_histogram_counts[op_key] += value

    histogram_checks = []
    for op, method in sorted(workload_ops):
        count = prom_histogram_counts.get((op, method), 0)
        has_observations = count > 0
        if not has_observations:
            all_pass = False

        histogram_checks.append({
            "operation": op,
            "method": method,
            "histogram_count": count,
            "has_observations": has_observations,
        })

        status = "OK" if has_observations else "MISSING"
        print(f"  {status}: {method} {op}: "
              f"histogram_count={count}", file=sys.stderr)

    # ---------------------------------------------------------------
    # Check 3: Byte counters
    # ---------------------------------------------------------------
    print("\n--- Check 3: Byte counters ---", file=sys.stderr)

    byte_checks = []

    # Check request bytes for PUTs with non-zero size
    put_workloads = [
        w for w in successful_workload
        if w["method"] == "PUT" and w.get("size", 0) > 0
    ]
    if put_workloads:
        put_pids = {str(w["pid"]) for w in put_workloads}
        total_req_bytes = sum(
            value
            for labels, value
            in prom_metrics.get("s3slower_request_bytes_total", [])
            if labels.get("pid", "") in put_pids
            and labels.get("method") == "PUT"
        )
        has_bytes = total_req_bytes > 0
        if not has_bytes:
            all_pass = False

        byte_checks.append({
            "check": "put_request_bytes",
            "total_bytes": total_req_bytes,
            "passed": has_bytes,
        })
        status = "OK" if has_bytes else "MISSING"
        print(f"  {status}: PUT request bytes: {total_req_bytes}",
              file=sys.stderr)

    # Check response bytes for GETs
    get_workloads = [
        w for w in successful_workload if w["operation"] == "GET_OBJECT"
    ]
    if get_workloads:
        get_pids = {str(w["pid"]) for w in get_workloads}
        total_resp_bytes = sum(
            value
            for labels, value
            in prom_metrics.get("s3slower_response_bytes_total", [])
            if labels.get("pid", "") in get_pids
            and labels.get("s3_operation") == "GET_OBJECT"
        )
        has_bytes = total_resp_bytes > 0
        if not has_bytes:
            all_pass = False

        byte_checks.append({
            "check": "get_response_bytes",
            "total_bytes": total_resp_bytes,
            "passed": has_bytes,
        })
        status = "OK" if has_bytes else "MISSING"
        print(f"  {status}: GET response bytes: {total_resp_bytes}",
              file=sys.stderr)

    # ---------------------------------------------------------------
    # Check 4: Workload-to-Prometheus cross-check (aggregated)
    # ---------------------------------------------------------------
    print("\n--- Check 4: Workload vs Prometheus (aggregated) ---",
          file=sys.stderr)

    workload_op_counts = defaultdict(int)
    for wl in successful_workload:
        key = (wl["operation"], wl["method"])
        workload_op_counts[key] += 1

    prom_op_counts = defaultdict(float)
    for labels, value in prom_metrics.get("s3slower_requests_total", []):
        pid_str = labels.get("pid", "")
        if pid_str.isdigit() and int(pid_str) in workload_pids:
            key = (labels.get("s3_operation", ""),
                   labels.get("method", ""))
            prom_op_counts[key] += value

    workload_vs_prom = []
    for key in sorted(set(workload_op_counts) | set(prom_op_counts)):
        op, method = key
        wl_count = workload_op_counts.get(key, 0)
        pm_count = prom_op_counts.get(key, 0)
        # Prom count should be >= workload count (retries may add extras)
        matched = pm_count >= wl_count
        if not matched:
            all_pass = False

        workload_vs_prom.append({
            "operation": op,
            "method": method,
            "workload_count": wl_count,
            "prometheus_count": pm_count,
            "matched": matched,
        })

        status = "OK" if matched else "MISMATCH"
        print(f"  {status}: {method} {op}: "
              f"workload={wl_count} prom={pm_count}", file=sys.stderr)

    # ---------------------------------------------------------------
    # Generate report
    # ---------------------------------------------------------------
    count_ok = sum(1 for c in count_checks if c["matched"])
    hist_ok = sum(1 for h in histogram_checks if h["has_observations"])
    byte_ok = sum(1 for b in byte_checks if b["passed"])
    wlpm_ok = sum(1 for w in workload_vs_prom if w["matched"])

    report = {
        "summary": {
            "pass": all_pass,
            "total_capture_groups": len(capture_counts),
            "total_prom_groups": len(prom_counts),
            "count_checks": f"{count_ok}/{len(count_checks)} matched",
            "histogram_checks": f"{hist_ok}/{len(histogram_checks)} with observations",
            "byte_checks": f"{byte_ok}/{len(byte_checks)} passed",
            "workload_vs_prom": f"{wlpm_ok}/{len(workload_vs_prom)} matched",
        },
        "request_count_checks": count_checks,
        "histogram_checks": histogram_checks,
        "byte_checks": byte_checks,
        "workload_vs_prometheus": workload_vs_prom,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    status = "PASS" if all_pass else "FAIL"
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Prometheus validation: {status}", file=sys.stderr)
    print(f"  Request count checks: {count_ok}/{len(count_checks)} matched",
          file=sys.stderr)
    print(f"  Histogram checks: {hist_ok}/{len(histogram_checks)} "
          f"with observations", file=sys.stderr)
    print(f"  Byte checks: {byte_ok}/{len(byte_checks)} passed",
          file=sys.stderr)
    print(f"  Workload vs Prometheus: {wlpm_ok}/{len(workload_vs_prom)} "
          f"matched", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    # Also print to stdout
    print(f"Prometheus {status}: counts={count_ok}/{len(count_checks)}, "
          f"histograms={hist_ok}/{len(histogram_checks)}, "
          f"bytes={byte_ok}/{len(byte_checks)}, "
          f"workload={wlpm_ok}/{len(workload_vs_prom)}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
