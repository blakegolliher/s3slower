#!/usr/bin/env python3
"""Reconcile a workload's request log against an s3slower JSON capture.

  sudo s3slower run --output json --no-log > capture.jsonl &
  python3 demo/ai_pipeline_workload.py ... --epochs 1 --truth truth.jsonl
  python3 demo/reconcile.py truth.jsonl capture.jsonl

Prints sent vs captured counts per operation, unmatched requests, payload
size mismatches, and captured latency percentiles. Exits non-zero if any
request was missed or misclassified.
"""
import argparse
import json
import sys
from collections import Counter, defaultdict


def load(path):
    out = []
    with open(path) as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def range_len(spec):
    """Byte count requested by a Range header value like bytes=0-99 or
    bytes=-8192, or None for an open-ended range (bytes=100-)."""
    r = spec.split("=", 1)[1]
    if r.startswith("-"):
        return int(r[1:])
    lo, hi = r.split("-")
    return int(hi) - int(lo) + 1 if hi else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("truth")
    ap.add_argument("capture")
    ap.add_argument("--client", default="boto3",
                    help="client label of the workload in the capture (default boto3)")
    args = ap.parse_args()

    truth = load(args.truth)
    cap = [e for e in load(args.capture) if e.get("client_type") == args.client]

    sent = Counter(t["op"] for t in truth)
    got = Counter(e.get("operation", "") for e in cap)
    print(f"{'operation':<20}{'sent':>8}{'captured':>10}")
    for op in sorted(set(sent) | set(got)):
        mark = "" if sent[op] == got[op] else "   <-- mismatch"
        print(f"{op:<20}{sent[op]:>8}{got[op]:>10}{mark}")
    print(f"{'TOTAL':<20}{len(truth):>8}{len(cap):>10}")

    # Match requests by (method, path, op); each truth entry consumes one capture.
    key = lambda m, p, o: (m, p, o)
    pending = Counter(key(t["method"], t["path"], t["op"]) for t in truth)
    captured = Counter(key(e["method"], e["path"], e.get("operation", "")) for e in cap)
    missing, extra = pending - captured, captured - pending
    print(f"\nunmatched sent requests: {sum(missing.values())}")
    for (m, p, o), n in list(missing.items())[:10]:
        print(f"   {n}x {o:<16} {m} {p[:90]}")
    print(f"unmatched captured events: {sum(extra.values())}")
    for (m, p, o), n in list(extra.items())[:10]:
        print(f"   {n}x {o:<16} {m} {p[:90]}")

    # Payload sizes: uploads by Content-Length, ranged reads by range length.
    by_path = defaultdict(list)
    for t in truth:
        by_path[(t["method"], t["path"])].append(t)
    bad = defaultdict(int)
    checked = 0
    for e in cap:
        ts = by_path.get((e["method"], e["path"]), [])
        op = e.get("operation")
        if op in ("PUT_OBJECT", "MPU_PART") and ts:
            checked += 1
            if e["request_size"] not in {t["content_length"] for t in ts}:
                bad[op + " request_size"] += 1
        elif op == "GET_OBJECT_RANGE" and e.get("range") and range_len(e["range"]):
            checked += 1
            if e["response_size"] > range_len(e["range"]):
                bad[op + " response_size"] += 1
    print(f"\npayload sizes checked: {checked}, mismatches: {dict(bad) or 0}")

    statuses = Counter(e.get("status_code", 0) for e in cap)
    print("status codes:", dict(sorted(statuses.items())))

    lat = defaultdict(list)
    for e in cap:
        lat[e.get("operation", "")].append(e["latency_ms"])
    print("\ncaptured latency (ms):")
    print(f"   {'operation':<18}{'n':>6}{'p50':>10}{'p99':>10}{'max':>10}")
    for op, v in sorted(lat.items()):
        v.sort()
        p = lambda q: v[min(len(v) - 1, int(len(v) * q))]
        print(f"   {op:<18}{len(v):>6}{p(0.5):>10.2f}{p(0.99):>10.2f}{v[-1]:>10.2f}")

    ok = not missing and not extra and not bad and statuses.get(0, 0) == 0
    print("\nRESULT:", "PASS - every request captured and classified" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
