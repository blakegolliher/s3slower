# S3Slower Long-Running Stress Test

Runs 3 concurrent S3 client workloads (awscli, boto3, elbencho) against an S3
endpoint for extended periods while s3slower captures latency metrics.

## Quick Start

```bash
# From the repo root:
make test-stress
```

Or manually:

```bash
sudo -E bash -c '
  export AWS_ACCESS_KEY_ID=<key>
  export AWS_SECRET_ACCESS_KEY=<secret>
  export S3_ENDPOINT=http://your-s3-endpoint
  export S3_NO_VERIFY_SSL=true
  export S3SLOWER_BIN=build/s3slower
  validation_test/stress/run_stress_test.sh
'
```

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `S3_ENDPOINT` | (required) | S3 endpoint URL |
| `AWS_ACCESS_KEY_ID` | (required) | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | (required) | AWS secret key |
| `S3SLOWER_BIN` | `build/s3slower` | Path to s3slower binary |
| `S3_NO_VERIFY_SSL` | `false` | Skip SSL verification |
| `STRESS_DURATION_HOURS` | `24` | How long to run |
| `STRESS_MAX_DATA_GB` | `250` | Max data per bucket before GC |
| `STRESS_CYCLE_MIN_S` | `30` | Min seconds between operation batches |
| `STRESS_CYCLE_MAX_S` | `120` | Max seconds between operation batches |
| `NO_S3SLOWER` | `false` | Skip launching s3slower (if already running) |

## Operation Mix

Each workload uses the same weighted distribution:

| Operation | Weight | Details |
|-----------|--------|---------|
| PUT (single) | 25% | Random: 1KB, 4KB, 64KB, 1MB, 16MB, 64MB |
| PUT (multipart) | 10% | 5MB parts, 35-70MB total |
| GET (full) | 20% | Random existing object |
| GET (ranged) | 10% | Random byte range |
| HEAD | 10% | Random existing object |
| LIST | 10% | With/without prefix |
| DELETE | 10% | Random existing object |
| COPY | 5% | Random existing to new key |

## Architecture

```
run_stress_test.sh (orchestrator)
├── s3slower --prometheus --port 9000
├── stress_workload_awscli.sh    → bucket: s3slower-e2e-awscli
├── stress_workload_boto3.py     → bucket: s3slower-e2e-boto3
└── stress_workload_elbencho.sh  → bucket: s3slower-e2e-elbencho
```

Each workload maintains its own object registry and garbage collector.
The orchestrator monitors worker health every 60s and restarts crashed workers.

## Output

All output goes to a temp directory (printed at startup):

```
/tmp/s3slower-stress-XXXXX/
├── s3slower_capture.jsonl    # s3slower JSON output
├── s3slower.stderr           # s3slower stderr
├── workload_awscli.jsonl     # awscli operation log
├── workload_boto3.jsonl      # boto3 operation log
├── workload_elbencho.jsonl   # elbencho operation log
├── awscli.stderr             # awscli stderr
├── boto3.stderr              # boto3 stderr
├── elbencho.stderr           # elbencho stderr
└── stress_status.log         # periodic status heartbeats
```

## With Monitoring

Run alongside Prometheus + Grafana for real-time dashboards:

```bash
make monitoring-up    # Start Prometheus + Grafana
make test-stress      # Start stress test (s3slower exposes :9000/metrics)
# Open http://localhost:3000 for Grafana
```
