# S3Slower demo kit

Generate an AI-pipeline-shaped S3 workload with the AWS CLI and boto3, and
watch every request in the s3slower terminal view and the Grafana dashboard.

| File | What it does |
|------|--------------|
| `ai_pipeline_workload.py` | boto3 workload: shard PUTs, checkpoint multipart uploads, server-side copy, paginated LIST, full and ranged GETs, checkpoint restore, HEADs (including 404 misses), batch and single deletes, an aborted MPU |
| `awscli_workload.sh` | The same pipeline with `aws s3 sync/cp/ls/rm` and `aws s3api` |
| `reconcile.py` | Proves capture accuracy: compares every request the boto3 workload sent with what s3slower recorded |
| `mixed_workload.py` | boto3 workers issuing weighted-random operations; the mix shifts every 1-3 minutes (ingest, training, checkpoint, evaluation, compaction) and the load drifts |
| `cli_clients_workload.sh` | Traffic from other client binaries, one per lane: `s5cmd`, `mc`, `rclone`, `curl` |
| `elbencho_bursts.sh` | Alternating small-object IOPS and large-object throughput bursts every 3-7 minutes |
| `run_mixed_demo.sh` | Starts the tracer plus all of the above as background lanes; `start`, `status`, `stop` |

All workloads write only under their key prefix and delete what they create.

## Leave a mixed workload running

To explore the dashboard with many clients and a constantly changing mix:

```bash
export S3_ENDPOINT=https://s3.example.com S3_BUCKET=my-bucket
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
export NO_VERIFY_SSL=1                       # self-signed certificate
export HTTP_ENDPOINT=http://s3.example.com   # for elbencho, which cannot skip TLS verification

make build monitoring-up
demo/run_mixed_demo.sh start     # tracer + 8 lanes, detached; auto-stops after MAX_HOURS (12)
demo/run_mixed_demo.sh status
demo/run_mixed_demo.sh stop      # stops everything and deletes the demo objects
```

The dashboard then shows eight clients: `train-loader` (the random mix, run
under its own process name), `boto3` (pipeline epochs with pauses), `awscli`,
`elbencho`, `s5cmd`, `mc`, `rclone` and `curl`. Lanes for tools that are not
installed are skipped; `s5cmd`, `mc` and `rclone` are single static binaries
from their GitHub releases and can live in `build/demo-bin/<tool>/<tool>`.
Logs, pid files and the tracer's rotating request log go to `build/demo-run/`.

## 1. Start s3slower

```bash
make build
sudo build/s3slower run --prometheus
```

The terminal shows one line per request; Prometheus metrics are served on
`:9000`. If s3slower is installed as a service, it is already exporting
metrics; run a second instance with `--no-log -p 9001` for the terminal view,
or use `journalctl -u s3slower -f`.

## 2. Start Prometheus and Grafana

```bash
make monitoring-up        # podman-compose; Prometheus :9090, Grafana :3000
```

Open `http://<host>:3000/d/s3slower-main` (anonymous viewer access is on;
admin/admin to edit). Set the time range to the last 15 minutes.

## 3. Run the workloads

```bash
export S3_ENDPOINT=https://s3.example.com S3_BUCKET=my-bucket
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...   # or AWS_PROFILE=...

python3 demo/ai_pipeline_workload.py --no-verify-ssl     # loops until Ctrl-C
NO_VERIFY_SSL=1 demo/awscli_workload.sh                  # loops until Ctrl-C
```

Drop `--no-verify-ssl` / `NO_VERIFY_SSL=1` when the endpoint has a trusted
certificate. Plain `http://` endpoints work too. Useful knobs:
`--threads`, `--shards`, `--shard-kib`, `--ckpt-mib`, `--reads`,
`--range-kib`, `--pause` (see `--help`).

## What to point out

**Overview tiles.** Requests/s, read and write throughput, GET time to first
byte (p50/p99), PUT/part p99, error rate, and dropped events. "Events dropped
= 0" means every request on the host was measured.

**Workload mix.** The pipeline phases are visible as they happen: a burst of
PUTs (ingest), MPU parts (checkpoint), GET range (data loading), HEAD and
DELETE. Read and write throughput are split by operation.

**Latency.** Data-path latency shows p50 (dashed) and p99 per operation on a
log scale; metadata operations have their own panel. The heatmap shows the
whole latency distribution, so tail outliers stand out.

**Per-operation table.** Every operation individually, with request count,
rate, average payload (ranged reads ≈ 64 KiB, shards 1 MiB, parts 8 MiB),
throughput, p50/p99 and errors over the selected range.

**Clients.** boto3 and the AWS CLI appear side by side; any other process is
shown by name.

**Errors & status.** The workloads' deliberate misses appear as 404s on
HEAD_OBJECT and GET_OBJECT, which is how missing-checkpoint checks look in
production. The mixed workload sends about 3% of its HEADs and 1% of its
full GETs to absent keys (`--head-miss`, `--get-miss`); there are no other
errors unless the endpoint returns them.

### Terminal view

```bash
sudo build/s3slower run --output top                 # live per-operation summary
sudo build/s3slower run --watch python3              # only the boto3 workload
sudo build/s3slower run --watch aws --min-latency 50 # slow aws cli calls only
sudo build/s3slower run --output json | jq .         # full detail per request
```

Ranged reads show as `GET_RNG` with the byte range after the key.

## Prove the numbers

```bash
sudo build/s3slower run --output json --no-log > capture.jsonl &
python3 demo/ai_pipeline_workload.py --no-verify-ssl --epochs 1 --truth truth.jsonl
sudo pkill -INT -x s3slower
python3 demo/reconcile.py truth.jsonl capture.jsonl
```

`reconcile.py` prints sent vs captured counts per operation, unmatched
requests, payload-size mismatches and latency percentiles, and ends with
`RESULT: PASS` when every request was captured and classified.

## How to read the latency numbers

- **GET** latency is time to first byte: from the request leaving the client
  to the first bytes of the response arriving.
- **PUT and MPU part** latency runs from the request head to the response,
  so it includes uploading the body.
- Responses sent with chunked encoding (for example ListObjects on some
  servers) count only the body bytes that arrive with the response head.

## Clean up

```bash
make monitoring-down
```

Both workloads remove everything under their prefix when interrupted with
Ctrl-C.
