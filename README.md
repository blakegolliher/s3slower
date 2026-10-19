# S3Slower

**See exactly how slow your S3 traffic is — from any client, without changing a single line of code.**

S3Slower is an eBPF-based tracer that measures the latency of every S3 request leaving a Linux host. It hooks into the kernel and TLS libraries to time HTTP request/response pairs as they happen, so you get accurate per-request timing whether the traffic comes from the AWS CLI, Boto3, `s3cmd`, `mc`, `elbencho`, Go clients, or any other tool that speaks S3 over HTTPS.

## Why S3Slower

- **Zero client instrumentation.** No SDK wrappers, no proxies, no code changes. Attach it to a host and it starts measuring.
- **Works with every S3 client.** OpenSSL, GnuTLS, NSS, s2n-tls, and Go's native `crypto/tls` are all supported. If the app makes an HTTPS S3 call, S3Slower sees it.
- **Real request latency, not synthetic probes.** You see what your actual workload experiences, bucket by bucket, operation by operation.
- **Low-cardinality Prometheus metrics by default.** Ships production-safe labels out of the box, with opt-in bucket/endpoint dimensions when you want them.
- **Runs as a systemd service.** Install the RPM, start the service, scrape the metrics endpoint. That's the whole deployment.

## Deploy

**1. Install the RPM.** It sets up the `s3slower` user, drops the config in `/etc/s3slower/`, and enables the systemd unit at boot.

```bash
sudo rpm -ivh s3slower-*.rpm
sudo systemctl start s3slower
```

**2. Verify it's running.**

```bash
sudo systemctl status s3slower
sudo journalctl -u s3slower -f
```

**3. Scrape the metrics endpoint.**

```bash
curl -s http://localhost:9000/metrics | grep s3slower
```

That's it. S3Slower is now tracing every S3 request on the host and exposing metrics on port 9000.

## Configure

Edit `/etc/s3slower/s3slower.yaml`. `min_latency_ms` and `debug` are hot-reloaded on save; everything else needs `sudo systemctl restart s3slower`.

```yaml
min_latency_ms: 0             # Only capture requests slower than this
prometheus:
  prom_exporter_host: "::"    # Listen on all interfaces
  prom_exporter_port: 9000
file:
  samples_path: /var/log/s3slower/s3slower.log
  max_backups: 5
  max_size_mb: 100
```

## Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `s3slower_requests_total` | Counter | Total S3 requests |
| `s3slower_request_errors_total` | Counter | HTTP 4xx/5xx errors |
| `s3slower_request_duration_ms` | Histogram | Latency distribution (ms), buckets from 0.25 ms to 60 s |
| `s3slower_request_bytes_total` | Counter | Upload payload bytes (request bodies) |
| `s3slower_response_bytes_total` | Counter | Download payload bytes (response bodies) |
| `s3slower_response_status_total` | Counter | Responses by HTTP status code and `s3_operation` |
| `s3slower_events_dropped_total` | Counter | Events dropped before export (`reason=perf_lost` for kernel-ring overflow, `channel_full` for userspace back-pressure) |

**Labels.** The always-on core is `comm` and `s3_operation`. `comm` is the client: `awscli`, `boto3`, `elbencho`, `warp`, `mc` or `s3cmd` for recognized tools, otherwise the process name (`java`, `s5cmd`, ...). The scrape-injected `instance` label identifies the host. Two more labels are opt-in because they can explode cardinality on multi-tenant workloads:

```yaml
metrics:
  labels:
    - bucket     # One series per (bucket × comm × operation)
    - endpoint   # One series per S3 endpoint address
```

Enable them only if your Prometheus can handle the cardinality of your bucket count. Dashboards that previously used a `hostname` label should switch to `instance`.

**Operations.** `s3_operation` is one of:

| Data | Multipart | Metadata | Bucket |
|------|-----------|----------|--------|
| `GET_OBJECT`, `GET_OBJECT_RANGE`, `PUT_OBJECT`, `COPY_OBJECT` | `MPU_CREATE`, `MPU_PART`, `MPU_COMPLETE`, `MPU_ABORT`, `MPU_LIST`, `MPU_LIST_PARTS` | `HEAD_OBJECT`, `LIST_PREFIX`, `LIST_OBJECTS`, `LIST_BUCKETS`, `DELETE_OBJECT`, `DELETE_OBJECTS` (batch) | `CREATE_BUCKET`, `DELETE_BUCKET`, `HEAD_BUCKET`, `BUCKET_CONFIG` |

Go clients (`mc`, `s5cmd`, `rclone`, SDK-based services) are traced over TLS through their built-in `crypto/tls`, including stripped release binaries; s3slower attaches when a Go binary starts, so the very first requests of the first run of a new binary can be missed.

A GET with a `Range` header (or a 206 response) is `GET_OBJECT_RANGE`. Operation detection assumes path-style requests (`/bucket/key`), which the AWS CLI and boto3 use for custom endpoints.

**What latency means.** For GETs, latency is time to first byte: from the request leaving the client to the first bytes of the response. For PUTs and multipart parts it runs from the request head to the response, so it includes uploading the body. Byte counters count payload (bodies), not HTTP headers. Two approximations: responses sent with chunked encoding count only the body bytes that arrive with the response head, and a PUT/POST whose request head is larger than the 2 KB capture with no visible Content-Length reports the size of the write that carried the head.

## Grafana Dashboard and Demo

`make monitoring-up` starts Prometheus and Grafana (podman-compose) with the S3Slower dashboard provisioned at `http://<host>:3000/d/s3slower-main`: headline tiles, request mix and throughput by operation, data-path and metadata latency, a latency heatmap, a per-operation summary table, per-client views, HTTP status and errors, and tracer health.

[`demo/`](demo/README.md) has AI-pipeline workloads for the AWS CLI and boto3 (shard PUTs, checkpoint multipart uploads, ranged reads, LIST, HEAD, batch deletes), a reconcile script that proves every request was captured, and `demo/run_mixed_demo.sh`, which keeps eight different clients (boto3, AWS CLI, elbencho, s5cmd, mc, rclone, curl and a random-mix loader) running against a bucket for open-ended exploration.

## Ad-hoc Usage

You can also run `s3slower` directly against a live workload without the service:

```bash
# Trace all S3 traffic, print a live table
sudo s3slower run

# Report only specific processes (names or client labels), slow requests only
sudo s3slower run --watch python3,aws --min-latency 100

# Attach to a single running process
sudo s3slower attach --pid 12345
```

Sample output (one line per request; ranged reads show the byte range):

```
TIME         PROC       OP       STAT      BYTES   LAT(ms) BUCKET               ENDPOINT               KEY
----------------------------------------------------------------------------------------------------------------------------------
21:16:11.293 boto3      PUT       200    1048576     59.99 s3action             main.selab-var204.sel~ s3slower-demo/table/epoch-0/data/shard-00000.tar
21:16:11.569 boto3      MPU_PART  200    8388608     30.31 s3action             main.selab-var204.sel~ s3slower-demo/table/epoch-0/ckpt/step-000000.pt
21:16:11.660 boto3      LIST_PFX  200          0      2.98 s3action             main.selab-var204.sel~ s3slower-demo/table/epoch-0/data/*
21:16:11.673 boto3      GET_RNG   206      65536      2.32 s3action             main.selab-var204.sel~ s3slower-demo/table/epoch-0/data/shard-00013.tar [bytes=42450-107985]
21:16:11.879 boto3      DEL_BULK  200       1604     19.89 s3action             main.selab-var204.sel~
```

`--output top` replaces the scrolling list with a summary redrawn every second (last 5 seconds):

```
s3slower top  21:17:09  (last 5s)   77.2 req/s   read 38.5MB/s   write 57.5MB/s   errors 0.3%

OPERATION             REQ/S     READ/S    WRITE/S  AVG SIZE    P50 ms    P99 ms    MAX ms   ERR%     TOTAL
GET_OBJECT_RANGE       32.6     28.2MB         0B   865.3kB      3.65     13.63     15.74    0.0      1112
PUT_OBJECT             29.2         0B     30.6MB     1.0MB     81.26    122.91    130.17    0.0       900
GET_OBJECT              9.8     10.3MB         0B     1.0MB      5.27     14.78     14.78    0.0       449
MPU_PART                3.2         0B     26.8MB     8.4MB    405.40    449.42    449.42    0.0        99
HEAD_OBJECT             0.6         0B         0B        0B      1.56      2.18      2.18   33.3       174

CLIENT                REQ/S     READ/S    WRITE/S  AVG SIZE    P50 ms    P99 ms    MAX ms   ERR%
boto3                  73.2     11.6MB     57.5MB   944.0kB      8.18    433.51    449.42    0.0
awscli                  4.0     26.8MB         0B     6.7MB      4.15     15.74     15.74    5.0
```

Output formats: `--output table` (default), `top`, `simple`, `json`.

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-C, --config` | Config file path | - |
| `-T, --targets` | Targets file (hot-reloaded) | - |
| `--prometheus` | Enable Prometheus exporter | false |
| `-p, --port` | Prometheus port | 9000 |
| `--min-latency` | Min latency (ms) to report | 0 |
| `--watch` | Only report these process names or client labels (e.g. `python3,aws,boto3`) | - |
| `--mode` | Probe mode: auto, http, openssl, gnutls, nss, s2n, gotls | auto |
| `--output` | Output format: table, top, simple, json | table |
| `--log-dir` | Log directory | /var/log/s3slower |
| `--no-log` | Disable file logging | false |
| `--perf-buffer-kb` | Per-CPU perf ring size; raise if `s3slower_events_dropped_total{reason="perf_lost"}` grows | 256 |
| `--debug` | Debug output | false |

## Requirements

- Linux kernel 4.4+ with eBPF support
- Root privileges (eBPF and uprobe attachment)

## Build from Source

```bash
make build      # Go 1.24+; uses the checked-in BPF object
make test
make rpm        # or: make deb
```

After changing `internal/ebpf/bpf/s3slower.c`, regenerate the BPF object with `make generate` (needs `clang`, `bpftool`, and kernel headers that ship libbpf: `kernel-devel` on RHEL-family, `linux-headers-$(uname -r)` on Debian/Ubuntu; override the location with `KERNEL_SRC=...`).
