#!/usr/bin/env bash
# Run the s3slower tracer plus a continuous, randomly varying S3 workload
# for exploring the Grafana dashboard.
#
#   demo/run_mixed_demo.sh start    # tracer + four workload lanes, detached
#   demo/run_mixed_demo.sh status
#   demo/run_mixed_demo.sh stop     # stops everything and deletes demo objects
#
# Lanes (client label on the dashboard):
#   train-loader  demo/mixed_workload.py   weighted-random operations; the mix
#                                          shifts every 1-3 minutes and load drifts
#   boto3         demo/ai_pipeline_workload.py   a training-pipeline epoch, then a pause
#   awscli        demo/awscli_workload.sh  sync/cp/ls/rm loop with pauses
#   elbencho      demo/elbencho_bursts.sh  IOPS and throughput bursts every 3-7 minutes
#   s5cmd, mc, rclone, curl                demo/cli_clients_workload.sh, one lane each
#                                          (lanes for tools that are not installed are skipped)
#
# Environment: S3_ENDPOINT, S3_BUCKET, AWS credentials (env), NO_VERIFY_SSL=1
# for self-signed certificates, HTTP_ENDPOINT (a plain http:// URL for
# elbencho, which cannot skip TLS verification; defaults to S3_ENDPOINT),
# MAX_HOURS (auto-stop, default 12),
# RUN_DIR (logs and pid files, default build/demo-run), S3SLOWER_BIN
# (default build/s3slower; Prometheus metrics on :9000), DEMO_BIN_DIR (where
# s5cmd/mc/rclone live if not on PATH, default build/demo-bin).
set -euo pipefail

cd "$(dirname "$0")/.."
RUN_DIR="${RUN_DIR:-build/demo-run}"
BIN="${S3SLOWER_BIN:-build/s3slower}"
MAX_HOURS="${MAX_HOURS:-12}"
LANES=(mixed pipeline awscli elbencho s5cmd mc rclone curl)

pidfile() { echo "$RUN_DIR/$1.pid"; }
alive() { [[ -f "$(pidfile "$1")" ]] && sudo kill -0 "$(cat "$(pidfile "$1")")" 2>/dev/null; }
# tree PID: PID and all of its descendants.
tree() { local c; echo "$1"; for c in $(ps -o pid= --ppid "$1"); do tree "$c"; done; }

# launch NAME CMD...: run detached in its own session, auto-stopped after
# MAX_HOURS. timeout relays SIGTERM to the command on stop, and SIGKILLs it
# if its cleanup has not finished 5 minutes later.
launch() {
    local name=$1; shift
    setsid nohup timeout -k 5m "${MAX_HOURS}h" "$@" > "$RUN_DIR/$name.log" 2>&1 < /dev/null &
    echo $! > "$(pidfile "$name")"
    echo "  started $name (pid $!, log $RUN_DIR/$name.log)"
}

start() {
    : "${S3_ENDPOINT:?set S3_ENDPOINT}" "${S3_BUCKET:?set S3_BUCKET}"
    for n in tracer "${LANES[@]}"; do
        if alive "$n"; then echo "$n is already running; run '$0 stop' first"; exit 1; fi
    done
    mkdir -p "$RUN_DIR"
    [[ -x "$BIN" ]] || { echo "$BIN not found; run 'make build'"; exit 1; }
    local ssl=() ; [[ "${NO_VERIFY_SSL:-0}" == 1 ]] && ssl=(--no-verify-ssl)

    echo "starting s3slower tracer (Prometheus :9000, request log in $RUN_DIR/s3slower-log)"
    sudo true # authenticate once up front
    sudo setsid nohup timeout -k 1m "${MAX_HOURS}h" "$BIN" run --prometheus --log-dir "$RUN_DIR/s3slower-log" \
        --log-max-size 50 > /dev/null 2> "$RUN_DIR/tracer.log" < /dev/null &
    echo $! > "$(pidfile tracer)"
    sleep 5 # let probes attach before traffic starts

    # Run each Go client once so s3slower discovers it and attaches its Go
    # TLS probes before the lanes' first requests (probes persist per binary).
    local bin_dir="${DEMO_BIN_DIR:-build/demo-bin}"
    for tool in s5cmd mc rclone; do
        local exe; exe="$(command -v "$tool" || echo "$bin_dir/$tool/$tool")"
        [[ -x "$exe" ]] && "$exe" --version > /dev/null 2>&1 || true
    done
    sleep 2

    echo "starting workloads (auto-stop after ${MAX_HOURS}h)"
    launch mixed python3 demo/mixed_workload.py "${ssl[@]}" --process-name train-loader \
        --prefix s3slower-demo/mixed
    launch pipeline python3 demo/ai_pipeline_workload.py "${ssl[@]}" --prefix s3slower-demo/pipeline \
        --shards 150 --reads 300 --ckpts 1 --misses 1 --pause 45
    S3_PREFIX=s3slower-demo/awscli SHARDS=30 CKPT_MIB=64 PAUSE=30 launch awscli demo/awscli_workload.sh
    local plain="${HTTP_ENDPOINT:-$S3_ENDPOINT}"
    ELBENCHO_ENDPOINT="$plain" S3_PREFIX=s3slower-demo/elbencho launch elbencho demo/elbencho_bursts.sh
    for tool in s5cmd mc rclone curl; do
        if ! command -v "$tool" > /dev/null && [[ ! -x "$bin_dir/$tool/$tool" ]]; then
            echo "  skipping $tool (not installed)"
            continue
        fi
        S3_PREFIX="s3slower-demo/$tool" launch "$tool" demo/cli_clients_workload.sh "$tool"
    done
}

stop() {
    # Workloads first so their cleanup traffic is still traced.
    for n in "${LANES[@]}" tracer; do
        local f; f="$(pidfile "$n")"
        [[ -f "$f" ]] || continue
        if alive "$n"; then
            echo "stopping $n"
            sudo kill -TERM "$(cat "$f")" 2>/dev/null || true
            for _ in $(seq 1 180); do alive "$n" || break; sleep 1; done
            if alive "$n"; then
                echo "  $n did not exit within 3 minutes; killing it"
                sudo kill -KILL $(tree "$(cat "$f")") 2>/dev/null
            fi
        fi
        rm -f "$f"
    done
}

status() {
    for n in tracer "${LANES[@]}"; do
        if alive "$n"; then
            printf "%-9s running (pid %s)  %s\n" "$n" "$(cat "$(pidfile "$n")")" \
                "$(tail -n 1 "$RUN_DIR/$n.log" 2>/dev/null | cut -c1-110)"
        else
            printf "%-9s stopped\n" "$n"
        fi
    done
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    *) echo "usage: $0 start|stop|status"; exit 2 ;;
esac
