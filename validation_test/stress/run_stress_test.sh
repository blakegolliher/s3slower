#!/usr/bin/env bash
# run_stress_test.sh — Orchestrator for long-running s3slower stress test.
#
# Starts s3slower, launches 3 concurrent workloads (awscli, boto3, elbencho),
# monitors worker health, and performs graceful shutdown on SIGINT/SIGTERM.
#
# Usage:
#   sudo -E run_stress_test.sh
#
# Required env vars:
#   S3_ENDPOINT, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
#
# Optional env vars:
#   S3SLOWER_BIN        (default: build/s3slower)
#   S3_NO_VERIFY_SSL    (default: false)
#   STRESS_DURATION_HOURS (default: 24)
#   STRESS_MAX_DATA_GB  (default: 250, per bucket)
#   STRESS_CYCLE_MIN_S  (default: 30)
#   STRESS_CYCLE_MAX_S  (default: 120)
#   NO_S3SLOWER         (default: false, set "true" to skip launching s3slower)

set -uo pipefail

# Ensure /usr/local/bin is in PATH (sudo may strip it)
case ":$PATH:" in
    *":/usr/local/bin:"*) ;;
    *) export PATH="/usr/local/bin:$PATH" ;;
esac

# ─── Configuration ─────────────────────────────────────────────────────────────
: "${S3_ENDPOINT:?S3_ENDPOINT must be set}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID must be set}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY must be set}"
: "${S3SLOWER_BIN:=build/s3slower}"
: "${S3_NO_VERIFY_SSL:=false}"
: "${STRESS_DURATION_HOURS:=24}"
: "${STRESS_MAX_DATA_GB:=250}"
: "${STRESS_CYCLE_MIN_S:=30}"
: "${STRESS_CYCLE_MAX_S:=120}"
: "${NO_S3SLOWER:=false}"

export S3_ENDPOINT AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY S3_NO_VERIFY_SSL
export STRESS_MAX_DATA_GB STRESS_CYCLE_MIN_S STRESS_CYCLE_MAX_S

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TIMESTAMP=$(date +%s)

# Bucket names (fixed, not timestamped — reusable across runs)
BUCKET_AWSCLI="s3slower-e2e-awscli"
BUCKET_BOTO3="s3slower-e2e-boto3"
BUCKET_ELBENCHO="s3slower-e2e-elbencho"

# Output directory
STRESS_DIR=$(mktemp -d /tmp/s3slower-stress-XXXXX)
LOG_AWSCLI="$STRESS_DIR/workload_awscli.jsonl"
LOG_BOTO3="$STRESS_DIR/workload_boto3.jsonl"
LOG_ELBENCHO="$STRESS_DIR/workload_elbencho.jsonl"
STATUS_LOG="$STRESS_DIR/stress_status.log"
S3SLOWER_OUTPUT="$STRESS_DIR/s3slower_capture.jsonl"

# PIDs
PID_S3SLOWER=0
PID_AWSCLI=0
PID_BOTO3=0
PID_ELBENCHO=0
SHUTDOWN=0

# ─── Logging ───────────────────────────────────────────────────────────────────
log() { echo "[$(date -Iseconds)] $*" >&2; }
log_status() { echo "[$(date -Iseconds)] $*" >> "$STATUS_LOG"; }

# ─── Prerequisites ─────────────────────────────────────────────────────────────
check_prerequisites() {
    local fail=0

    if [[ $EUID -ne 0 ]]; then
        log "ERROR: Must run as root (eBPF requires CAP_SYS_ADMIN)"
        fail=1
    fi

    if [[ ! -x "$S3SLOWER_BIN" ]] && [[ "$NO_S3SLOWER" != "true" ]]; then
        # Try relative to repo root
        if [[ -x "$REPO_ROOT/$S3SLOWER_BIN" ]]; then
            S3SLOWER_BIN="$REPO_ROOT/$S3SLOWER_BIN"
        else
            log "ERROR: s3slower binary not found at $S3SLOWER_BIN"
            fail=1
        fi
    fi

    for cmd in aws python3 curl; do
        if ! command -v "$cmd" &>/dev/null; then
            log "ERROR: $cmd not found"
            fail=1
        fi
    done

    if ! python3 -c "import boto3" 2>/dev/null; then
        log "ERROR: boto3 not installed (pip3 install boto3)"
        fail=1
    fi

    if ! command -v elbencho &>/dev/null; then
        log "WARNING: elbencho not found — elbencho workload will be skipped"
    fi

    # Test S3 endpoint reachability
    local endpoint_host="${S3_ENDPOINT#http://}"
    endpoint_host="${endpoint_host#https://}"
    endpoint_host="${endpoint_host%%/*}"
    endpoint_host="${endpoint_host%%:*}"
    if ! curl -sf --connect-timeout 5 "$S3_ENDPOINT" >/dev/null 2>&1; then
        # Some S3 endpoints return non-zero for root, try a HEAD
        if ! curl -sf --connect-timeout 5 -o /dev/null "$S3_ENDPOINT/" 2>/dev/null; then
            log "WARNING: S3 endpoint $S3_ENDPOINT may not be reachable"
        fi
    fi

    return $fail
}

# ─── Cleanup ───────────────────────────────────────────────────────────────────
cleanup_bucket() {
    local bucket="$1"
    log "Cleaning bucket $bucket..."

    # Abort lingering multipart uploads
    local uploads
    uploads=$(aws s3api list-multipart-uploads --endpoint-url "$S3_ENDPOINT" \
        ${S3_NO_VERIFY_SSL:+--no-verify-ssl} --bucket "$bucket" 2>/dev/null || true)
    if [[ -n "$uploads" ]]; then
        echo "$uploads" | python3 -c "
import json,sys
data = json.load(sys.stdin)
for u in data.get('Uploads', []):
    print(u['Key'], u['UploadId'])
" 2>/dev/null | while read -r key uid; do
            aws s3api abort-multipart-upload --endpoint-url "$S3_ENDPOINT" \
                ${S3_NO_VERIFY_SSL:+--no-verify-ssl} \
                --bucket "$bucket" --key "$key" --upload-id "$uid" 2>/dev/null || true
        done
    fi

    # Delete all objects
    aws s3 rm "s3://$bucket" --recursive --endpoint-url "$S3_ENDPOINT" \
        ${S3_NO_VERIFY_SSL:+--no-verify-ssl} 2>/dev/null || true

    # Delete bucket
    aws s3api delete-bucket --endpoint-url "$S3_ENDPOINT" \
        ${S3_NO_VERIFY_SSL:+--no-verify-ssl} --bucket "$bucket" 2>/dev/null || true
}

kill_pid() {
    local pid="$1" name="$2"
    if [[ "$pid" -gt 0 ]] && kill -0 "$pid" 2>/dev/null; then
        log "Stopping $name (PID $pid)..."
        kill -TERM "$pid" 2>/dev/null || true
        # Wait up to 10s for graceful shutdown
        local i
        for (( i=0; i<20; i++ )); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.5
        done
        # Force kill if still alive
        if kill -0 "$pid" 2>/dev/null; then
            log "Force killing $name (PID $pid)"
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi
}

graceful_shutdown() {
    if [[ $SHUTDOWN -eq 1 ]]; then return; fi
    SHUTDOWN=1
    log "Graceful shutdown initiated..."

    # Stop workers
    kill_pid $PID_AWSCLI "awscli workload"
    kill_pid $PID_BOTO3 "boto3 workload"
    kill_pid $PID_ELBENCHO "elbencho workload"

    # Wait for workers to flush logs
    sleep 2

    # Stop s3slower
    kill_pid $PID_S3SLOWER "s3slower"

    # Report final status
    log "Final status:"
    for f in "$LOG_AWSCLI" "$LOG_BOTO3" "$LOG_ELBENCHO"; do
        if [[ -f "$f" ]]; then
            local count
            count=$(wc -l < "$f" 2>/dev/null || echo 0)
            log "  $(basename "$f"): $count operations"
        fi
    done

    if [[ -f "$S3SLOWER_OUTPUT" ]]; then
        local capture_count
        capture_count=$(wc -l < "$S3SLOWER_OUTPUT" 2>/dev/null || echo 0)
        log "  s3slower captured: $capture_count events"
    fi

    log "Output directory: $STRESS_DIR"
    log "Stress test completed."
}

trap graceful_shutdown SIGINT SIGTERM EXIT

# ─── Bucket setup ──────────────────────────────────────────────────────────────
create_buckets() {
    local ssl_flag=""
    [[ "$S3_NO_VERIFY_SSL" == "true" ]] && ssl_flag="--no-verify-ssl"

    for bucket in "$BUCKET_AWSCLI" "$BUCKET_BOTO3" "$BUCKET_ELBENCHO"; do
        if aws s3api head-bucket --endpoint-url "$S3_ENDPOINT" $ssl_flag \
                --bucket "$bucket" 2>/dev/null; then
            log "Bucket exists: $bucket"
        else
            log "Creating bucket: $bucket"
            aws s3api create-bucket --endpoint-url "$S3_ENDPOINT" $ssl_flag \
                --bucket "$bucket" 2>/dev/null || true
        fi
    done
}

# ─── Worker management ────────────────────────────────────────────────────────
start_s3slower() {
    if [[ "$NO_S3SLOWER" == "true" ]]; then
        log "NO_S3SLOWER=true, skipping s3slower launch"
        return
    fi

    log "Starting s3slower..."
    $S3SLOWER_BIN run \
        --prometheus --port 9000 \
        --output json --no-log --min-latency 0 \
        > "$S3SLOWER_OUTPUT" 2>"$STRESS_DIR/s3slower.stderr" &
    PID_S3SLOWER=$!
    log "s3slower started (PID $PID_S3SLOWER)"

    # Wait for probe attachment
    sleep 3

    if ! kill -0 $PID_S3SLOWER 2>/dev/null; then
        log "ERROR: s3slower died on startup. Check $STRESS_DIR/s3slower.stderr"
        cat "$STRESS_DIR/s3slower.stderr" >&2
        exit 1
    fi
}

start_awscli() {
    local ssl_arg=""
    [[ "$S3_NO_VERIFY_SSL" == "true" ]] && ssl_arg="no-verify-ssl"

    bash "$SCRIPT_DIR/stress_workload_awscli.sh" \
        "$LOG_AWSCLI" "$S3_ENDPOINT" "$BUCKET_AWSCLI" "$ssl_arg" \
        2>"$STRESS_DIR/awscli.stderr" &
    PID_AWSCLI=$!
    log "awscli workload started (PID $PID_AWSCLI)"
}

start_boto3() {
    local ssl_flag=()
    [[ "$S3_NO_VERIFY_SSL" == "true" ]] && ssl_flag=(--no-verify-ssl)

    python3 "$SCRIPT_DIR/stress_workload_boto3.py" \
        --output "$LOG_BOTO3" --endpoint "$S3_ENDPOINT" --bucket "$BUCKET_BOTO3" \
        --max-data-gb "$STRESS_MAX_DATA_GB" \
        --cycle-min-s "$STRESS_CYCLE_MIN_S" --cycle-max-s "$STRESS_CYCLE_MAX_S" \
        "${ssl_flag[@]}" \
        2>"$STRESS_DIR/boto3.stderr" &
    PID_BOTO3=$!
    log "boto3 workload started (PID $PID_BOTO3)"
}

start_elbencho() {
    if ! command -v elbencho &>/dev/null; then
        log "Skipping elbencho workload (not installed)"
        return
    fi

    bash "$SCRIPT_DIR/stress_workload_elbencho.sh" \
        "$LOG_ELBENCHO" "$S3_ENDPOINT" "$BUCKET_ELBENCHO" \
        2>"$STRESS_DIR/elbencho.stderr" &
    PID_ELBENCHO=$!
    log "elbencho workload started (PID $PID_ELBENCHO)"
}

check_worker() {
    local pid="$1" name="$2" start_func="$3"
    if [[ "$pid" -gt 0 ]] && ! kill -0 "$pid" 2>/dev/null; then
        log "WARNING: $name (PID $pid) has died, restarting..."
        log_status "RESTART $name (was PID $pid)"
        $start_func
    fi
}

# ─── Main ──────────────────────────────────────────────────────────────────────
main() {
    log "═══════════════════════════════════════════════════════════════"
    log "  s3slower Long-Running Stress Test"
    log "═══════════════════════════════════════════════════════════════"
    log "  Endpoint:       $S3_ENDPOINT"
    log "  Duration:       ${STRESS_DURATION_HOURS}h"
    log "  Max data/bucket: ${STRESS_MAX_DATA_GB}GB"
    log "  Cycle interval: ${STRESS_CYCLE_MIN_S}-${STRESS_CYCLE_MAX_S}s"
    log "  Output dir:     $STRESS_DIR"
    log "  NO_S3SLOWER:    $NO_S3SLOWER"
    log "═══════════════════════════════════════════════════════════════"

    check_prerequisites || exit 1

    create_buckets
    start_s3slower
    start_awscli
    start_boto3
    start_elbencho

    log "All workers launched. Monitoring for ${STRESS_DURATION_HOURS}h..."
    log_status "STARTED duration=${STRESS_DURATION_HOURS}h"

    local end_time=$(( $(date +%s) + STRESS_DURATION_HOURS * 3600 ))
    local health_check_interval=60
    local heartbeat_interval=300
    local last_heartbeat=$(date +%s)

    while [[ $SHUTDOWN -eq 0 ]] && [[ $(date +%s) -lt $end_time ]]; do
        sleep $health_check_interval &
        local sleep_pid=$!
        wait $sleep_pid 2>/dev/null || true

        if [[ $SHUTDOWN -eq 1 ]]; then break; fi

        # Health check — restart crashed workers
        check_worker $PID_AWSCLI "awscli" start_awscli
        check_worker $PID_BOTO3 "boto3" start_boto3
        if command -v elbencho &>/dev/null; then
            check_worker $PID_ELBENCHO "elbencho" start_elbencho
        fi

        # Heartbeat every 5 minutes
        local now
        now=$(date +%s)
        if (( now - last_heartbeat >= heartbeat_interval )); then
            last_heartbeat=$now
            local elapsed=$(( (now - TIMESTAMP) / 60 ))
            local remaining=$(( (end_time - now) / 60 ))

            local awscli_ops=0 boto3_ops=0 elbencho_ops=0
            [[ -f "$LOG_AWSCLI" ]] && awscli_ops=$(wc -l < "$LOG_AWSCLI")
            [[ -f "$LOG_BOTO3" ]] && boto3_ops=$(wc -l < "$LOG_BOTO3")
            [[ -f "$LOG_ELBENCHO" ]] && elbencho_ops=$(wc -l < "$LOG_ELBENCHO")
            local total_ops=$(( awscli_ops + boto3_ops + elbencho_ops ))

            local s3slower_ok="N/A"
            if [[ $PID_S3SLOWER -gt 0 ]]; then
                kill -0 $PID_S3SLOWER 2>/dev/null && s3slower_ok="UP" || s3slower_ok="DOWN"
            fi

            local prom_ok="N/A"
            if [[ "$NO_S3SLOWER" != "true" ]]; then
                curl -sf "http://127.0.0.1:9000/health" >/dev/null 2>&1 && prom_ok="UP" || prom_ok="DOWN"
            fi

            log "HEARTBEAT: elapsed=${elapsed}m remaining=${remaining}m ops=${total_ops} (awscli=$awscli_ops boto3=$boto3_ops elbencho=$elbencho_ops) s3slower=$s3slower_ok prometheus=$prom_ok"
            log_status "HEARTBEAT elapsed=${elapsed}m remaining=${remaining}m total_ops=$total_ops s3slower=$s3slower_ok prometheus=$prom_ok"
        fi
    done

    if [[ $SHUTDOWN -eq 0 ]]; then
        log "Duration ${STRESS_DURATION_HOURS}h reached. Shutting down."
        log_status "COMPLETED duration=${STRESS_DURATION_HOURS}h"
    fi
}

main "$@"
