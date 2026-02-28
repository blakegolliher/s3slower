#!/usr/bin/env bash
# stress_common.sh — Shared library for s3slower stress test workloads.
# Source this file from bash workloads:  source "$(dirname "$0")/stress_common.sh"

set -euo pipefail

# ─── Defaults (override via env before sourcing) ───────────────────────────────
: "${S3_ENDPOINT:?S3_ENDPOINT must be set}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID must be set}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY must be set}"
: "${STRESS_MAX_DATA_GB:=250}"
: "${STRESS_CYCLE_MIN_S:=30}"
: "${STRESS_CYCLE_MAX_S:=120}"
: "${STRESS_OPS_MIN:=1}"
: "${STRESS_OPS_MAX:=5}"
: "${S3_NO_VERIFY_SSL:=false}"

# ─── Global state ──────────────────────────────────────────────────────────────
SHUTDOWN=0
_SEQ=0

# AWS CLI common args
AWS_COMMON_ARGS=(--endpoint-url "$S3_ENDPOINT")
if [[ "$S3_NO_VERIFY_SSL" == "true" ]]; then
    AWS_COMMON_ARGS+=(--no-verify-ssl)
fi

# ─── Signal handling ───────────────────────────────────────────────────────────
_shutdown_handler() {
    SHUTDOWN=1
    echo "[$(date -Iseconds)] Shutdown signal received" >&2
}
trap _shutdown_handler SIGINT SIGTERM

should_continue() {
    [[ $SHUTDOWN -eq 0 ]]
}

# ─── Object registry ──────────────────────────────────────────────────────────
# Flat file: KEY SIZE_BYTES TIMESTAMP
# One registry per workload — pass the file path.

registry_init() {
    local file="$1"
    : > "$file"
}

registry_add() {
    local file="$1" key="$2" size="$3"
    echo "$key $size $(date +%s)" >> "$file"
}

registry_remove() {
    local file="$1" key="$2"
    # Remove first matching line
    local tmp="${file}.tmp"
    grep -v "^${key} " "$file" > "$tmp" 2>/dev/null || true
    mv "$tmp" "$file"
}

registry_count() {
    local file="$1"
    wc -l < "$file" 2>/dev/null || echo 0
}

registry_total_bytes() {
    local file="$1"
    awk '{s+=$2} END{print s+0}' "$file" 2>/dev/null || echo 0
}

registry_random_object() {
    # Print a random line (KEY SIZE_BYTES TIMESTAMP). Returns 1 if empty.
    local file="$1"
    local count
    count=$(registry_count "$file")
    if [[ "$count" -eq 0 ]]; then
        return 1
    fi
    local idx=$(( RANDOM % count + 1 ))
    sed -n "${idx}p" "$file"
}

registry_oldest_keys() {
    # Print the N oldest keys (sorted by timestamp asc).
    local file="$1" n="$2"
    sort -k3 -n "$file" | head -n "$n" | awk '{print $1}'
}

# ─── Garbage collection ───────────────────────────────────────────────────────
gc_if_needed() {
    local bucket="$1" registry_file="$2"
    local max_bytes=$(( STRESS_MAX_DATA_GB * 1073741824 ))  # GB → bytes
    local total
    total=$(registry_total_bytes "$registry_file")
    if [[ "$total" -le "$max_bytes" ]]; then
        return 0
    fi

    echo "[$(date -Iseconds)] GC: total ${total} bytes exceeds ${max_bytes}, deleting oldest 100 objects" >&2
    local keys
    keys=$(registry_oldest_keys "$registry_file" 100)
    local key
    for key in $keys; do
        if ! should_continue; then break; fi
        aws s3api delete-object "${AWS_COMMON_ARGS[@]}" --bucket "$bucket" --key "$key" 2>/dev/null || true
        registry_remove "$registry_file" "$key"
    done
    echo "[$(date -Iseconds)] GC: complete, $(registry_count "$registry_file") objects remaining" >&2
}

# ─── Weighted random operation selection ───────────────────────────────────────
# Usage: pick_operation
# Prints one of: PUT_SINGLE PUT_MPU GET_FULL GET_RANGE HEAD LIST DELETE COPY
pick_operation() {
    local r=$(( RANDOM % 100 ))
    if   (( r < 25 )); then echo "PUT_SINGLE"
    elif (( r < 35 )); then echo "PUT_MPU"
    elif (( r < 55 )); then echo "GET_FULL"
    elif (( r < 65 )); then echo "GET_RANGE"
    elif (( r < 75 )); then echo "HEAD"
    elif (( r < 85 )); then echo "LIST"
    elif (( r < 95 )); then echo "DELETE"
    else                     echo "COPY"
    fi
}

# ─── Random helpers ────────────────────────────────────────────────────────────
random_range() {
    local min="$1" max="$2"
    echo $(( RANDOM % (max - min + 1) + min ))
}

random_size() {
    # Returns a random object size in bytes from the distribution
    local sizes=(1024 4096 65536 1048576 16777216 67108864)
    local idx=$(( RANDOM % ${#sizes[@]} ))
    echo "${sizes[$idx]}"
}

random_key_prefix() {
    echo "stress/$(date +%s)-${RANDOM}"
}

random_sleep() {
    local secs
    secs=$(random_range "$STRESS_CYCLE_MIN_S" "$STRESS_CYCLE_MAX_S")
    if should_continue; then
        sleep "$secs" &
        local sleep_pid=$!
        # Allow interruption of sleep
        wait $sleep_pid 2>/dev/null || true
    fi
}

# ─── Retry logic ───────────────────────────────────────────────────────────────
retry() {
    local max_attempts=3
    local attempt=1
    local delay=1
    while (( attempt <= max_attempts )); do
        if "$@"; then
            return 0
        fi
        if (( attempt == max_attempts )); then
            return 1
        fi
        echo "[$(date -Iseconds)] Retry $attempt/$max_attempts failed, sleeping ${delay}s" >&2
        sleep "$delay"
        delay=$(( delay * 2 ))
        attempt=$(( attempt + 1 ))
    done
    return 1
}

# ─── JSONL logging ─────────────────────────────────────────────────────────────
# Same format as existing validation workloads.
log_op() {
    local output_file="$1" pid="$2" client="$3" operation="$4" method="$5" \
          bucket="$6" key="$7" size="$8" exit_code="$9"
    _SEQ=$(( _SEQ + 1 ))
    printf '{"seq":%d,"timestamp":"%s","pid":%d,"client":"%s","operation":"%s","method":"%s","bucket":"%s","key":"%s","size":%d,"exit_code":%d}\n' \
        "$_SEQ" "$(date -Iseconds)" "$pid" "$client" "$operation" "$method" \
        "$bucket" "$key" "$size" "$exit_code" >> "$output_file"
}

# ─── Data generation ───────────────────────────────────────────────────────────
generate_data_file() {
    # Create a temporary file of the given size using dd from /dev/urandom.
    local size="$1"
    local tmpfile
    tmpfile=$(mktemp /tmp/stress-data-XXXXXX)
    dd if=/dev/urandom of="$tmpfile" bs=1M count=$(( (size + 1048575) / 1048576 )) iflag=count_bytes,fullblock 2>/dev/null
    # Truncate to exact size
    truncate -s "$size" "$tmpfile"
    echo "$tmpfile"
}
