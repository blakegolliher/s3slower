#!/usr/bin/env bash
# stress_workload_elbencho.sh — Long-running elbencho stress workload.
#
# Usage: stress_workload_elbencho.sh <output_jsonl> <endpoint_url> <bucket_name>
#
# Runs elbencho in discrete phases, tracking objects and performing weighted
# random operation selection. Unlike awscli which spawns per-command, elbencho
# runs as a single binary for each phase.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/stress_common.sh"

# ─── Arguments ─────────────────────────────────────────────────────────────────
OUTPUT_JSONL="${1:?Usage: $0 <output_jsonl> <endpoint_url> <bucket_name>}"
ENDPOINT_URL="${2:?Missing endpoint_url}"
BUCKET="${3:?Missing bucket_name}"

CLIENT="elbencho"

# ─── Registry ──────────────────────────────────────────────────────────────────
REGISTRY_FILE=$(mktemp /tmp/stress-registry-elbencho-XXXXXX)
registry_init "$REGISTRY_FILE"

# Track file prefixes and counts for elbencho naming convention (rN-fN)
declare -A PREFIX_FILES  # prefix -> count

cleanup_registry() {
    rm -f "$REGISTRY_FILE" "${REGISTRY_FILE}.tmp"
}
trap 'cleanup_registry' EXIT

# ─── SSL flag ──────────────────────────────────────────────────────────────────
ELBENCHO_SSL_FLAG=()
if [[ "$S3_NO_VERIFY_SSL" == "true" ]]; then
    ELBENCHO_SSL_FLAG=(--s3noverify)
fi

# ─── Helpers ───────────────────────────────────────────────────────────────────
run_elbencho() {
    # Run elbencho and capture PID + exit code.
    local pid_file
    pid_file=$(mktemp /tmp/stress-elb-pid-XXXXXX)

    elbencho "$@" &
    local elb_pid=$!
    echo "$elb_pid" > "$pid_file"
    wait $elb_pid 2>/dev/null
    local ec=$?
    rm -f "$pid_file"
    echo "$elb_pid:$ec"
}

parse_pid_ec() {
    local result="$1"
    PID_VAL="${result%%:*}"
    EC_VAL="${result##*:}"
}

next_prefix() {
    echo "stress/elb-$(date +%s)-${RANDOM}"
}

# ─── Operations ────────────────────────────────────────────────────────────────
do_put_single() {
    # Write 1-4 small files using elbencho
    local prefix
    prefix=$(next_prefix)
    local num_files=$(random_range 1 4)

    # Pick a size tier for this batch
    local size_tiers=(1024 4096 65536 1048576)
    local size="${size_tiers[$((RANDOM % ${#size_tiers[@]}))]}"
    local size_kb=$(( size / 1024 ))
    [[ $size_kb -lt 1 ]] && size_kb=1

    local result
    result=$(run_elbencho \
        --s3endpoints "$ENDPOINT_URL" "${ELBENCHO_SSL_FLAG[@]}" \
        --s3key "$AWS_ACCESS_KEY_ID" --s3secret "$AWS_SECRET_ACCESS_KEY" \
        -w -t 1 -n "$num_files" -s "${size_kb}k" -b "${size_kb}k" \
        "/${BUCKET}/${prefix}/" 2>/dev/null)
    parse_pid_ec "$result"

    # Register each file (elbencho naming: r0-f0, r0-f1, ...)
    local f
    for (( f=0; f<num_files; f++ )); do
        local key="${prefix}/r0-f${f}"
        log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "PUT_OBJECT" "PUT" "$BUCKET" "$key" "$size" "$EC_VAL"
        if [[ "$EC_VAL" -eq 0 ]]; then
            registry_add "$REGISTRY_FILE" "$key" "$size"
        fi
    done
    PREFIX_FILES["$prefix"]=$num_files
}

do_put_large() {
    # Write 1-2 large files (16MB or 64MB)
    local prefix
    prefix=$(next_prefix)
    local sizes_mb=(16 64)
    local size_mb="${sizes_mb[$((RANDOM % ${#sizes_mb[@]}))]}"
    local size=$(( size_mb * 1048576 ))
    local num_files=$(random_range 1 2)

    local result
    result=$(run_elbencho \
        --s3endpoints "$ENDPOINT_URL" "${ELBENCHO_SSL_FLAG[@]}" \
        --s3key "$AWS_ACCESS_KEY_ID" --s3secret "$AWS_SECRET_ACCESS_KEY" \
        -w -t 1 -n "$num_files" -s "${size_mb}m" -b 5m \
        "/${BUCKET}/${prefix}/" 2>/dev/null)
    parse_pid_ec "$result"

    local f
    for (( f=0; f<num_files; f++ )); do
        local key="${prefix}/r0-f${f}"
        log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "PUT_OBJECT" "PUT" "$BUCKET" "$key" "$size" "$EC_VAL"
        if [[ "$EC_VAL" -eq 0 ]]; then
            registry_add "$REGISTRY_FILE" "$key" "$size"
        fi
    done
    PREFIX_FILES["$prefix"]=$num_files
}

do_get_full() {
    # Read files from a known prefix
    local line
    line=$(registry_random_object "$REGISTRY_FILE") || return
    local key size
    key=$(echo "$line" | awk '{print $1}')
    size=$(echo "$line" | awk '{print $2}')

    # Extract prefix (everything up to /r0-fN)
    local prefix="${key%/r0-f*}"
    local num_files="${PREFIX_FILES[$prefix]:-1}"

    local result
    result=$(run_elbencho \
        --s3endpoints "$ENDPOINT_URL" "${ELBENCHO_SSL_FLAG[@]}" \
        --s3key "$AWS_ACCESS_KEY_ID" --s3secret "$AWS_SECRET_ACCESS_KEY" \
        -r -t 1 -n "$num_files" -s "$size" -b "$size" \
        "/${BUCKET}/${prefix}/" 2>/dev/null)
    parse_pid_ec "$result"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "GET_OBJECT" "GET" "$BUCKET" "$key" "$size" "$EC_VAL"
}

do_get_range() {
    # Ranged read: use -r with smaller block size
    local line
    line=$(registry_random_object "$REGISTRY_FILE") || return
    local key size
    key=$(echo "$line" | awk '{print $1}')
    size=$(echo "$line" | awk '{print $2}')

    if [[ "$size" -lt 4096 ]]; then return; fi

    local prefix="${key%/r0-f*}"
    local num_files="${PREFIX_FILES[$prefix]:-1}"
    local blocksize=$((size / 4))  # read 25% of the object

    local result
    result=$(run_elbencho \
        --s3endpoints "$ENDPOINT_URL" "${ELBENCHO_SSL_FLAG[@]}" \
        --s3key "$AWS_ACCESS_KEY_ID" --s3secret "$AWS_SECRET_ACCESS_KEY" \
        -r -t 1 -n "$num_files" -s "$size" -b "$blocksize" \
        "/${BUCKET}/${prefix}/" 2>/dev/null)
    parse_pid_ec "$result"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "GET_OBJECT" "GET" "$BUCKET" "$key" "$blocksize" "$EC_VAL"
}

do_head() {
    local line
    line=$(registry_random_object "$REGISTRY_FILE") || return
    local key
    key=$(echo "$line" | awk '{print $1}')

    local prefix="${key%/r0-f*}"
    local num_files="${PREFIX_FILES[$prefix]:-1}"

    local result
    result=$(run_elbencho \
        --s3endpoints "$ENDPOINT_URL" "${ELBENCHO_SSL_FLAG[@]}" \
        --s3key "$AWS_ACCESS_KEY_ID" --s3secret "$AWS_SECRET_ACCESS_KEY" \
        --stat -t 1 -n "$num_files" \
        "/${BUCKET}/${prefix}/" 2>/dev/null)
    parse_pid_ec "$result"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "HEAD_OBJECT" "HEAD" "$BUCKET" "$key" 0 "$EC_VAL"
}

do_list() {
    local result
    result=$(run_elbencho \
        --s3endpoints "$ENDPOINT_URL" "${ELBENCHO_SSL_FLAG[@]}" \
        --s3key "$AWS_ACCESS_KEY_ID" --s3secret "$AWS_SECRET_ACCESS_KEY" \
        --s3listobj \
        "/${BUCKET}/stress/" 2>/dev/null)
    parse_pid_ec "$result"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "LIST_PREFIX" "GET" "$BUCKET" "stress/" 0 "$EC_VAL"
}

do_delete() {
    local line
    line=$(registry_random_object "$REGISTRY_FILE") || return
    local key
    key=$(echo "$line" | awk '{print $1}')

    local prefix="${key%/r0-f*}"
    local num_files="${PREFIX_FILES[$prefix]:-1}"

    local result
    result=$(run_elbencho \
        --s3endpoints "$ENDPOINT_URL" "${ELBENCHO_SSL_FLAG[@]}" \
        --s3key "$AWS_ACCESS_KEY_ID" --s3secret "$AWS_SECRET_ACCESS_KEY" \
        -F -t 1 -n "$num_files" \
        "/${BUCKET}/${prefix}/" 2>/dev/null)
    parse_pid_ec "$result"

    # Remove all files in this prefix from registry
    local f
    for (( f=0; f<num_files; f++ )); do
        local k="${prefix}/r0-f${f}"
        registry_remove "$REGISTRY_FILE" "$k"
        log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "DELETE_OBJECT" "DELETE" "$BUCKET" "$k" 0 "$EC_VAL"
    done
    unset PREFIX_FILES["$prefix"] 2>/dev/null || true
}

# ─── Dispatch ──────────────────────────────────────────────────────────────────
dispatch_op() {
    local op="$1"
    case "$op" in
        PUT_SINGLE) do_put_single ;;
        PUT_MPU)    do_put_large ;;   # elbencho uses multipart for large files automatically
        GET_FULL)   do_get_full ;;
        GET_RANGE)  do_get_range ;;
        HEAD)       do_head ;;
        LIST)       do_list ;;
        DELETE)     do_delete ;;
        COPY)       do_put_single ;;  # elbencho doesn't support copy, use extra write
    esac
}

# ─── Main loop ─────────────────────────────────────────────────────────────────
echo "[$(date -Iseconds)] elbencho stress workload started (PID $$, bucket=$BUCKET)" >&2

CYCLE=0
while should_continue; do
    CYCLE=$(( CYCLE + 1 ))

    NUM_OPS=$(random_range "$STRESS_OPS_MIN" "$STRESS_OPS_MAX")
    for (( i=0; i<NUM_OPS; i++ )); do
        if ! should_continue; then break; fi

        OP=$(pick_operation)
        NEEDS_OBJECTS=0
        case "$OP" in GET_FULL|GET_RANGE|HEAD|DELETE|COPY) NEEDS_OBJECTS=1 ;; esac
        if [[ "$NEEDS_OBJECTS" -eq 1 ]] && [[ $(registry_count "$REGISTRY_FILE") -eq 0 ]]; then
            OP="PUT_SINGLE"
        fi

        dispatch_op "$OP"
    done

    # Periodic status
    if (( CYCLE % 10 == 0 )); then
        echo "[$(date -Iseconds)] elbencho cycle=$CYCLE objects=$(registry_count "$REGISTRY_FILE") seq=$_SEQ" >&2
    fi

    # GC
    gc_if_needed "$BUCKET" "$REGISTRY_FILE"

    # Random sleep
    random_sleep
done

echo "[$(date -Iseconds)] elbencho stress workload exiting (seq=$_SEQ, objects=$(registry_count "$REGISTRY_FILE"))" >&2
