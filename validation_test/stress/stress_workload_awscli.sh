#!/usr/bin/env bash
# stress_workload_awscli.sh — Long-running AWS CLI stress workload.
#
# Usage: stress_workload_awscli.sh <output_jsonl> <endpoint_url> <bucket_name> [no-verify-ssl]
#
# Runs continuously performing weighted-random S3 operations via aws s3api.
# Each AWS CLI invocation is a separate process, matching PID tracking patterns.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/stress_common.sh"

# ─── Arguments ─────────────────────────────────────────────────────────────────
OUTPUT_JSONL="${1:?Usage: $0 <output_jsonl> <endpoint_url> <bucket_name> [no-verify-ssl]}"
ENDPOINT_URL="${2:?Missing endpoint_url}"
BUCKET="${3:?Missing bucket_name}"
NO_VERIFY_SSL="${4:-}"

CLIENT="awscli"

# ─── SSL flag ──────────────────────────────────────────────────────────────────
SSL_FLAG=()
if [[ "$NO_VERIFY_SSL" == "no-verify-ssl" || "$S3_NO_VERIFY_SSL" == "true" ]]; then
    SSL_FLAG=(--no-verify-ssl)
fi

# ─── Registry ──────────────────────────────────────────────────────────────────
REGISTRY_FILE=$(mktemp /tmp/stress-registry-awscli-XXXXXX)
registry_init "$REGISTRY_FILE"

cleanup_registry() {
    rm -f "$REGISTRY_FILE" "${REGISTRY_FILE}.tmp"
}
trap 'cleanup_registry' EXIT

# ─── Helpers ───────────────────────────────────────────────────────────────────
run_s3api() {
    # Run aws s3api in background, capture PID, wait for exit code.
    local subcmd="$1"; shift
    aws s3api "$subcmd" --endpoint-url "$ENDPOINT_URL" "${SSL_FLAG[@]}" "$@" \
        >/dev/null 2>&1 &
    local pid=$!
    wait $pid 2>/dev/null
    local ec=$?
    echo "$pid:$ec"
}

run_s3api_capture() {
    # Like run_s3api but captures stdout to a file.
    local subcmd="$1" outfile="$2"; shift 2
    aws s3api "$subcmd" --endpoint-url "$ENDPOINT_URL" "${SSL_FLAG[@]}" "$@" \
        > "$outfile" 2>/dev/null &
    local pid=$!
    wait $pid 2>/dev/null
    local ec=$?
    echo "$pid:$ec"
}

parse_pid_ec() {
    local result="$1"
    PID_VAL="${result%%:*}"
    EC_VAL="${result##*:}"
}

# ─── Operations ────────────────────────────────────────────────────────────────
do_put_single() {
    local size
    size=$(random_size)
    local key="stress/$(date +%s)-${RANDOM}"
    local tmpfile
    tmpfile=$(generate_data_file "$size")

    local result
    result=$(run_s3api put-object --bucket "$BUCKET" --key "$key" --body "$tmpfile")
    parse_pid_ec "$result"
    rm -f "$tmpfile"

    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "PUT_OBJECT" "PUT" "$BUCKET" "$key" "$size" "$EC_VAL"
    if [[ "$EC_VAL" -eq 0 ]]; then
        registry_add "$REGISTRY_FILE" "$key" "$size"
    fi
}

do_put_mpu() {
    local key="stress/mpu-$(date +%s)-${RANDOM}"
    local part_size=$((5 * 1024 * 1024))
    local num_parts=$(random_range 7 14)
    local total_size=$((part_size * num_parts))
    local capture_file
    capture_file=$(mktemp /tmp/stress-mpu-XXXXXX)

    # Create MPU
    local result
    result=$(run_s3api_capture create-multipart-upload "$capture_file" --bucket "$BUCKET" --key "$key")
    parse_pid_ec "$result"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "MPU_CREATE" "POST" "$BUCKET" "$key" 0 "$EC_VAL"

    if [[ "$EC_VAL" -ne 0 ]]; then
        rm -f "$capture_file"
        return
    fi

    local upload_id
    upload_id=$(python3 -c "import json,sys; print(json.load(open('$capture_file'))['UploadId'])" 2>/dev/null)
    rm -f "$capture_file"

    if [[ -z "$upload_id" ]]; then
        echo "[$(date -Iseconds)] MPU: failed to extract UploadId" >&2
        return
    fi

    # Upload parts
    local parts_json="["
    local i
    for (( i=1; i<=num_parts; i++ )); do
        if ! should_continue; then break; fi
        local tmpfile
        tmpfile=$(generate_data_file "$part_size")
        capture_file=$(mktemp /tmp/stress-mpu-part-XXXXXX)

        result=$(run_s3api_capture upload-part "$capture_file" \
            --bucket "$BUCKET" --key "$key" \
            --upload-id "$upload_id" --part-number "$i" --body "$tmpfile")
        parse_pid_ec "$result"
        rm -f "$tmpfile"
        log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "MPU_PART" "PUT" "$BUCKET" "$key" "$part_size" "$EC_VAL"

        if [[ "$EC_VAL" -ne 0 ]]; then
            rm -f "$capture_file"
            # Abort on part failure
            run_s3api abort-multipart-upload --bucket "$BUCKET" --key "$key" --upload-id "$upload_id" >/dev/null 2>&1 || true
            return
        fi

        local etag
        etag=$(python3 -c "import json,sys; print(json.load(open('$capture_file'))['ETag'])" 2>/dev/null)
        rm -f "$capture_file"

        [[ $i -gt 1 ]] && parts_json+=","
        parts_json+="{\"ETag\":${etag},\"PartNumber\":${i}}"
    done
    parts_json+="]"

    # Complete MPU
    local mpu_struct="{\"Parts\":${parts_json}}"
    result=$(run_s3api complete-multipart-upload \
        --bucket "$BUCKET" --key "$key" \
        --upload-id "$upload_id" --multipart-upload "$mpu_struct")
    parse_pid_ec "$result"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "MPU_COMPLETE" "POST" "$BUCKET" "$key" 0 "$EC_VAL"

    if [[ "$EC_VAL" -eq 0 ]]; then
        registry_add "$REGISTRY_FILE" "$key" "$total_size"
    fi
}

do_get_full() {
    local line
    line=$(registry_random_object "$REGISTRY_FILE") || return
    local key size
    key=$(echo "$line" | awk '{print $1}')
    size=$(echo "$line" | awk '{print $2}')
    local tmpfile
    tmpfile=$(mktemp /tmp/stress-get-XXXXXX)

    local result
    result=$(run_s3api_capture get-object "$tmpfile" --bucket "$BUCKET" --key "$key" /dev/null)
    parse_pid_ec "$result"
    rm -f "$tmpfile"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "GET_OBJECT" "GET" "$BUCKET" "$key" "$size" "$EC_VAL"
}

do_get_range() {
    local line
    line=$(registry_random_object "$REGISTRY_FILE") || return
    local key size
    key=$(echo "$line" | awk '{print $1}')
    size=$(echo "$line" | awk '{print $2}')

    if [[ "$size" -lt 2 ]]; then return; fi
    local start=$(( RANDOM % (size / 2) ))
    local end_max=$(( start + 1048576 ))
    [[ $end_max -ge $size ]] && end_max=$(( size - 1 ))
    local end=$(random_range $((start + 1)) $end_max)
    local range_size=$(( end - start + 1 ))
    local tmpfile
    tmpfile=$(mktemp /tmp/stress-get-range-XXXXXX)

    local result
    result=$(run_s3api_capture get-object "$tmpfile" --bucket "$BUCKET" --key "$key" \
        --range "bytes=${start}-${end}" /dev/null)
    parse_pid_ec "$result"
    rm -f "$tmpfile"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "GET_OBJECT" "GET" "$BUCKET" "$key" "$range_size" "$EC_VAL"
}

do_head() {
    local line
    line=$(registry_random_object "$REGISTRY_FILE") || return
    local key
    key=$(echo "$line" | awk '{print $1}')

    local result
    result=$(run_s3api head-object --bucket "$BUCKET" --key "$key")
    parse_pid_ec "$result"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "HEAD_OBJECT" "HEAD" "$BUCKET" "$key" 0 "$EC_VAL"
}

do_list() {
    local max_keys
    max_keys=$(random_range 10 1000)
    local prefixes=("stress/" "stress/mpu-" "")
    local prefix="${prefixes[$((RANDOM % ${#prefixes[@]}))]}"

    local result
    result=$(run_s3api list-objects-v2 --bucket "$BUCKET" --prefix "$prefix" --max-keys "$max_keys")
    parse_pid_ec "$result"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "LIST_PREFIX" "GET" "$BUCKET" "$prefix" 0 "$EC_VAL"
}

do_delete() {
    local line
    line=$(registry_random_object "$REGISTRY_FILE") || return
    local key
    key=$(echo "$line" | awk '{print $1}')

    local result
    result=$(run_s3api delete-object --bucket "$BUCKET" --key "$key")
    parse_pid_ec "$result"
    registry_remove "$REGISTRY_FILE" "$key"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "DELETE_OBJECT" "DELETE" "$BUCKET" "$key" 0 "$EC_VAL"
}

do_copy() {
    local line
    line=$(registry_random_object "$REGISTRY_FILE") || return
    local src_key size
    src_key=$(echo "$line" | awk '{print $1}')
    size=$(echo "$line" | awk '{print $2}')
    local dst_key="stress/copy-$(date +%s)-${RANDOM}"

    local result
    result=$(run_s3api copy-object --bucket "$BUCKET" --key "$dst_key" \
        --copy-source "$BUCKET/$src_key")
    parse_pid_ec "$result"
    log_op "$OUTPUT_JSONL" "$PID_VAL" "$CLIENT" "PUT_OBJECT" "PUT" "$BUCKET" "$dst_key" "$size" "$EC_VAL"
    if [[ "$EC_VAL" -eq 0 ]]; then
        registry_add "$REGISTRY_FILE" "$dst_key" "$size"
    fi
}

# ─── Dispatch ──────────────────────────────────────────────────────────────────
dispatch_op() {
    local op="$1"
    case "$op" in
        PUT_SINGLE) do_put_single ;;
        PUT_MPU)    do_put_mpu ;;
        GET_FULL)   do_get_full ;;
        GET_RANGE)  do_get_range ;;
        HEAD)       do_head ;;
        LIST)       do_list ;;
        DELETE)     do_delete ;;
        COPY)       do_copy ;;
    esac
}

# ─── Main loop ─────────────────────────────────────────────────────────────────
echo "[$(date -Iseconds)] awscli stress workload started (PID $$, bucket=$BUCKET)" >&2

CYCLE=0
while should_continue; do
    CYCLE=$(( CYCLE + 1 ))

    NUM_OPS=$(random_range "$STRESS_OPS_MIN" "$STRESS_OPS_MAX")
    for (( i=0; i<NUM_OPS; i++ )); do
        if ! should_continue; then break; fi

        OP=$(pick_operation)
        # Fall back to PUT if we need objects but have none
        NEEDS_OBJECTS=0
        case "$OP" in GET_FULL|GET_RANGE|HEAD|DELETE|COPY) NEEDS_OBJECTS=1 ;; esac
        if [[ "$NEEDS_OBJECTS" -eq 1 ]] && [[ $(registry_count "$REGISTRY_FILE") -eq 0 ]]; then
            OP="PUT_SINGLE"
        fi

        dispatch_op "$OP"
    done

    # Periodic status
    if (( CYCLE % 10 == 0 )); then
        echo "[$(date -Iseconds)] awscli cycle=$CYCLE objects=$(registry_count "$REGISTRY_FILE") seq=$_SEQ" >&2
    fi

    # GC
    gc_if_needed "$BUCKET" "$REGISTRY_FILE"

    # Random sleep
    random_sleep
done

echo "[$(date -Iseconds)] awscli stress workload exiting (seq=$_SEQ, objects=$(registry_count "$REGISTRY_FILE"))" >&2
