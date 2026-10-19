#!/usr/bin/env bash
# Periodic elbencho bursts for s3slower demos: alternates a small-object
# IOPS burst (4 KiB objects) with a large-object throughput burst (16 MiB
# objects), each writing, reading and deleting its objects. The first burst
# starts after a minute, then one every 3-7 minutes.
#
# Environment:
#   S3_ENDPOINT / ELBENCHO_ENDPOINT  endpoint URL (ELBENCHO_ENDPOINT wins; elbencho
#                                    has no option to skip TLS verification, so use
#                                    http:// for self-signed endpoints)
#   S3_BUCKET                        existing bucket (required)
#   S3_PREFIX                        key prefix (default s3slower-demo/elbencho)
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
#   BURST_THREADS                    elbencho threads (default 16)
set -uo pipefail

ENDPOINT="${ELBENCHO_ENDPOINT:-${S3_ENDPOINT:?set S3_ENDPOINT}}"
: "${S3_BUCKET:?set S3_BUCKET}"
: "${AWS_ACCESS_KEY_ID:?set AWS_ACCESS_KEY_ID}" "${AWS_SECRET_ACCESS_KEY:?set AWS_SECRET_ACCESS_KEY}"
PREFIX="${S3_PREFIX:-s3slower-demo/elbencho}"
THREADS="${BURST_THREADS:-16}"

AWS=(aws --endpoint-url "${S3_ENDPOINT:-$ENDPOINT}")
[[ "${NO_VERIFY_SSL:-0}" == 1 ]] && AWS+=(--no-verify-ssl)
LOG="$(mktemp)"

child=""
cleanup() {
    [[ -n "$child" ]] && kill "$child" 2>/dev/null && wait "$child" 2>/dev/null
    # Remove anything an interrupted burst left behind.
    PYTHONWARNINGS="ignore:Unverified HTTPS request" \
        "${AWS[@]}" s3 rm --recursive --only-show-errors "s3://$S3_BUCKET/$PREFIX/" || true
    rm -f "$LOG"
    exit 0
}
trap cleanup TERM INT

burst() { # name size files-per-thread
    echo "[$(date +%H:%M:%S)] burst: $1 ($THREADS threads x $3 x $2)"
    elbencho --s3endpoints "$ENDPOINT" --s3key "$AWS_ACCESS_KEY_ID" --s3secret "$AWS_SECRET_ACCESS_KEY" \
        --s3region "${AWS_DEFAULT_REGION:-us-east-1}" -w -r -F -t "$THREADS" -n 1 -N "$3" -s "$2" -b "$2" \
        --s3objprefix "$PREFIX/$1/" "$S3_BUCKET" > "$LOG" 2>&1 &
    child=$!
    wait "$child"
    child=""
    grep -E '^(WRITE|READ|RMOBJECTS) +(Elapsed|IOPS|Throughput)' "$LOG"
}

kind=0
pause=60 # first burst a minute in, then every 3-7 minutes
while true; do
    sleep "$pause" & child=$!; wait "$child"; child=""
    pause=$(( RANDOM % 240 + 180 ))
    if (( kind % 2 == 0 )); then burst iops 4k 2000; else burst throughput 16m 16; fi
    kind=$(( kind + 1 ))
done
