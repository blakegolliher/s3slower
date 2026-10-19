#!/usr/bin/env bash
# AI-pipeline-shaped S3 workload for s3slower demos (AWS CLI).
#
# Each iteration: sync dataset shards up (PUT), upload a checkpoint
# (multipart), list, download the dataset (GET), read shard footers
# (ranged GET), restore the checkpoint (parallel ranged GETs), HEAD
# existing and missing keys (404), then delete everything (DELETE).
#
# Usage:
#   S3_ENDPOINT=https://s3.example.com S3_BUCKET=my-bucket demo/awscli_workload.sh
#
# Environment:
#   S3_ENDPOINT     endpoint URL (required)
#   S3_BUCKET       existing bucket (required)
#   S3_PREFIX       key prefix (default s3slower-demo/awscli)
#   NO_VERIFY_SSL   1 to skip TLS certificate verification
#   ITERATIONS      iterations to run; 0 = until Ctrl-C (default 0)
#   SHARDS          dataset shards per iteration (default 50)
#   SHARD_KIB       shard size in KiB (default 512)
#   CKPT_MIB        checkpoint size in MiB (default 128; 8 MiB parts)
#   PAUSE           seconds to sleep between iterations (default 0)
# Credentials come from the standard AWS chain (env vars, AWS_PROFILE, ~/.aws).
set -euo pipefail

: "${S3_ENDPOINT:?set S3_ENDPOINT}"
: "${S3_BUCKET:?set S3_BUCKET}"
PREFIX="${S3_PREFIX:-s3slower-demo/awscli}"
ITERATIONS="${ITERATIONS:-0}"
SHARDS="${SHARDS:-50}"
SHARD_KIB="${SHARD_KIB:-512}"
CKPT_MIB="${CKPT_MIB:-128}"
PAUSE="${PAUSE:-0}"

AWS=(aws --endpoint-url "$S3_ENDPOINT")
if [[ "${NO_VERIFY_SSL:-0}" == 1 ]]; then
    AWS+=(--no-verify-ssl)
    export PYTHONWARNINGS="ignore:Unverified HTTPS request"
fi
DEST="s3://$S3_BUCKET/$PREFIX"

WORK="$(mktemp -d)"
cleanup() {
    rm -rf "$WORK"
    "${AWS[@]}" s3 rm --recursive --only-show-errors "$DEST/" || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

log() { echo "[$(date +%H:%M:%S)] $*"; }

log "generating $SHARDS x ${SHARD_KIB} KiB shards and a ${CKPT_MIB} MiB checkpoint in $WORK"
mkdir -p "$WORK/shards" "$WORK/download"
for i in $(seq -f "%05g" 1 "$SHARDS"); do
    head -c "$((SHARD_KIB * 1024))" /dev/urandom > "$WORK/shards/shard-$i.tar"
done
head -c "$((CKPT_MIB * 1024 * 1024))" /dev/urandom > "$WORK/ckpt.pt"

iter=0
while [[ "$ITERATIONS" == 0 || "$iter" -lt "$ITERATIONS" ]]; do
    log "iteration $iter: ingest (s3 sync -> PUT)"
    "${AWS[@]}" s3 sync --only-show-errors "$WORK/shards" "$DEST/data/"

    log "iteration $iter: checkpoint (s3 cp -> multipart upload)"
    "${AWS[@]}" s3 cp --only-show-errors "$WORK/ckpt.pt" "$DEST/ckpt/model.pt"

    log "iteration $iter: list"
    "${AWS[@]}" s3 ls --recursive "$DEST/" > /dev/null

    log "iteration $iter: load (s3 cp --recursive -> GET)"
    "${AWS[@]}" s3 cp --only-show-errors --recursive "$DEST/data/" "$WORK/download/"

    log "iteration $iter: footer reads (s3api get-object --range)"
    for i in $(seq -f "%05g" 1 "$(( SHARDS < 5 ? SHARDS : 5 ))"); do
        "${AWS[@]}" s3api get-object --bucket "$S3_BUCKET" --key "$PREFIX/data/shard-$i.tar" \
            --range bytes=-8192 /dev/null > /dev/null
    done

    log "iteration $iter: restore (s3 cp -> HEAD + parallel ranged GETs)"
    "${AWS[@]}" s3 cp --only-show-errors "$DEST/ckpt/model.pt" "$WORK/restore.pt"

    log "iteration $iter: head (existing + missing)"
    "${AWS[@]}" s3api head-object --bucket "$S3_BUCKET" --key "$PREFIX/ckpt/model.pt" > /dev/null
    "${AWS[@]}" s3api head-object --bucket "$S3_BUCKET" --key "$PREFIX/ckpt/missing.pt" \
        > /dev/null 2>&1 || true

    log "iteration $iter: cleanup (s3 rm --recursive -> DELETE)"
    "${AWS[@]}" s3 rm --recursive --only-show-errors "$DEST/"
    rm -rf "$WORK/download"/* "$WORK/restore.pt"

    iter=$((iter + 1))
    if [[ "$PAUSE" != 0 ]]; then sleep "$PAUSE"; fi
done
