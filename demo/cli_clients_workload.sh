#!/usr/bin/env bash
# S3 traffic from other client binaries, so each shows up as its own client
# on the s3slower dashboard. Loops until stopped, pausing 20-60 s between
# iterations.
#
# Usage: demo/cli_clients_workload.sh s5cmd|mc|rclone|curl
#
#   s5cmd   parallel PUT of many small files, LIST, parallel GET, cat, batch DELETE
#   mc      recursive copy, multipart upload, LIST, stat (HEAD), cat (GET), rm
#   rclone  copy up (HEAD + PUT), LIST, copy down (GET), delete
#   curl    SigV4-signed PUT, GET, ranged GET, HEAD, LIST, DELETE, GET of a missing key
#
# Environment:
#   S3_ENDPOINT, S3_BUCKET, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (required)
#   S3_PREFIX      key prefix (default s3slower-demo/<client>)
#   NO_VERIFY_SSL  1 to skip TLS certificate verification
#   DEMO_BIN_DIR   where s5cmd/mc/rclone live if not on PATH (default build/demo-bin)
set -uo pipefail

TOOL="${1:?usage: $0 s5cmd|mc|rclone|curl}"
: "${S3_ENDPOINT:?set S3_ENDPOINT}" "${S3_BUCKET:?set S3_BUCKET}"
: "${AWS_ACCESS_KEY_ID:?set AWS_ACCESS_KEY_ID}" "${AWS_SECRET_ACCESS_KEY:?set AWS_SECRET_ACCESS_KEY}"
PREFIX="${S3_PREFIX:-s3slower-demo/$TOOL}"
BIN_DIR="${DEMO_BIN_DIR:-$(dirname "$0")/../build/demo-bin}"
INSECURE="${NO_VERIFY_SSL:-0}"
HOSTPORT="${S3_ENDPOINT#*://}"
SCHEME="${S3_ENDPOINT%%://*}"

find_bin() { command -v "$1" 2>/dev/null || { [[ -x "$BIN_DIR/$1/$1" ]] && echo "$BIN_DIR/$1/$1"; }; }
EXE="$(find_bin "$TOOL")" || { echo "$TOOL not found on PATH or in $BIN_DIR"; exit 1; }

WORK="$(mktemp -d)"
mkdir -p "$WORK/up" "$WORK/down"
for i in $(seq -f "%04g" 1 40); do head -c "$(( (RANDOM % 512 + 4) * 1024 ))" /dev/urandom > "$WORK/up/file-$i.bin"; done
head -c $(( 48 * 1024 * 1024 )) /dev/urandom > "$WORK/large.bin"

log() { echo "[$(date +%H:%M:%S)] $TOOL: $*"; }

# ---- per-tool configuration ----
case "$TOOL" in
    s5cmd)
        S5=("$EXE" --endpoint-url "$S3_ENDPOINT")
        [[ "$INSECURE" == 1 ]] && S5+=(--no-verify-ssl)
        ;;
    mc)
        export MC_HOST_demo="$SCHEME://$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY@$HOSTPORT"
        MC=("$EXE" --config-dir "$WORK/mc" --quiet)
        [[ "$INSECURE" == 1 ]] && MC+=(--insecure)
        ;;
    rclone)
        export RCLONE_CONFIG_DEMO_TYPE=s3 RCLONE_CONFIG_DEMO_PROVIDER=Other \
            RCLONE_CONFIG_DEMO_ENDPOINT="$S3_ENDPOINT" RCLONE_CONFIG_DEMO_FORCE_PATH_STYLE=true \
            RCLONE_CONFIG_DEMO_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
            RCLONE_CONFIG_DEMO_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
        RC=("$EXE" --config /dev/null -q)
        [[ "$INSECURE" == 1 ]] && RC+=(--no-check-certificate)
        ;;
    curl)
        CU=("$EXE" -sS -o /dev/null -w "%{http_code} " --aws-sigv4 "aws:amz:${AWS_DEFAULT_REGION:-us-east-1}:s3"
            --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY")
        [[ "$INSECURE" == 1 ]] && CU+=(-k)
        URL="$S3_ENDPOINT/$S3_BUCKET/$PREFIX"
        ;;
    *) echo "unknown client: $TOOL"; exit 2 ;;
esac

remove_all() {
    case "$TOOL" in
        s5cmd) "${S5[@]}" rm "s3://$S3_BUCKET/$PREFIX/*" > /dev/null 2>&1 ;;
        mc) "${MC[@]}" rm --recursive --force "demo/$S3_BUCKET/$PREFIX/" > /dev/null 2>&1 ;;
        rclone) "${RC[@]}" delete "demo:$S3_BUCKET/$PREFIX" 2>/dev/null ;;
        curl) for f in "$WORK"/up/*; do "${CU[@]}" -X DELETE "$URL/$(basename "$f")" > /dev/null; done ;;
    esac
}

child=""
cleanup() {
    [[ -n "$child" ]] && kill "$child" 2>/dev/null
    remove_all
    rm -rf "$WORK"
    exit 0
}
trap cleanup TERM INT

iteration() {
    case "$TOOL" in
        s5cmd)
            log "upload 40 files"; "${S5[@]}" --numworkers 16 cp "$WORK/up/*" "s3://$S3_BUCKET/$PREFIX/" > /dev/null
            log "list"; "${S5[@]}" ls "s3://$S3_BUCKET/$PREFIX/*" > /dev/null
            log "download"; rm -rf "$WORK/down"/*; "${S5[@]}" --numworkers 16 cp "s3://$S3_BUCKET/$PREFIX/*" "$WORK/down/" > /dev/null
            log "cat"; "${S5[@]}" cat "s3://$S3_BUCKET/$PREFIX/file-0001.bin" > /dev/null
            log "large upload"; "${S5[@]}" cp "$WORK/large.bin" "s3://$S3_BUCKET/$PREFIX/large.bin" > /dev/null
            log "batch delete"; "${S5[@]}" rm "s3://$S3_BUCKET/$PREFIX/*" > /dev/null
            ;;
        mc)
            log "recursive copy"; "${MC[@]}" cp --recursive "$WORK/up/" "demo/$S3_BUCKET/$PREFIX/" > /dev/null
            log "multipart upload"; "${MC[@]}" cp "$WORK/large.bin" "demo/$S3_BUCKET/$PREFIX/large.bin" > /dev/null
            log "list"; "${MC[@]}" ls --recursive "demo/$S3_BUCKET/$PREFIX/" > /dev/null
            log "stat + cat"
            for i in 0001 0002 0003 0004 0005; do
                "${MC[@]}" stat "demo/$S3_BUCKET/$PREFIX/file-$i.bin" > /dev/null
                "${MC[@]}" cat "demo/$S3_BUCKET/$PREFIX/file-$i.bin" > /dev/null
            done
            "${MC[@]}" stat "demo/$S3_BUCKET/$PREFIX/missing.bin" > /dev/null 2>&1
            log "remove"; "${MC[@]}" rm --recursive --force "demo/$S3_BUCKET/$PREFIX/" > /dev/null
            ;;
        rclone)
            log "copy up"; "${RC[@]}" copy --transfers 8 "$WORK/up" "demo:$S3_BUCKET/$PREFIX"
            log "list"; "${RC[@]}" lsf "demo:$S3_BUCKET/$PREFIX" > /dev/null
            log "copy down"; rm -rf "$WORK/down"/*; "${RC[@]}" copy --transfers 8 "demo:$S3_BUCKET/$PREFIX" "$WORK/down"
            log "delete"; "${RC[@]}" delete "demo:$S3_BUCKET/$PREFIX"
            ;;
        curl)
            log "put/get/range/head"
            for f in "$WORK"/up/file-000*.bin; do
                k="$(basename "$f")"
                "${CU[@]}" -T "$f" "$URL/$k"
                "${CU[@]}" "$URL/$k"
                "${CU[@]}" -r 0-4095 "$URL/$k"
                "${CU[@]}" -I "$URL/$k"
            done
            "${CU[@]}" "$S3_ENDPOINT/$S3_BUCKET?list-type=2&prefix=${PREFIX//\//%2F}%2F"
            "${CU[@]}" "$URL/missing.bin"
            log "delete"
            for f in "$WORK"/up/file-000*.bin; do "${CU[@]}" -X DELETE "$URL/$(basename "$f")"; done
            echo
            ;;
    esac
}

while true; do
    iteration
    sleep "$(( RANDOM % 40 + 20 ))" & child=$!; wait "$child"; child=""
done
