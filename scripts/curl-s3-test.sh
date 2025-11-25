#!/usr/bin/env bash
set -euo pipefail

# Generate S3 traffic using curl with SigV4 signing (no presign step).
# Logs operations to OPS_LOG for correlation with s3slower.

ITERATIONS="${1:-50}"
# Force defaults even if the env var is set but empty
: "${PROTOCOL:=https}"         # http or https
: "${ENDPOINT_HOST:=main.selab-var204.selab.vastdata.com}"
: "${AWS_REGION:=us-east-1}"
: "${BUCKET:=s3slower-curl}"
: "${PREFIX:=s3slower-curl}"

TMPDIR="${TMPDIR:-/tmp}/s3curl"
KEY_TRACK_FILE="${TMPDIR}/keys.txt"
OPS_LOG="${OPS_LOG:-${TMPDIR}/curl-ops.log}"

# curl flags: force HTTP/1.1 so s3slower's HTTP parser can see requests; override if needed
CURL_FLAGS="${CURL_FLAGS:---insecure --silent --show-error --http1.1}"

mkdir -p "${TMPDIR}"
: > "${KEY_TRACK_FILE}"
: > "${OPS_LOG}"

log() { printf '%s %s\n' "$(date +'%F %T')" "$*" >&2; }

log_op() {
  local op_name="$1" method="$2" target="$3"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date +'%s')" "${PROTOCOL}" "${op_name}" "${method}" "${BUCKET}" "${target}" >> "${OPS_LOG}"
}

require_creds() {
  if [[ -z "${AWS_ACCESS_KEY_ID:-}" || -z "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
    echo "ERROR: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set for curl SigV4" >&2
    exit 1
  fi
}

urlencode() {
  python3 -c 'import sys, urllib.parse; s = sys.stdin.read().strip(); print(urllib.parse.quote(s, safe="/"))'
}

base_url() { printf '%s://%s' "${PROTOCOL}" "${ENDPOINT_HOST}"; }

object_url() {
  local key="$1"
  local enc
  # Key already contains bucket prefix, so don't add bucket again
  enc="$(echo -n "${key}" | urlencode)"
  printf '%s/%s' "$(base_url)" "${enc}"
}

list_url() {
  local enc_prefix
  enc_prefix="$(printf '%s/' "${PREFIX}" | urlencode)"
  printf '%s/%s?list-type=2&prefix=%s&encoding-type=url' "$(base_url)" "${BUCKET}" "${enc_prefix}"
}

signed_curl() {
  # Common curl args for SigV4
  local url="$1"; shift
  local extra_headers=()
  if [[ -n "${AWS_SESSION_TOKEN:-}" ]]; then
    extra_headers+=( -H "x-amz-security-token: ${AWS_SESSION_TOKEN}" )
  fi
  curl ${CURL_FLAGS} \
    --aws-sigv4 "aws:amz:${AWS_REGION}:s3" \
    --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
    "${extra_headers[@]}" \
    "$@" \
    -o /dev/null \
    "${url}" || true
}

random_key() { printf '%s/file-%06d.bin' "${PREFIX}" "$((RANDOM % 1000000))"; }

add_key() { echo "$1" >> "${KEY_TRACK_FILE}"; }

pick_random_key() {
  if ! [ -s "${KEY_TRACK_FILE}" ]; then return 1; fi
  mapfile -t KEYS < "${KEY_TRACK_FILE}"
  local idx=$((RANDOM % ${#KEYS[@]}))
  printf '%s\n' "${KEYS[$idx]}"
}

cleanup_if_needed() {
  local max_objects=100
  local current_count
  current_count=$(wc -l < "${KEY_TRACK_FILE}")
  if [ "${current_count}" -gt "${max_objects}" ]; then
    log "Cleanup: trimming ${current_count} objects"
    local to_delete=$((current_count - max_objects + 10))
    for ((i=0; i<to_delete; i++)); do
      delete_object || true
    done
  fi
}

put_small() {
  cleanup_if_needed
  local key file basename_key
  file="$(mktemp "${TMPDIR}/curl-put-XXXX.bin")"
  basename_key="$(basename "${file}")"
  key="${PREFIX}/${basename_key}"
  head -c $((1 * 1024 * 1024)) /dev/urandom > "${file}"
  local url
  url="$(object_url "${key}")"
  if [[ -z "${key}" ]]; then
    log "WARN: empty key, skipping PUT"
    rm -f "${file}"
    return
  fi
  signed_curl "${url}" -X PUT -T "${file}"
  add_key "${key}"
  log_op "PUT_SMALL" "PUT" "${key}"
  rm -f "${file}"
}

get_full() {
  local key
  if ! key="$(pick_random_key)"; then
    log "GET: no keys yet"
    return
  fi
  local url
  url="$(object_url "${key}")"
  if [[ -z "${key}" ]]; then
    log "WARN: empty key, skipping GET"
    return
  fi
  signed_curl "${url}" -X GET -o /dev/null
  log_op "GET_FULL" "GET" "${key}"
}

get_range() {
  local key
  if ! key="$(pick_random_key)"; then
    log "RANGE: no keys yet"
    return
  fi
  local url
  url="$(object_url "${key}")"
  if [[ -z "${key}" ]]; then
    log "WARN: empty key, skipping RANGE"
    return
  fi
  signed_curl "${url}" -X GET -H "Range: bytes=0-1048575" -o /dev/null
  log_op "GET_RANGE" "GET" "${key}"
}

head_object() {
  local key
  if ! key="$(pick_random_key)"; then
    log "HEAD: no keys yet"
    return
  fi
  local url
  url="$(object_url "${key}")"
  if [[ -z "${key}" ]]; then
    log "WARN: empty key, skipping HEAD"
    return
  fi
  signed_curl "${url}" -I >/dev/null
  log_op "HEAD_OBJECT" "HEAD" "${key}"
}

delete_object() {
  local key
  if ! key="$(pick_random_key)"; then
    log "DEL: no keys yet"
    return
  fi
  local url
  url="$(object_url "${key}")"
  if [[ -z "${key}" ]]; then
    log "WARN: empty key, skipping DELETE"
    return
  fi
  signed_curl "${url}" -X DELETE
  grep -v "^${key}$" "${KEY_TRACK_FILE}" > "${KEY_TRACK_FILE}.tmp" && mv "${KEY_TRACK_FILE}.tmp" "${KEY_TRACK_FILE}" || true
  log_op "DELETE_OBJECT" "DELETE" "${key}"
}

list_prefix() {
  local url
  url="$(list_url)"
  signed_curl "${url}" -X GET >/dev/null
  log_op "LIST_PREFIX" "GET" "${PREFIX}"
}

require_creds
log "Starting curl S3 ops against ${PROTOCOL}://${ENDPOINT_HOST}, bucket ${BUCKET}"
log "Prefix=${PREFIX} ; Running ${ITERATIONS} iterations"

# Pre-warm: Do a dummy operation to trigger s3slower attachment before we start logging
log "Pre-warming s3slower attachment..."
curl ${CURL_FLAGS} \
    --aws-sigv4 "aws:amz:${AWS_REGION}:s3" \
    --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
    -X GET \
    "${PROTOCOL}://${ENDPOINT_HOST}/${BUCKET}?list-type=2" \
    -o /dev/null 2>/dev/null || true
sleep 1
log "Pre-warming complete, starting actual test..."

if ! [ -s "${KEY_TRACK_FILE}" ]; then
  log "No existing keys, seeding with a few PUTs"
  for ((i=0; i<5; i++)); do
    put_small
  done
fi

for ((i=1; i<=ITERATIONS; i++)); do
  op=$((RANDOM % 6))
  case "${op}" in
    0) put_small ;;
    1) get_full ;;
    2) get_range ;;
    3) head_object ;;
    4) delete_object ;;
    5) list_prefix ;;
  esac
done

log "Done. Ops log: ${OPS_LOG}"
