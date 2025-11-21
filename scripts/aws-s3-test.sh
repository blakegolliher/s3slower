#!/usr/bin/env bash
set -euo pipefail

### CONFIG #####################################################################

ITERATIONS="${1:-100}"                # how many operations to run

# Protocol selection:
#   - default: https
#   - override via 2nd CLI arg: ./aws-s3-test.sh 100 http
#   - or via PROTOCOL env var: PROTOCOL=http ./aws-s3-test.sh
PROTOCOL="${2:-${PROTOCOL:-https}}"
if [[ "${PROTOCOL}" != "http" && "${PROTOCOL}" != "https" ]]; then
  echo "ERROR: PROTOCOL must be 'http' or 'https' (got '${PROTOCOL}')" >&2
  exit 1
fi

ENDPOINT_HOST="${ENDPOINT_HOST:-main.selab-var204.selab.vastdata.com}"
# Allow full ENDPOINT override via env; otherwise build from PROTOCOL + host
ENDPOINT="${ENDPOINT:-${PROTOCOL}://${ENDPOINT_HOST}}"

BUCKET="s3slower-awscli"
PREFIX="s3slower-random"              # all test objects live under this prefix
AWS="aws --endpoint-url ${ENDPOINT} --no-verify-ssl"

TMPDIR="${TMPDIR:-/tmp}/s3rand"
KEY_TRACK_FILE="${TMPDIR}/keys.txt"   # local list of keys we’ve created
OPS_LOG="${OPS_LOG:-${TMPDIR}/aws-s3-ops.log}"  # per-operation log for correlation

SMALL_SIZE_MB=1                       # small PUT size
LARGE_SIZE_MB=64                      # large PUT size (triggers MPU in aws cli)

mkdir -p "${TMPDIR}"
touch "${KEY_TRACK_FILE}"
: > "${OPS_LOG}"

###############################################################################

log() {
  printf '%s %s\n' "$(date +'%F %T')" "$*" >&2
}

log_op() {
  # Structured per-operation log: epoch, protocol, op_name, http_method, bucket, target(key/prefix)
  local op_name="$1"
  local http_method="$2"
  local target="$3"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date +'%s')" "${PROTOCOL}" "${op_name}" "${http_method}" "${BUCKET}" "${target}" >> "${OPS_LOG}"
}

# Initialize key tracking file with existing objects in S3
init_existing_keys() {
  log "Initializing: listing existing objects in s3://${BUCKET}/${PREFIX}/"
  # Clear the key tracking file first
  > "${KEY_TRACK_FILE}"

  # List all existing objects and populate the tracking file
  ${AWS} s3api list-objects-v2 \
    --bucket "${BUCKET}" \
    --prefix "${PREFIX}/" \
    --query 'Contents[].Key' \
    --output text 2>/dev/null | tr '\t' '\n' | while read -r key; do
    if [ -n "${key}" ]; then
      echo "${key}" >> "${KEY_TRACK_FILE}"
    fi
  done

  local count=$(wc -l < "${KEY_TRACK_FILE}")
  log "Found ${count} existing objects"
}

random_key() {
  # random filename under the PREFIX
  printf '%s/file-%06d.bin\n' "${PREFIX}" "$((RANDOM % 1000000))"
}

add_key() {
  echo "$1" >> "${KEY_TRACK_FILE}"
}

pick_random_key() {
  # returns 0 with key on stdout if we have any; 1 if none
  if ! [ -s "${KEY_TRACK_FILE}" ]; then
    return 1
  fi
  mapfile -t KEYS < "${KEY_TRACK_FILE}"
  local count="${#KEYS[@]}"
  local idx=$((RANDOM % count))
  printf '%s\n' "${KEYS[$idx]}"
}

# Check if a key exists in S3
key_exists() {
  local key="$1"
  ${AWS} s3api head-object \
    --bucket "${BUCKET}" \
    --key "${key}" &>/dev/null
}

# Pick a random key that actually exists in S3
pick_existing_key() {
  local attempts=0
  local max_attempts=10
  local key

  while [ $attempts -lt $max_attempts ]; do
    if ! key="$(pick_random_key)"; then
      return 1  # No keys in tracking file
    fi

    if key_exists "$key"; then
      echo "$key"
      return 0
    fi

    ((attempts++))
  done

  # If we couldn't find an existing key after max attempts, return failure
  return 1
}

put_small() {
  # Check if we need to clean up first
  cleanup_if_needed

  local key
  key="$(random_key)"
  local file
  file="$(mktemp "${TMPDIR}/small-XXXXXX.bin")"

  log "PUT small: s3://${BUCKET}/${key} (${SMALL_SIZE_MB} MiB)"
  head -c "$((SMALL_SIZE_MB * 1024 * 1024))" /dev/urandom > "${file}"

  ${AWS} s3 cp "${file}" "s3://${BUCKET}/${key}" 2>&1 | grep -v "InsecureRequestWarning" || true
  add_key "${key}"
  log_op "PUT_SMALL" "PUT" "${key}"
  rm -f "${file}"
}

put_large_mpu() {
  # Check if we need to clean up first
  cleanup_if_needed

  local key
  key="$(random_key)"
  local file
  file="$(mktemp "${TMPDIR}/large-XXXXXX.bin")"

  log "PUT large/MPU: s3://${BUCKET}/${key} (${LARGE_SIZE_MB} MiB)"
  head -c "$((LARGE_SIZE_MB * 1024 * 1024))" /dev/urandom > "${file}"

  # aws cli will automatically use multipart upload for larger files
  ${AWS} s3 cp "${file}" "s3://${BUCKET}/${key}" 2>&1 | grep -v "InsecureRequestWarning" || true
  add_key "${key}"
  log_op "PUT_LARGE_MPU" "PUT" "${key}"
  rm -f "${file}"
}

get_full() {
  local key
  if ! key="$(pick_existing_key)"; then
    log "GET full: no existing keys found, skipping"
    return
  fi
  log "GET full: s3://${BUCKET}/${key}"
  ${AWS} s3 cp "s3://${BUCKET}/${key}" /dev/null 2>&1 | grep -v "warning: Skipping file /dev/null" || true
  log_op "GET_FULL" "GET" "${key}"
}

get_range() {
  local key
  if ! key="$(pick_existing_key)"; then
    log "GET range: no existing keys found, skipping"
    return
  fi
  log "GET range: s3://${BUCKET}/${key} (bytes 0-1MiB)"
  ${AWS} s3api get-object \
    --bucket "${BUCKET}" \
    --key "${key}" \
    --range "bytes=0-$((1024 * 1024 - 1))" \
    /dev/null >/dev/null
  log_op "GET_RANGE" "GET" "${key}"
}

list_prefix() {
  log "LIST: s3://${BUCKET}/${PREFIX}"
  ${AWS} s3 ls "s3://${BUCKET}/${PREFIX}" || true
  log_op "LIST_PREFIX" "GET" "${PREFIX}"
}

rm_object() {
  local key
  if ! key="$(pick_existing_key)"; then
    log "RM: no existing keys found, skipping"
    return
  fi
  log "RM: s3://${BUCKET}/${key}"
  ${AWS} s3 rm "s3://${BUCKET}/${key}" || true
  # Remove the key from tracking file
  grep -v "^${key}$" "${KEY_TRACK_FILE}" > "${KEY_TRACK_FILE}.tmp" && mv "${KEY_TRACK_FILE}.tmp" "${KEY_TRACK_FILE}" || true
  log_op "RM_OBJECT" "DELETE" "${key}"
}

# Clean up objects if we have too many
cleanup_if_needed() {
  local max_objects=100  # Maximum objects to keep
  local current_count=$(wc -l < "${KEY_TRACK_FILE}")

  if [ "${current_count}" -gt "${max_objects}" ]; then
    log "Cleanup: have ${current_count} objects, removing some to stay under ${max_objects}"
    local to_delete=$((current_count - max_objects + 10))  # Delete a few extra

    for ((i=0; i<to_delete; i++)); do
      rm_object
    done
  fi
}

###############################################################################

log "Starting random S3 ops against ${ENDPOINT}, bucket ${BUCKET}"
log "Running ${ITERATIONS} iterations"

# Initialize by listing existing objects
init_existing_keys

# If no objects exist, create a few to start with
if ! [ -s "${KEY_TRACK_FILE}" ]; then
  log "No existing objects found, creating initial objects..."
  for ((j=0; j<5; j++)); do
    put_small
  done
  log "Initial objects created"
fi

for ((i=1; i<=ITERATIONS; i++)); do
  # 0–5 → six operations
  op=$((RANDOM % 6))

  case "${op}" in
    0) put_small ;;
    1) put_large_mpu ;;
    2) get_full ;;
    3) get_range ;;
    4) list_prefix ;;
    5) rm_object ;;
  esac
done

log "Done."
