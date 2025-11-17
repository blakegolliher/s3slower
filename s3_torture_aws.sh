#!/usr/bin/env bash
#
# s3_torture_aws.sh
#
# Simple S3 “torture” / visibility test using aws CLI.
# Exercises PUT/GET/HEAD/LIST/DELETE (including multipart uploads)
# so s3slower-ssl.py can see a variety of HTTPS S3 operations.
#
# Env vars / args:
#   S3_ENDPOINT   - S3 endpoint URL (e.g. https://main.selab-var204.selab.vastdata.com)
#   S3_BUCKET     - Bucket name (required)
#   S3_PREFIX     - Prefix inside bucket (default: s3slower-test)
#   AWS_PROFILE   - AWS CLI profile (default: default)
#   ITERATIONS    - How many objects to put/get/head/list/delete (default: 20)
#
# Example:
#   export S3_ENDPOINT=https://main.selab-var204.selab.vastdata.com
#   export S3_BUCKET=s3-dest
#   export AWS_PROFILE=vast
#   ./s3_torture_aws.sh
#

set -euo pipefail

S3_ENDPOINT="${S3_ENDPOINT:-}"
S3_BUCKET="${S3_BUCKET:-}"
S3_PREFIX="${S3_PREFIX:-s3slower-test}"
AWS_PROFILE="${AWS_PROFILE:-default}"
ITERATIONS="${ITERATIONS:-20}"

# Sizes:  small (KB) and big (MB) for multipart
SMALL_SIZE_KB="${SMALL_SIZE_KB:-4}"    # tiny objects
BIG_SIZE_MB="${BIG_SIZE_MB:-64}"       # big enough for multipart uploads

if [[ -z "${S3_BUCKET}" ]]; then
  echo "ERROR: S3_BUCKET is not set." >&2
  echo "Usage: S3_BUCKET=mybucket [S3_ENDPOINT=...] [AWS_PROFILE=...] ./s3_torture_aws.sh" >&2
  exit 1
fi

AWS_BASE=(aws --profile "${AWS_PROFILE}")
if [[ -n "${S3_ENDPOINT}" ]]; then
  AWS_BASE+=(--endpoint-url "${S3_ENDPOINT}" --no-verify-ssl)
fi

echo "=== S3 torture test configuration ==="
echo "Bucket      : ${S3_BUCKET}"
echo "Prefix      : ${S3_PREFIX}"
echo "Endpoint    : ${S3_ENDPOINT:-<AWS default>}"
echo "Profile     : ${AWS_PROFILE}"
echo "Iterations  : ${ITERATIONS}"
echo "Small size  : ${SMALL_SIZE_KB} KB"
echo "Big size    : ${BIG_SIZE_MB} MB"
echo

TMPDIR="$(mktemp -d /tmp/s3torture.XXXXXX)"
trap 'rm -rf "${TMPDIR}"' EXIT

SMALL_FILE="${TMPDIR}/small.bin"
BIG_FILE="${TMPDIR}/big.bin"

echo "Creating test files in ${TMPDIR} ..."
# small
dd if=/dev/zero of="${SMALL_FILE}" bs=1K count="${SMALL_SIZE_KB}" status=none
# big (for multipart)
dd if=/dev/zero of="${BIG_FILE}" bs=1M count="${BIG_SIZE_MB}" status=none

echo "Small file: $(ls -lh "${SMALL_FILE}")"
echo "Big file  : $(ls -lh "${BIG_FILE}")"
echo

echo "Starting torture loop ..."
echo

for i in $(seq 1 "${ITERATIONS}"); do
  # Two keys: one small, one big
  SMALL_KEY="${S3_PREFIX}/small-${i}.bin"
  BIG_KEY="${S3_PREFIX}/big-${i}.bin"

  echo "---- Iteration ${i}/${ITERATIONS} ----"

  # PUT small
  echo "PUT small   : s3://${S3_BUCKET}/${SMALL_KEY}"
  "${AWS_BASE[@]}" s3 cp "${SMALL_FILE}" "s3://${S3_BUCKET}/${SMALL_KEY}" > /dev/null

  # HEAD small
  echo "HEAD small  : s3://${S3_BUCKET}/${SMALL_KEY}"
  "${AWS_BASE[@]}" s3api head-object --bucket "${S3_BUCKET}" --key "${SMALL_KEY}" > /dev/null

  # GET small
  echo "GET small   : s3://${S3_BUCKET}/${SMALL_KEY}"
  "${AWS_BASE[@]}" s3 cp "s3://${S3_BUCKET}/${SMALL_KEY}" "${TMPDIR}/small-${i}-dl.bin" > /dev/null

  # PUT big (this should use multipart in aws CLI)
  echo "PUT big     : s3://${S3_BUCKET}/${BIG_KEY}"
  "${AWS_BASE[@]}" s3 cp "${BIG_FILE}" "s3://${S3_BUCKET}/${BIG_KEY}" > /dev/null

  # HEAD big
  echo "HEAD big    : s3://${S3_BUCKET}/${BIG_KEY}"
  "${AWS_BASE[@]}" s3api head-object --bucket "${S3_BUCKET}" --key "${BIG_KEY}" > /dev/null

  # GET big
  echo "GET big     : s3://${S3_BUCKET}/${BIG_KEY}"
  "${AWS_BASE[@]}" s3 cp "s3://${S3_BUCKET}/${BIG_KEY}" "${TMPDIR}/big-${i}-dl.bin" > /dev/null

  # LIST prefix (aws s3)
  echo "LIST (s3)   : s3://${S3_BUCKET}/${S3_PREFIX}/"
  "${AWS_BASE[@]}" s3 ls "s3://${S3_BUCKET}/${S3_PREFIX}/" > /dev/null

  # LIST prefix (s3api list-objects-v2)
  echo "LIST (api)  : bucket=${S3_BUCKET}, prefix=${S3_PREFIX}/"
  "${AWS_BASE[@]}" s3api list-objects-v2 --bucket "${S3_BUCKET}" --prefix "${S3_PREFIX}/" --max-keys 10 > /dev/null

  # DELETE small
  echo "DEL small   : s3://${S3_BUCKET}/${SMALL_KEY}"
  "${AWS_BASE[@]}" s3 rm "s3://${S3_BUCKET}/${SMALL_KEY}" > /dev/null

  # DELETE big
  echo "DEL big     : s3://${S3_BUCKET}/${BIG_KEY}"
  "${AWS_BASE[@]}" s3 rm "s3://${S3_BUCKET}/${BIG_KEY}" > /dev/null

  echo
done

echo "Done. Objects should be cleaned up under prefix: s3://${S3_BUCKET}/${S3_PREFIX}/"

