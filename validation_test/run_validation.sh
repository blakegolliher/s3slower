#!/usr/bin/env bash
# run_validation.sh - E2E validation orchestrator for s3slower
#
# Runs controlled S3 workloads and validates s3slower captures them correctly.
#
# Requires: root (eBPF), aws cli, python3+boto3, s3slower binary, S3 endpoint
#
# Environment variables:
#   S3_ENDPOINT          - S3 endpoint URL (default: https://172.200.202.1)
#   AWS_ACCESS_KEY_ID    - AWS access key (required)
#   AWS_SECRET_ACCESS_KEY - AWS secret key (required)
#   S3SLOWER_BIN         - Path to s3slower binary (default: build/s3slower)
#   S3_NO_VERIFY_SSL     - Set to "true" to disable SSL verification (default: true)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
S3_ENDPOINT="${S3_ENDPOINT:-https://172.200.202.1}"
S3SLOWER_BIN="${S3SLOWER_BIN:-$PROJECT_DIR/build/s3slower}"
NO_VERIFY_SSL="${S3_NO_VERIFY_SSL:-true}"
TIMESTAMP=$(date +%s)
BUCKET_CLI="s3slower-e2e-${TIMESTAMP}-cli"
BUCKET_BOTO3="s3slower-e2e-${TIMESTAMP}-boto3"

# Create temp directory for outputs
TMPDIR=$(mktemp -d /tmp/s3slower-validation-XXXXX)
CAPTURE_FILE="$TMPDIR/s3slower_capture.jsonl"
STDERR_LOG="$TMPDIR/s3slower_stderr.log"
WORKLOAD_CLI="$TMPDIR/workload_awscli.jsonl"
WORKLOAD_BOTO3="$TMPDIR/workload_boto3.jsonl"
REPORT_FILE="$TMPDIR/validation_report.json"

S3SLOWER_PID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC}  $*" >&2; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Cleanup trap
cleanup() {
    local exit_code=$?
    info "Cleaning up..."

    # Stop s3slower
    if [ -n "$S3SLOWER_PID" ] && kill -0 "$S3SLOWER_PID" 2>/dev/null; then
        info "Stopping s3slower (PID $S3SLOWER_PID)..."
        kill -INT "$S3SLOWER_PID" 2>/dev/null || true
        wait "$S3SLOWER_PID" 2>/dev/null || true
    fi

    # Build ssl flag for cleanup
    local ssl_flag=""
    if [ "$NO_VERIFY_SSL" = "true" ]; then
        ssl_flag="--no-verify-ssl"
    fi

    # Abort any in-progress multipart uploads and force-remove buckets
    for bucket in "$BUCKET_CLI" "$BUCKET_BOTO3"; do
        # List and abort any in-progress multipart uploads
        local uploads
        uploads=$(aws --endpoint-url "$S3_ENDPOINT" $ssl_flag s3api list-multipart-uploads \
            --bucket "$bucket" 2>/dev/null | grep -o '"UploadId": *"[^"]*"' | cut -d'"' -f4) || true
        if [ -n "$uploads" ]; then
            # We need the key too - just try to remove the bucket forcefully
            warn "Aborting lingering multipart uploads in $bucket"
        fi

        # Force remove bucket and contents
        aws --endpoint-url "$S3_ENDPOINT" $ssl_flag s3 rb "s3://$bucket" --force 2>/dev/null || true
    done

    if [ $exit_code -eq 0 ]; then
        info "Output directory: $TMPDIR"
    else
        error "Validation failed. Output directory: $TMPDIR"
    fi

    exit $exit_code
}
trap cleanup EXIT

# -------------------------------------------------------------------
# Prerequisites check
# -------------------------------------------------------------------
check_prerequisites() {
    info "Checking prerequisites..."

    # Must be root
    if [ "$(id -u)" -ne 0 ]; then
        error "Must run as root (eBPF requires root privileges)"
        exit 1
    fi

    # AWS credentials
    if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
        error "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set"
        exit 1
    fi

    # aws cli
    if ! command -v aws &>/dev/null; then
        error "aws CLI not found. Install: pip install awscli"
        exit 1
    fi

    # python3
    if ! command -v python3 &>/dev/null; then
        error "python3 not found"
        exit 1
    fi

    # boto3
    if ! python3 -c "import boto3" 2>/dev/null; then
        error "boto3 not found. Install: pip install boto3"
        exit 1
    fi

    # s3slower binary
    if [ ! -x "$S3SLOWER_BIN" ]; then
        error "s3slower binary not found at $S3SLOWER_BIN (run 'make build' first)"
        exit 1
    fi

    # Endpoint reachable (allow self-signed certs)
    local host port
    host=$(echo "$S3_ENDPOINT" | sed -E 's|https?://||;s|:[0-9]+$||;s|/.*||')
    port=$(echo "$S3_ENDPOINT" | grep -oP ':\K[0-9]+' || echo "443")
    if ! timeout 5 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        error "S3 endpoint $S3_ENDPOINT is not reachable"
        exit 1
    fi

    info "All prerequisites OK"
    info "  Endpoint: $S3_ENDPOINT"
    info "  Binary:   $S3SLOWER_BIN"
    info "  Output:   $TMPDIR"
    info "  Buckets:  $BUCKET_CLI, $BUCKET_BOTO3"
}

# -------------------------------------------------------------------
# Main execution
# -------------------------------------------------------------------
main() {
    check_prerequisites

    # Start s3slower in JSON mode
    info "Starting s3slower..."
    $S3SLOWER_BIN run --output json --no-log --min-latency 0 > "$CAPTURE_FILE" 2>"$STDERR_LOG" &
    S3SLOWER_PID=$!
    info "s3slower started (PID $S3SLOWER_PID)"

    # Wait for probe attachment
    info "Waiting 3s for probe attachment..."
    sleep 3

    # Verify s3slower is still running
    if ! kill -0 "$S3SLOWER_PID" 2>/dev/null; then
        error "s3slower exited prematurely. Stderr:"
        cat "$STDERR_LOG" >&2
        exit 1
    fi

    # Build ssl flag for workloads
    local ssl_flag="true"
    if [ "$NO_VERIFY_SSL" = "true" ]; then
        ssl_flag="no-verify-ssl"
    fi

    # Run AWS CLI workload
    info "Running AWS CLI workload..."
    bash "$SCRIPT_DIR/s3_workload_awscli.sh" "$WORKLOAD_CLI" "$S3_ENDPOINT" "$BUCKET_CLI" "$ssl_flag"
    info "AWS CLI workload complete"

    # Small gap between workloads
    sleep 2

    # Run boto3 workload
    info "Running boto3 workload..."
    local boto3_ssl_flag=""
    if [ "$NO_VERIFY_SSL" = "true" ]; then
        boto3_ssl_flag="--no-verify-ssl"
    fi
    python3 "$SCRIPT_DIR/s3_workload_boto3.py" \
        --output "$WORKLOAD_BOTO3" \
        --endpoint "$S3_ENDPOINT" \
        --bucket "$BUCKET_BOTO3" \
        $boto3_ssl_flag
    info "Boto3 workload complete"

    # Wait for event drain
    info "Waiting 3s for event drain..."
    sleep 3

    # Stop s3slower
    info "Stopping s3slower..."
    kill -INT "$S3SLOWER_PID" 2>/dev/null || true
    wait "$S3SLOWER_PID" 2>/dev/null || true
    S3SLOWER_PID=""
    info "s3slower stopped"

    # Show capture stats
    local capture_lines
    capture_lines=$(wc -l < "$CAPTURE_FILE" 2>/dev/null || echo 0)
    info "Captured $capture_lines events"

    if [ "$capture_lines" -eq 0 ]; then
        error "No events captured! s3slower stderr:"
        cat "$STDERR_LOG" >&2
        exit 1
    fi

    # Run validator
    info "Running validator..."
    python3 "$SCRIPT_DIR/validate_capture.py" \
        --capture "$CAPTURE_FILE" \
        --workload "$WORKLOAD_CLI" "$WORKLOAD_BOTO3" \
        --output "$REPORT_FILE"
    local validator_exit=$?

    # Print report location
    info "Report: $REPORT_FILE"
    info "Capture: $CAPTURE_FILE"
    info "Stderr log: $STDERR_LOG"

    if [ $validator_exit -eq 0 ]; then
        info "VALIDATION PASSED"
    else
        error "VALIDATION FAILED"
    fi

    exit $validator_exit
}

main "$@"
