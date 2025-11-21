#!/usr/bin/env bash
set -e

LOG_DIR="/opt/s3slower"
CONFIG_DIR="/etc/s3slower"

mkdir -p "${LOG_DIR}"
chmod 750 "${LOG_DIR}" || true
mkdir -p "${CONFIG_DIR}"
