#!/bin/sh
systemctl stop s3slower 2>/dev/null || true
systemctl disable s3slower 2>/dev/null || true
