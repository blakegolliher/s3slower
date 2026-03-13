#!/bin/sh
# $1 == 0 means full removal; $1 == 1 means upgrade (don't disable)
if [ "$1" = "0" ]; then
    systemctl stop s3slower 2>/dev/null || true
    systemctl disable s3slower 2>/dev/null || true
fi
