#!/bin/sh
systemctl daemon-reload
# On upgrade ($1 == 1), restart the service with the new binary
if [ "$1" = "1" ]; then
    systemctl try-restart s3slower 2>/dev/null || true
fi
