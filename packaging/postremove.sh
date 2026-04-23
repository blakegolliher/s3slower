#!/bin/sh
# Runs after uninstall/upgrade on both RPM and DEB.
#   RPM: $1 == 0 on full removal, 1 on upgrade.
#   DEB: $1 == remove|purge on full removal, upgrade|abort-upgrade on upgrade.
# On upgrade, restart the service with the new binary.
systemctl daemon-reload
case "$1" in
    1|upgrade|abort-upgrade)
        systemctl try-restart s3slower 2>/dev/null || true
        ;;
esac
