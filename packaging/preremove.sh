#!/bin/sh
# Runs before uninstall on both RPM and DEB.
#   RPM: $1 == 0 on full removal, 1 on upgrade.
#   DEB: $1 == remove|purge on full removal, upgrade|deconfigure on upgrade.
# Stop and disable only on full removal.
case "$1" in
    0|remove|purge)
        systemctl stop s3slower 2>/dev/null || true
        systemctl disable s3slower 2>/dev/null || true
        ;;
esac
