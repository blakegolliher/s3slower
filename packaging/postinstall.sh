#!/bin/sh
# Runs after install/upgrade on both RPM and DEB.
#   RPM: $1 == 1 on fresh install, 2 on upgrade.
#   DEB: $1 == configure; $2 is empty on fresh install, old version on upgrade.
# Only enable at boot on fresh installs so an admin's `systemctl disable`
# survives subsequent package upgrades.
systemctl daemon-reload

fresh_install=0
case "$1" in
    1) fresh_install=1 ;;
    configure) [ -z "${2:-}" ] && fresh_install=1 ;;
esac

if [ "$fresh_install" = "1" ]; then
    systemctl enable s3slower
fi

echo ""
echo "S3Slower has been installed."
echo ""
echo "To start the service now:"
echo "  sudo systemctl start s3slower"
echo ""
echo "Configuration: /etc/s3slower/s3slower.yaml"
echo "Log files:     /var/log/s3slower/"
echo ""
