#!/bin/sh
systemctl daemon-reload
systemctl enable s3slower

echo ""
echo "S3Slower has been installed and enabled at boot."
echo ""
echo "To start the service now:"
echo "  sudo systemctl start s3slower"
echo ""
echo "Configuration: /etc/s3slower/s3slower.yaml"
echo "Log files:     /var/log/s3slower/"
echo ""
