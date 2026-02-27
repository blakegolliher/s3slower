#!/bin/sh
systemctl daemon-reload
echo ""
echo "S3Slower has been installed."
echo ""
echo "To start the service:"
echo "  sudo systemctl start s3slower"
echo ""
echo "To enable at boot:"
echo "  sudo systemctl enable s3slower"
echo ""
echo "Configuration: /etc/s3slower/s3slower.yaml"
echo ""
