#!/bin/bash

# A simple script to install the Security Scan tool

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/security-scan"
TOOL_NAME="security-scan"

echo "Starting Security Scan installation..."

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run with sudo. Please run 'sudo bash install.sh'" >&2
  exit 1
fi

# Create config directory
echo "Creating configuration directory at $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"

# Copy rules and ignore files
echo "Copying configuration files..."
cp ./config/rules.txt "$CONFIG_DIR/rules.txt"
cp ./config/ignore.txt "$CONFIG_DIR/ignore.txt"

# Copy main script and make it executable
echo "Installing the main script to $INSTALL_DIR/$TOOL_NAME..."
cp ./bin/scan.sh "$INSTALL_DIR/$TOOL_NAME"
chmod +x "$INSTALL_DIR/$TOOL_NAME"

echo "============================================================"
echo "✅ Installation complete!"
echo "You can now run the tool from anywhere by typing: $TOOL_NAME"
echo ""
echo "Configuration files are located at: $CONFIG_DIR"
echo "============================================================"
