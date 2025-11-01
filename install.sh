#!/bin/bash

INSTALL_DIR="/usr/local/bin"
LIB_DIR="/usr/local/lib/security-scan"
CONFIG_DIR="/etc/security-scan"
TOOL_NAME="security-scan"

echo "Starting Security Scan installation..."

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run with sudo. Please run 'sudo bash install.sh'" >&2
  exit 1
fi

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$LIB_DIR"
mkdir -p "$CONFIG_DIR"

# Copy config files
echo "Copying configuration files to $CONFIG_DIR..."
cp ./config/rules.txt "$CONFIG_DIR/rules.txt"
cp ./config/ignore.txt "$CONFIG_DIR/ignore.txt"

# Copy helper scripts to lib directory
echo "Copying helper scripts to $LIB_DIR..."
cp ./bin/json-to-md.sh "$LIB_DIR/json-to-md.sh"
cp ./bin/json-to-html.sh "$LIB_DIR/json-to-html.sh"
chmod +x "$LIB_DIR"/*.sh

# Copy main script and make it the CLI command
echo "Installing main command to $INSTALL_DIR/$TOOL_NAME..."
cp ./bin/scan.sh "$INSTALL_DIR/$TOOL_NAME"
chmod +x "$INSTALL_DIR/$TOOL_NAME"

# *** خطوة مهمة: تعديل السكربت المثبت ليعرف مكان ملفاته ***
# This line tells the installed script where to find its config and libs
sed -i "1a export SCAN_TOOL_DIR=\"$LIB_DIR\"\nexport SCAN_CONFIG_DIR=\"$CONFIG_DIR\"" "$INSTALL_DIR/$TOOL_NAME"


echo "============================================================"
echo "✅ Installation complete!"
echo "You can now run the tool from anywhere by typing: $TOOL_NAME -h"
echo "============================================================"
