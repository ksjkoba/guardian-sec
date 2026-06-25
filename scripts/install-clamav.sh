#!/usr/bin/env bash
# Install ClamAV for local file scanning (WSL/Ubuntu)
set -euo pipefail
echo "Installing ClamAV..."
sudo apt-get update
sudo apt-get install -y clamav clamav-daemon
echo "Updating virus definitions (may take a few minutes)..."
sudo freshclam || echo "freshclam failed — try: sudo systemctl stop clamav-freshclam && sudo freshclam"
echo ""
echo "Done. Test with: clamscan --version"
echo "Guardian file scan: Threat Feed → Scan file"
