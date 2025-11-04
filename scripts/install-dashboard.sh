#!/usr/bin/env bash
set -euo pipefail

BIN_NAME=wireshield-dashboard
PREFIX=/usr/local/bin
CONFIG_DIR=/etc/wireshield
SERVICE_FILE=/etc/systemd/system/wireshield-dashboard.service
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

if ! command -v go >/dev/null 2>&1; then
  echo "Go toolchain is required to build the dashboard. Install Go >=1.22 and re-run." >&2
  exit 1
fi

echo "Building dashboard..."
(cd "$REPO_ROOT/dashboard" && go build -o "$BIN_NAME" ./cmd/wireshield-dashboard)
install -m 0755 "$REPO_ROOT/dashboard/$BIN_NAME" "$PREFIX/$BIN_NAME"

mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/dashboard-config.json" ]]; then
  echo "Initializing config..."
  "$PREFIX/$BIN_NAME" -init-admin admin -init-admin-pass "$(openssl rand -hex 12)" -config "$CONFIG_DIR/dashboard-config.json"
  echo "Config written to $CONFIG_DIR/dashboard-config.json (default admin user: admin with random password). Please update password ASAP."
fi

install -m 0644 "$REPO_ROOT/dashboard/wireshield-dashboard.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable --now wireshield-dashboard

echo "Dashboard started on http://127.0.0.1:51821 (bind can be changed in config)."
