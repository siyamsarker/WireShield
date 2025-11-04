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

# Detect script path for the dashboard service
WS_SCRIPT_PATH="$REPO_ROOT/wireshield.sh"
if [[ ! -f "$WS_SCRIPT_PATH" ]]; then
  # Common fallback
  if [[ -f "/root/wireshield.sh" ]]; then WS_SCRIPT_PATH="/root/wireshield.sh"; fi
  if [[ -f "/usr/local/bin/wireshield.sh" ]]; then WS_SCRIPT_PATH="/usr/local/bin/wireshield.sh"; fi
fi

# Write unit with the detected WIRE_SHIELD_SCRIPT
cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=WireShield Web Dashboard
After=network.target

[Service]
Type=simple
User=root
Group=root
Environment=WIRE_SHIELD_SCRIPT=$WS_SCRIPT_PATH
ExecStart=/usr/local/bin/wireshield-dashboard -config /etc/wireshield/dashboard-config.json
Restart=on-failure
RestartSec=5s

# Hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now wireshield-dashboard

echo "Dashboard started on http://127.0.0.1:51821 (bind can be changed in config)."
