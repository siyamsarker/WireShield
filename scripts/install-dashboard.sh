#!/usr/bin/env bash
set -euo pipefail

BIN_NAME=wireshield-dashboard
PREFIX=/usr/local/bin
CONFIG_DIR=/etc/wireshield
SERVICE_FILE=/etc/systemd/system/wireshield-dashboard.service
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
OWNER_REPO="siyamsarker/WireShield"

detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) ARCH=amd64;;
    aarch64|arm64) ARCH=arm64;;
    armv7l|armv7) ARCH=armv7;;
    armv6l|armv6) ARCH=armv6;;
    i386|i686) ARCH=386;;
  esac
}

download_prebuilt() {
  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi
  detect_platform
  # Expect assets named with OS/ARCH; try to discover via GitHub API
  echo "Attempting to download prebuilt dashboard binary (${OS}/${ARCH})..."
  api_url="https://api.github.com/repos/${OWNER_REPO}/releases/latest"
  json=$(curl -fsSL "$api_url" || true)
  if [[ -z "$json" ]]; then
    return 1
  fi
  # Grep download URLs; prefer matches containing both OS and ARCH
  mapfile -t urls < <(printf "%s\n" "$json" | grep -oE '"browser_download_url"\s*:\s*"[^"]+"' | sed -E 's/.*:\s*"([^"]+)"/\1/' )
  candidate=""
  for u in "${urls[@]}"; do
    if [[ "$u" == *"${BIN_NAME}"* && "$u" == *"${OS}"* && "$u" == *"${ARCH}"* ]]; then
      candidate="$u"; break
    fi
  done
  # Fallback: first url containing binary name
  if [[ -z "$candidate" ]]; then
    for u in "${urls[@]}"; do
      if [[ "$u" == *"${BIN_NAME}"* ]]; then candidate="$u"; break; fi
    done
  fi
  [[ -z "$candidate" ]] && return 1

  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  file="$tmpdir/asset"
  echo "Downloading: $candidate"
  curl -fsSL "$candidate" -o "$file"
  # If it's an archive, try to extract; else assume it's the binary
  if file "$file" 2>/dev/null | grep -qiE 'gzip|tar'; then
    tar -xzf "$file" -C "$tmpdir" || true
    # find binary
    found=$(find "$tmpdir" -type f -name "$BIN_NAME" | head -n1 || true)
    if [[ -n "$found" ]]; then file="$found"; fi
  fi
  if [[ ! -s "$file" ]]; then
    return 1
  fi
  install -m 0755 "$file" "$PREFIX/$BIN_NAME"
}

build_from_source() {
  if ! command -v go >/dev/null 2>&1; then
    return 1
  fi
  echo "Building dashboard from source..."
  (cd "$REPO_ROOT/dashboard" && go build -o "$BIN_NAME" ./cmd/wireshield-dashboard)
  install -m 0755 "$REPO_ROOT/dashboard/$BIN_NAME" "$PREFIX/$BIN_NAME"
}

# Try prebuilt first; fallback to build if Go is present
if ! download_prebuilt; then
  if ! build_from_source; then
    echo "Failed to install dashboard: no prebuilt binary found and Go toolchain not available." >&2
    echo "Options:" >&2
    echo "  - Install Go >=1.22 and re-run this installer" >&2
    echo "  - Or place a prebuilt '${BIN_NAME}' at ${PREFIX}/${BIN_NAME} and re-run" >&2
    exit 1
  fi
fi

mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/dashboard-config.json" ]]; then
  echo "Initializing config..."
  randpw=$(openssl rand -hex 12 2>/dev/null || head -c 12 /dev/urandom | hexdump -v -e '/1 "%02x"')
  "$PREFIX/$BIN_NAME" -init-admin admin -init-admin-pass "$randpw" -config "$CONFIG_DIR/dashboard-config.json"
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
