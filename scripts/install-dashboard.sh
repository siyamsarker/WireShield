#!/usr/bin/env bash
set -euo pipefail

# Ensure running as root (re-exec with sudo if available)
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

BIN_NAME=wireshield-dashboard
PREFIX=/usr/local/bin
CONFIG_DIR=/etc/wireshield
SERVICE_FILE=/etc/systemd/system/wireshield-dashboard.service
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

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

install_go() {
  if command -v go >/dev/null 2>&1; then return 0; fi
  echo "Installing Go toolchain..."
  # Try distro package manager first
  if [[ -f /etc/os-release ]]; then . /etc/os-release; fi
  ID_LIKE=${ID_LIKE:-}
  ID=${ID:-}
  PM=""
  if command -v apt-get >/dev/null 2>&1; then PM=apt-get; fi
  if command -v dnf >/dev/null 2>&1; then PM=dnf; fi
  if command -v yum >/dev/null 2>&1; then PM=yum; fi
  if command -v pacman >/dev/null 2>&1; then PM=pacman; fi
  if command -v apk >/dev/null 2>&1; then PM=apk; fi
  case "$PM" in
    apt-get)
      apt-get update -y && apt-get install -y golang || true;;
    dnf)
      dnf install -y golang || true;;
    yum)
      yum install -y golang || true;;
    pacman)
      pacman -Sy --noconfirm go || true;;
    apk)
      apk add --no-cache go || true;;
  esac
  if command -v go >/dev/null 2>&1; then return 0; fi
  # Fallback: install from official tarball (linux only)
  detect_platform
  if [[ "$OS" != "linux" ]]; then
    echo "Unsupported OS for automatic Go install via tarball: $OS" >&2
    return 1
  fi
  GOV="1.22.0"
  case "$ARCH" in
    amd64) TAR="go${GOV}.linux-amd64.tar.gz";;
    arm64) TAR="go${GOV}.linux-arm64.tar.gz";;
    386) TAR="go${GOV}.linux-386.tar.gz";;
    *) echo "Unsupported ARCH for Go tarball: $ARCH"; return 1;;
  esac
  url="https://go.dev/dl/${TAR}"
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  echo "Downloading Go: $url"
  curl -fsSL "$url" -o "$tmpdir/go.tgz"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tmpdir/go.tgz"
  export PATH="/usr/local/go/bin:$PATH"
}

build_from_source() {
  if ! command -v go >/dev/null 2>&1; then
    install_go || return 1
  fi
  echo "Building dashboard from source..."
  (cd "$REPO_ROOT/dashboard" && go build -o "$BIN_NAME" ./cmd/wireshield-dashboard)
  install -m 0755 "$REPO_ROOT/dashboard/$BIN_NAME" "$PREFIX/$BIN_NAME"
}

# Always build from source; ensure Go is installed automatically
build_from_source || { echo "Failed to install dashboard." >&2; exit 1; }

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
