#!/usr/bin/env bash
set -euo pipefail

# WireShield unified installer
# - Detect latest release
# - Verify checksum
# - Install dashboard binary + script
# - Configure systemd services atomically
# - Idempotent re-runs

REPO="siyamsarker/WireShield"
API="https://api.github.com/repos/${REPO}/releases/latest"
TMP_DIR="/tmp/wireshield-install"
INSTALL_BIN="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"
DASHBOARD_SERVICE="wireshield-dashboard.service"
SCRIPT_NAME="wireshield.sh"

color() { printf "\033[%sm%s\033[0m\n" "$1" "$2"; }
info() { color "36" "[info] $*"; }
success() { color "32" "[ok] $*"; }
warn() { color "33" "[warn] $*"; }
error() { color "31" "[error] $*"; }

require_root() {
  if [ "${EUID}" -ne 0 ]; then
    error "Run as root (sudo)"; exit 1; fi
}

fetch_latest() {
  info "Resolving latest release..."
  if curl -fsSL "$API" >"${TMP_DIR}/latest.json"; then
    VERSION=$(jq -r .tag_name <"${TMP_DIR}/latest.json" 2>/dev/null || true)
  else
    VERSION=""
  fi
  if [ -z "${VERSION}" ] || [ "${VERSION}" = "null" ]; then
    warn "No GitHub release found (or API unavailable). Falling back to source install."
    VERSION="source"
  else
    success "Latest version: ${VERSION}"
  fi
}

select_archive() {
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) GOARCH="amd64" ;;
    aarch64|arm64) GOARCH="arm64" ;;
    *) error "Unsupported architecture: $ARCH"; exit 1 ;;
  esac
  FILE="wireshield-dashboard_${VERSION}_linux_${GOARCH}.tar.gz"
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILE}"
  CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/wireshield_checksums_${VERSION}.txt"
}

verify_checksum() {
  info "Verifying checksum..."
  curl -fsSL "$CHECKSUM_URL" -o "${TMP_DIR}/checksums.txt" || { error "Could not download checksums"; exit 1; }
  grep "${FILE}" "${TMP_DIR}/checksums.txt" | sha256sum -c - || { error "Checksum mismatch"; exit 1; }
  success "Checksum verified"
}

extract_archive() {
  tar -xf "${TMP_DIR}/${FILE}" -C "${TMP_DIR}" || { error "Extraction failed"; exit 1; }
}

install_files() {
  install -m 0755 "${TMP_DIR}/wireshield-dashboard" "${INSTALL_BIN}/wireshield-dashboard"
  install -m 0755 "${TMP_DIR}/${SCRIPT_NAME}" "${INSTALL_BIN}/${SCRIPT_NAME}"
  # Keep root copy as fallback
  install -m 0755 "${TMP_DIR}/${SCRIPT_NAME}" "/root/${SCRIPT_NAME}"
  success "Binaries installed"
}

setup_service() {
  info "Configuring dashboard systemd service..."
  local SCRIPT_PATH="${INSTALL_BIN}/${SCRIPT_NAME}"
  if [ ! -f "$SCRIPT_PATH" ]; then SCRIPT_PATH="/root/${SCRIPT_NAME}"; fi
  cat >"${SERVICE_DIR}/${DASHBOARD_SERVICE}" <<EOF
[Unit]
Description=WireShield Dashboard Service
After=network.target

[Service]
Type=simple
Environment=WIRE_SHIELD_SCRIPT=${SCRIPT_PATH}
ExecStart=${INSTALL_BIN}/wireshield-dashboard -config /etc/wireshield/dashboard-config.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now wireshield-dashboard || warn "Dashboard failed to start; check logs"
  success "Service installed"
}

build_from_source() {
  info "Building from source (master branch)..."
  # Install minimal deps
  if ! command -v git >/dev/null 2>&1; then apt-get update -y && apt-get install -y git || true; fi
  if ! command -v go >/dev/null 2>&1; then
    warn "Go not found; attempting to install lightweight Go toolchain"
    GO_URL="https://go.dev/dl/go1.22.6.linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz"
    curl -fsSL "$GO_URL" -o "${TMP_DIR}/go.tgz" && tar -C /usr/local -xzf "${TMP_DIR}/go.tgz"
    export PATH=/usr/local/go/bin:$PATH
  fi
  WORKDIR="${TMP_DIR}/src"
  git clone --depth=1 https://github.com/${REPO}.git "$WORKDIR"
  (cd "$WORKDIR" && CGO_ENABLED=0 go build -o wireshield-dashboard ./cmd/wireshield-dashboard)
  install -m 0755 "$WORKDIR/wireshield.sh" "${INSTALL_BIN}/wireshield.sh"
  install -m 0755 "$WORKDIR/wireshield.sh" "/root/wireshield.sh"
  install -m 0755 "$WORKDIR/wireshield-dashboard" "${INSTALL_BIN}/wireshield-dashboard"
}

main() {
  require_root
  mkdir -p "$TMP_DIR"
  fetch_latest
  if [ "$VERSION" = "source" ]; then
    build_from_source
  else
    select_archive
    info "Downloading archive ${FILE}";
    curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${FILE}" || { error "Download failed"; exit 1; }
    verify_checksum
    extract_archive
    install_files
  fi
  setup_service
  success "WireShield installation complete (version ${VERSION})."
  echo "Upgrade: rerun this script to move to latest release."
}

main "$@"
