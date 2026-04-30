#!/usr/bin/env bash
# WireShield Agent installer (Go binary)
#
# Usage:
#   curl -sSL https://VPN_HOST/api/agents/install-go | \
#     TOKEN=<single-use-token> WIRESHIELD_SERVER=https://VPN_HOST bash
#
# Optional env overrides:
#   AGENT_LAN_IF=eth1              override auto-detected LAN interface
#   AGENT_CIDRS=10.50.0.0/24,...   agent-declared LAN CIDRs
#   AGENT_VERSION=1.0.0            specific release to pin (defaults: latest)
#   AGENT_INSECURE_TLS=1           skip TLS verification on enroll call
#   SKIP_CHECKSUM=1                bypass binary sha256 check (lab use only — NOT recommended)
#
# Exit codes:
#   0  success
#   1  usage/env error
#   2  network or server error during download/enrollment
#   3  WireGuard/systemd failure after enrollment

set -euo pipefail

die() { echo "[wireshield-agent installer] ERROR: $*" >&2; exit "${2:-1}"; }
info() { echo "[wireshield-agent installer] $*"; }

[[ $EUID -eq 0 ]] || die "must run as root" 1
: "${TOKEN:?TOKEN env var is required (set by admin via 'POST /api/console/agents')}"
: "${WIRESHIELD_SERVER:?WIRESHIELD_SERVER env var is required (e.g. https://vpn.example.com)}"

# Strip trailing slashes from server URL so URL join below doesn't produce //.
SERVER="${WIRESHIELD_SERVER%/}"

# Detect architecture. We ship linux-amd64 and linux-arm64 (see agent/Makefile).
case "$(uname -m)" in
  x86_64)  ARCH="linux-amd64" ;;
  aarch64) ARCH="linux-arm64" ;;
  arm64)   ARCH="linux-arm64" ;;
  *)       die "unsupported architecture: $(uname -m)" 1 ;;
esac

# Install required tools. We need wg (wireguard-tools), curl, systemctl.
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends wireguard-tools curl iproute2 ca-certificates >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y wireguard-tools curl iproute ca-certificates >/dev/null
elif command -v yum >/dev/null 2>&1; then
  yum install -y wireguard-tools curl iproute ca-certificates >/dev/null
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm wireguard-tools curl iproute2 ca-certificates >/dev/null
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache wireguard-tools curl iproute2 ca-certificates >/dev/null
else
  die "unsupported package manager; install wireguard-tools + curl manually then retry" 1
fi

# Download binary. The server may pin a specific version via AGENT_VERSION.
VERSION_PATH=""
if [[ -n "${AGENT_VERSION:-}" ]]; then
  VERSION_PATH="?version=${AGENT_VERSION}"
fi
DOWNLOAD_URL="${SERVER}/api/agents/binary/${ARCH}${VERSION_PATH}"
info "downloading ${DOWNLOAD_URL}"

TMP_BIN=$(mktemp)
trap 'rm -f "$TMP_BIN" "${TMP_BIN}.sha256"' EXIT

CURL_OPTS=(-fsSL --retry 3 --retry-connrefused --connect-timeout 10 --max-time 300)
if [[ "${AGENT_INSECURE_TLS:-0}" == "1" ]]; then
  CURL_OPTS+=(-k)
fi
if ! curl "${CURL_OPTS[@]}" -o "$TMP_BIN" "$DOWNLOAD_URL"; then
  die "failed to download agent binary from $DOWNLOAD_URL" 2
fi

# Checksum verification — required unless operator sets SKIP_CHECKSUM=1.
if [[ "${SKIP_CHECKSUM:-0}" == "1" ]]; then
  info "WARNING: SKIP_CHECKSUM=1 set — binary integrity NOT verified. Use only in isolated lab environments."
else
  if ! curl "${CURL_OPTS[@]}" -o "${TMP_BIN}.sha256" "${DOWNLOAD_URL}.sha256"; then
    die "failed to fetch binary checksum from ${DOWNLOAD_URL}.sha256 — cannot verify integrity. Set SKIP_CHECKSUM=1 to bypass (not recommended)." 2
  fi
  EXPECTED=$(awk '{print $1}' "${TMP_BIN}.sha256")
  if [[ -z "$EXPECTED" ]]; then
    die "binary checksum file is empty — server may not have published hashes yet. Set SKIP_CHECKSUM=1 to bypass (not recommended)." 2
  fi
  ACTUAL=$(sha256sum "$TMP_BIN" | awk '{print $1}')
  if [[ "$EXPECTED" != "$ACTUAL" ]]; then
    die "binary checksum mismatch (expected $EXPECTED, got $ACTUAL)" 2
  fi
  info "binary checksum verified"
fi

install -m 0755 -D "$TMP_BIN" /usr/local/bin/wireshield-agent
info "installed /usr/local/bin/wireshield-agent ($(/usr/local/bin/wireshield-agent version))"

# Drop systemd unit — embedded here so it requires no additional network
# fetch and cannot be tampered with by a MITM after the script is downloaded.
info "installing /etc/systemd/system/wireshield-agent.service"
cat > /etc/systemd/system/wireshield-agent.service << 'UNIT_EOF'
[Unit]
Description=WireShield Agent — heartbeat + revocation daemon
Documentation=https://github.com/siyamsarker/wireshield
After=network-online.target wg-quick@wg-agent0.service
Wants=network-online.target
Requires=wg-quick@wg-agent0.service

[Service]
Type=simple
ExecStart=/usr/local/bin/wireshield-agent run
RestartPreventExitStatus=2
Restart=on-failure
RestartSec=10s
StartLimitBurst=6
StartLimitIntervalSec=300

User=root
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectKernelLogs=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
ReadOnlyPaths=/etc/wireshield-agent
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT_EOF
chmod 0644 /etc/systemd/system/wireshield-agent.service
info "installed /etc/systemd/system/wireshield-agent.service"

systemctl daemon-reload

# Enroll. The `enroll` subcommand writes /etc/wireshield-agent/* + /etc/wireguard/wg-agent0.conf
# and `systemctl enable --now wg-quick@wg-agent0`.
ENROLL_ARGS=(--token "$TOKEN" --server "$SERVER")
if [[ -n "${AGENT_LAN_IF:-}" ]]; then ENROLL_ARGS+=(--lan-if "$AGENT_LAN_IF"); fi
if [[ -n "${AGENT_CIDRS:-}" ]]; then ENROLL_ARGS+=(--advertised-cidrs "$AGENT_CIDRS"); fi
if [[ "${AGENT_INSECURE_TLS:-0}" == "1" ]]; then ENROLL_ARGS+=(--tls-insecure); fi

if ! /usr/local/bin/wireshield-agent enroll "${ENROLL_ARGS[@]}"; then
  die "enrollment failed (check token validity + server reachability)" 2
fi

# Start the heartbeat daemon.
if ! systemctl enable --now wireshield-agent.service; then
  die "systemctl enable --now wireshield-agent.service failed (check: journalctl -u wireshield-agent)" 3
fi

info "✓ agent installed and running"
info "  journal:    journalctl -u wireshield-agent -f"
info "  status:     wireshield-agent status"
info "  uninstall:  sudo wireshield-agent uninstall   # full removal from this host"
