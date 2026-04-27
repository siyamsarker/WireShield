#!/bin/bash

# ==============================================================================
# WireShield – Secure WireGuard VPN installer and manager
# ------------------------------------------------------------------------------
# Purpose
#   Automates installation, configuration, and lifecycle management of a
#   WireGuard VPN server, plus interactive management of client peers.
#
# Highlights
#   - Cross-distro support (Debian/Ubuntu/Fedora/CentOS/Alma/Rocky/Oracle/Arch/Alpine)
#   - Kernel-awareness: WireGuard built-in on Linux >= 5.6; installs module/tools
#   - Safe defaults, strong key generation, least-privilege file permissions
#   - Interactive TUI (whiptail if available) or CLI fallback
#   - Add/List/Revoke clients; show QR; backup configs; restart; uninstall
#
# Usage
#   Make executable and run as root:
#     chmod +x ./wireshield.sh && sudo ./wireshield.sh
#
# Security & Safety
#   - Requires root (networking, firewall, sysctl, /etc/wireguard writes)
#   - Writes configs to /etc/wireguard with 600 permissions
#   - Only modifies iptables/firewalld rules for the selected interface/port
#
# Repository
#   https://github.com/siyamsarker/WireShield
#
# Version: 3.0.0
# ============================================================================

# ── Color System ──────────────────────────────────────────────────────────────
# Core (backward compat)
RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'
# Extended palette
BOLD='\033[1m'
DIM='\033[2m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BGREEN='\033[1;32m'
BRED='\033[1;31m'
BYELLOW='\033[1;33m'

# ── UI Helper Functions ──────────────────────────────────────────────────────
_ws_ui_success() { echo -e "  ${GREEN}✓${NC} $1"; }
_ws_ui_error()   { echo -e "  ${RED}✗${NC} $1"; }
_ws_ui_warn()    { echo -e "  ${ORANGE}!${NC} $1"; }
_ws_ui_info()    { echo -e "  ${BLUE}ℹ${NC} ${DIM}$1${NC}"; }

_ws_ui_divider() {
	echo -e "  ${GRAY}$(printf '%.0s─' {1..54})${NC}"
}

_ws_ui_section() {
	# Section header with a subtle dotted trailing separator for visual flow.
	local label="$1"
	local pad=$((56 - ${#label}))
	(( pad < 3 )) && pad=3
	local dots
	dots=$(printf '%.0s·' $(seq 1 $pad))
	echo ""
	echo -e "  ${CYAN}${label}${NC}  ${GRAY}${dots}${NC}"
}

_ws_ui_menu_item() {
	# Usage: _ws_ui_menu_item "num" "Label" "Description"
	# Key is right-aligned inside [ ] in accent color, label in normal, description dim.
	printf "   ${CYAN}%4s${NC}  %-22s  ${DIM}%s${NC}\n" "[$1]" "$2" "$3"
}

_ws_ui_kv() {
	# Usage: _ws_ui_kv "Key" "value"
	printf "  \033[0;90m%-14s\033[0m %s\n" "$1" "$2"
}

# Detect UTF-8 capability; fall back to plain ASCII boxes when unavailable.
USE_ASCII_BOX=0
function _ws_init_locale() {
	if locale -a 2>/dev/null | grep -qi 'C.UTF-8'; then
		export LANG=C.UTF-8
		export LC_ALL=C.UTF-8
	elif locale -a 2>/dev/null | grep -qi 'en_US.UTF-8'; then
		export LANG=en_US.UTF-8
		export LC_ALL=en_US.UTF-8
	else
		USE_ASCII_BOX=1
	fi
}

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
    # Detect unsupported virtualization environments early.
    # WireGuard requires kernel support on the host; some containers are not
    # suitable without special host configuration and capabilities.
	function openvzErr() {
		echo "OpenVZ is not supported"
		exit 1
	}
	function lxcErr() {
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	}
	if command -v virt-what &>/dev/null; then
		if [ "$(virt-what)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(virt-what)" == "lxc" ]; then
			lxcErr
		fi
	else
		if [ "$(systemd-detect-virt)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(systemd-detect-virt)" == "lxc" ]; then
			lxcErr
		fi
	fi
}

function checkOS() {
    # Normalize the OS identifier and perform minimal supported-version checks.
    # This script uses distro package managers to install WireGuard tooling.
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS/AlmaLinux/Rocky (${VERSION_ID}) is not supported. Please use version 8 or later"
			exit 1
		fi
		# CentOS Stream, AlmaLinux, and Rocky Linux 8+ are supported
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	elif [[ -e /etc/alpine-release ]]; then
		OS=alpine
		if ! command -v virt-what &>/dev/null; then
			apk update && apk add virt-what
		fi
	else
		echo "Looks like you aren't running this installer on a supported Linux distribution."
		echo "Supported: Debian 10+, Ubuntu 18.04+, Fedora 32+, CentOS Stream 8+, AlmaLinux 8+, Rocky Linux 8+, Oracle Linux, Arch Linux, Alpine Linux"
		exit 1
	fi
}

function getHomeDirForClient() {
	# Return a writable directory path to place client configuration files.
	# Priority:
	#   1) /home/<client> if it exists
	#   2) /home/${SUDO_USER} if non-root sudo was used
	#   3) /root as a safe fallback
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function initialCheck() {
	isRoot
	checkOS
	checkVirt
}

function checkWireGuardSupport() {
	# Check if WireGuard kernel module is available or if wireguard-go is needed
	# WireGuard is included in Linux kernel 5.6+
	KERNEL_VERSION=$(uname -r | cut -d'.' -f1-2)
	KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d'.' -f1)
	KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d'.' -f2)
	
	if [[ ${KERNEL_MAJOR} -gt 5 ]] || [[ ${KERNEL_MAJOR} -eq 5 && ${KERNEL_MINOR} -ge 6 ]]; then
		echo -e "${GREEN}Kernel ${KERNEL_VERSION} detected - WireGuard is built into your kernel!${NC}"
	else
		echo -e "${ORANGE}Kernel ${KERNEL_VERSION} detected - WireGuard kernel module will be installed separately.${NC}"
	fi
}

function installQuestions() {
    # Collect installation inputs with validation and a final confirmation step.
    # Uses whiptail for a modern confirmation dialog when available.

	_ws_init_locale

	# helper: check interface existence
	interface_exists() {
		ip link show dev "$1" >/dev/null 2>&1
	}

	# helper: get the primary IPv4 assigned to an interface
	get_interface_ipv4() {
		local nic="$1"
		ip -o -4 addr show "$nic" 2>/dev/null | awk '{print $4}' | cut -d'/' -f1 | head -1
	}

	while true; do
		clear
		echo ""
    echo -e "  ╭──────────────────────────────────────────────────────╮"
		echo -e "  │                                                      │"
		echo -e "  │                ${WHITE}✻  WireShield${NC} ${GRAY}v3.0.0${NC}                  │"
		echo -e "  │                                                      │"
		echo -e "  │           ${GRAY}Zero-trust WireGuard VPN with 2FA${NC}          │"
		echo -e "  │                                                      │"
		echo -e "  │      ${DIM}Enter to accept defaults · Ctrl+C to cancel${NC}     │"
		echo -e "  │                                                      │"
		echo -e "  ╰──────────────────────────────────────────────────────╯"
		echo ""

		# ── Network ──
		echo -e "  ${CYAN}Network${NC}"
		echo ""

		# Detect public IPv4 or IPv6 address and pre-fill for the user
		SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
		if [[ -z ${SERVER_PUB_IP} ]]; then
			SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
		fi
		read -rp "$(echo -ne "  ${GRAY}Public address${NC} > ")" -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

		SERVER_NIC="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
		until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]] && interface_exists "${SERVER_PUB_NIC}"; do
			read -rp "$(echo -ne "  ${GRAY}Public interface${NC} > ")" -e -i "${SERVER_NIC}" SERVER_PUB_NIC
			if ! interface_exists "${SERVER_PUB_NIC}"; then
				_ws_ui_warn "Interface '${SERVER_PUB_NIC}' not found. Try: ${SERVER_NIC}"
			fi
		done

		SERVER_LOCAL_IPV4=$(get_interface_ipv4 "${SERVER_PUB_NIC}")
		if [[ -z ${SERVER_LOCAL_IPV4} ]]; then
			SERVER_LOCAL_IPV4=$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d'/' -f1 | head -1)
		fi

		echo ""
		# ── WireGuard ──
		echo -e "  ${CYAN}WireGuard${NC}"
		echo ""

		until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
			read -rp "$(echo -ne "  ${GRAY}Interface name${NC} > ")" -e -i wg0 SERVER_WG_NIC
		done

		until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
			read -rp "$(echo -ne "  ${GRAY}Server IPv4${NC}     > ")" -e -i 10.66.66.1 SERVER_WG_IPV4
		done

		if [[ -z ${SERVER_LOCAL_IPV4} ]]; then
			SERVER_LOCAL_IPV4="${SERVER_WG_IPV4}"
		fi

		until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
			read -rp "$(echo -ne "  ${GRAY}Server IPv6${NC}     > ")" -e -i fd42:42:42::1 SERVER_WG_IPV6
		done

		RANDOM_PORT=$(shuf -i49152-65535 -n1)
		until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
			read -rp "$(echo -ne "  ${GRAY}UDP port${NC}        > ")" -e -i "${RANDOM_PORT}" SERVER_PORT
		done

		echo ""
		# ── DNS ──
		echo -e "  ${CYAN}Client DNS${NC}"
		echo ""

		until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
			read -rp "$(echo -ne "  ${GRAY}Primary DNS${NC}     > ")" -e -i 1.1.1.1 CLIENT_DNS_1
		done
		until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
			read -rp "$(echo -ne "  ${GRAY}Secondary DNS${NC}   > ")" -e -i 1.0.0.1 CLIENT_DNS_2
			if [[ ${CLIENT_DNS_2} == "" ]]; then
				CLIENT_DNS_2="${CLIENT_DNS_1}"
			fi
		done

		echo ""
		# ── Routing ──
		echo -e "  ${CYAN}Routing${NC}"
		echo ""

		until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
			_ws_ui_info "AllowedIPs controls what traffic is routed through the VPN."
			read -rp "$(echo -ne "  ${GRAY}Allowed IPs${NC}     > ")" -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
			if [[ ${ALLOWED_IPS} == "" ]]; then
				ALLOWED_IPS="0.0.0.0/0,::/0"
			fi
		done

		# ── Confirmation ──
		echo ""
		_ws_ui_divider
		echo ""
		echo -e "  ${CYAN}Review Configuration${NC}"
		echo ""
		_ws_ui_kv "Public address" "${SERVER_PUB_IP}"
		_ws_ui_kv "Public NIC" "${SERVER_PUB_NIC}"
		_ws_ui_kv "WG interface" "${SERVER_WG_NIC}"
		_ws_ui_kv "WG IPv4" "${SERVER_WG_IPV4}/24"
		_ws_ui_kv "WG IPv6" "${SERVER_WG_IPV6}/64"
		_ws_ui_kv "WG port" "${SERVER_PORT}/udp"
		_ws_ui_kv "Client DNS" "${CLIENT_DNS_1}, ${CLIENT_DNS_2}"
		_ws_ui_kv "Allowed IPs" "${ALLOWED_IPS}"
		echo ""
		_ws_ui_divider

		if command -v whiptail &>/dev/null; then
			SUMMARY=$(printf "Public address : %s\nPublic NIC     : %s\nWG interface   : %s\nWG IPv4        : %s/24\nWG IPv6        : %s/64\nWG Port        : %s/udp\nClient DNS     : %s, %s\nAllowed IPs    : %s" \
				"${SERVER_PUB_IP}" "${SERVER_PUB_NIC}" "${SERVER_WG_NIC}" "${SERVER_WG_IPV4}" "${SERVER_WG_IPV6}" "${SERVER_PORT}" "${CLIENT_DNS_1}" "${CLIENT_DNS_2}" "${ALLOWED_IPS}")
			whiptail --title "Review & confirm" \
				--yes-button "Install" \
				--no-button "Edit" \
				--yesno "${SUMMARY}\n\nProceed with installation?" 18 64
			if [[ $? -eq 0 ]]; then
				break
			else
				_ws_ui_info "Restarting configuration..."
				echo ""
			fi
		else
			echo ""
			read -rp "$(echo -ne "  Proceed with installation? ${GRAY}[Y/n]${NC} > ")" -e CONFIRM
			CONFIRM=${CONFIRM:-Y}
			if [[ ${CONFIRM} =~ ^[Yy]$ ]]; then
				break
			else
				_ws_ui_info "Restarting configuration..."
				echo ""
			fi
		fi
	done

	echo ""
	_ws_ui_success "Configuration locked in. Starting installation..."
	_ws_ui_info "A first client will be generated automatically."
	echo ""
}

function _ws_upgrade_wireguard_packages() {
	# Best-effort upgrade to the newest WireGuard packages available for the distro.
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
		apt-get update
		apt-get install -y --only-upgrade wireguard wireguard-tools qrencode || true
	elif [[ ${OS} == 'fedora' ]]; then
		dnf upgrade -y wireguard-tools wireguard-dkms qrencode || true
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'oracle' ]]; then
		if command -v dnf >/dev/null 2>&1; then
			dnf upgrade -y wireguard-tools qrencode || true
		else
			yum update -y wireguard-tools qrencode || true
		fi
	elif [[ ${OS} == 'arch' ]]; then
		pacman -Sy --noconfirm --needed wireguard-tools qrencode || true
	elif [[ ${OS} == 'alpine' ]]; then
		apk update && apk add --upgrade wireguard-tools libqrencode-tools || true
	fi
}

# ============================================================================
# 2FA (Two-Factor Authentication) Management
# ============================================================================

function _ws_configure_2fa_ssl() {
	# Prompt for SSL configuration (domain, IP, or none)
	echo ""
	echo ""
	echo -e "  ${CYAN}SSL/TLS Configuration${NC}"
	echo ""
	_ws_ui_info "The 2FA web interface requires HTTPS for security."
	echo ""

	# Ask if user wants SSL/TLS
	read -rp "$(echo -ne "  Configure SSL/TLS? ${GRAY}(y/n)${NC} > ")" -e USE_SSL
	if [[ "${USE_SSL}" != "y" && "${USE_SSL}" != "Y" ]]; then
		_ws_ui_warn "2FA will run without SSL (only recommended for localhost)"
		echo "2FA_SSL_ENABLED=false" >> /etc/wireshield/2fa/config.env
		return 0
	fi

	echo ""
	_ws_ui_menu_item "1" "Let's Encrypt" "Domain required, auto-renewal"
	_ws_ui_menu_item "2" "Self-signed" "IP address or any hostname"
	echo ""
	read -rp "$(echo -ne "  \033[0;32m>\033[0m ")" -e SSL_TYPE
	
	if [[ "${SSL_TYPE}" == "1" ]]; then
		# Let's Encrypt with domain
		read -rp "$(echo -ne "  ${GRAY}Domain name${NC}     > ")" -e WS_2FA_DOMAIN

		if [[ -z "${WS_2FA_DOMAIN}" ]]; then
			_ws_ui_error "Domain name required for Let's Encrypt"
			return 1
		fi
		if [[ ${WS_2FA_DOMAIN} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
			_ws_ui_error "Let's Encrypt requires a DNS name (not an IP)"
			return 1
		fi
		if [[ ! ${WS_2FA_DOMAIN} =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*)(\.[a-zA-Z0-9](-?[a-zA-Z0-9])*)+$ ]]; then
			_ws_ui_error "Invalid domain format: ${WS_2FA_DOMAIN}"
			return 1
		fi

		_ws_ui_info "Setting up Let's Encrypt for ${WS_2FA_DOMAIN}..."
		
		# Install certbot if not present
		if ! command -v certbot &>/dev/null; then
			if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
				apt-get install -y certbot 2>/dev/null || apt-get install -y python3-certbot 2>/dev/null || true
			elif [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
				dnf install -y certbot 2>/dev/null || yum install -y certbot 2>/dev/null || true
			elif [[ ${OS} == 'arch' ]]; then
				pacman -S --noconfirm certbot 2>/dev/null || true
			elif [[ ${OS} == 'alpine' ]]; then
				apk add certbot 2>/dev/null || true
			fi
		fi
		
		# Request Let's Encrypt certificate
		if command -v certbot &>/dev/null; then
			certbot certonly --standalone --non-interactive --agree-tos -m "admin@${WS_2FA_DOMAIN}" \
				-d "${WS_2FA_DOMAIN}" 2>/dev/null || {
				_ws_ui_warn "Let's Encrypt setup incomplete. Falling back to self-signed."
				SSL_TYPE="2"
			}
		fi
		
		if [[ "${SSL_TYPE}" == "1" ]]; then
			# Symlink Let's Encrypt certs
			SSL_CERT_PATH="/etc/letsencrypt/live/${WS_2FA_DOMAIN}/fullchain.pem"
			SSL_KEY_PATH="/etc/letsencrypt/live/${WS_2FA_DOMAIN}/privkey.pem"
			
			if [[ -f "${SSL_CERT_PATH}" ]] && [[ -f "${SSL_KEY_PATH}" ]]; then
				ln -sf "${SSL_CERT_PATH}" /etc/wireshield/2fa/cert.pem 2>/dev/null || true
				ln -sf "${SSL_KEY_PATH}" /etc/wireshield/2fa/key.pem 2>/dev/null || true
				
				# Setup auto-renewal
				cat > /etc/systemd/system/wireshield-2fa-renew.timer << 'EOFTIMER'
[Unit]
Description=WireShield 2FA SSL Certificate Renewal Timer
Requires=wireshield-2fa-renew.service

[Timer]
OnCalendar=daily
OnBootSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOFTIMER

				cat > /etc/systemd/system/wireshield-2fa-renew.service << 'EOFSERVICE'
[Unit]
Description=WireShield 2FA SSL Certificate Renewal
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --post-hook "systemctl reload wireshield"

[Install]
WantedBy=multi-user.target
EOFSERVICE

				systemctl daemon-reload 2>/dev/null || true
				systemctl enable wireshield-2fa-renew.timer 2>/dev/null || true
				# Immediate dry-run to surface renewal issues early
				certbot renew --dry-run --quiet 2>/dev/null || _ws_ui_warn "Certbot dry-run failed; check ports 80/443 and DNS for ${WS_2FA_DOMAIN}"

				_ws_ui_success "Let's Encrypt certificate configured"
				_ws_ui_success "Auto-renewal enabled"
				# Write WS_* names only (systemd EnvironmentFile cannot parse 2FA_*)
				echo "WS_2FA_SSL_ENABLED=true" >> /etc/wireshield/2fa/config.env
				echo "WS_2FA_SSL_TYPE=letsencrypt" >> /etc/wireshield/2fa/config.env
				echo "WS_2FA_DOMAIN=${WS_2FA_DOMAIN}" >> /etc/wireshield/2fa/config.env
				return 0
			fi
		fi
	fi
	
	# Self-signed certificate (for IP or localhost)
	read -rp "$(echo -ne "  ${GRAY}IP or hostname${NC} > ")" -e -i "${SERVER_WG_IPV4}" WS_HOSTNAME_2FA

	if [[ -z "${WS_HOSTNAME_2FA}" ]]; then
		WS_HOSTNAME_2FA="${SERVER_WG_IPV4}"
	fi

	_ws_ui_info "Generating self-signed certificate for ${WS_HOSTNAME_2FA}..."
	
	openssl req -x509 -newkey rsa:4096 \
		-keyout /etc/wireshield/2fa/key.pem \
		-out /etc/wireshield/2fa/cert.pem \
		-days 365 -nodes \
		-subj "/C=US/ST=State/L=City/O=WireShield/CN=${WS_HOSTNAME_2FA}" 2>/dev/null || true
	
	chmod 600 /etc/wireshield/2fa/key.pem
	chmod 644 /etc/wireshield/2fa/cert.pem
	
	_ws_ui_success "Self-signed certificate configured"
	# Write WS_* names only (systemd EnvironmentFile cannot parse 2FA_*)
	echo "WS_2FA_SSL_ENABLED=true" >> /etc/wireshield/2fa/config.env
	echo "WS_2FA_SSL_TYPE=self-signed" >> /etc/wireshield/2fa/config.env
	echo "WS_HOSTNAME_2FA=${WS_HOSTNAME_2FA}" >> /etc/wireshield/2fa/config.env
}

function _ws_build_agent() {
	# Build and publish wireshield-agent binaries to AGENT_BINARY_DIR so the
	# /api/agents/binary/* endpoints are immediately ready to serve. Non-fatal:
	# a missing or too-old Go toolchain just prints a warning with manual steps.
	local SCRIPT_DIR
	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	local AGENT_DIR="${SCRIPT_DIR}/agent"
	local AGENT_BINARY_DIR="/etc/wireshield/agent-binaries"

	_ws_ui_section "Agent Binary Build"

	if [[ ! -d "${AGENT_DIR}" ]]; then
		_ws_ui_warn "agent/ source directory not found — skipping agent build"
		_ws_ui_info  "Build manually: make -C agent dist && sudo make -C agent install"
		return 0
	fi

	if ! command -v go >/dev/null 2>&1; then
		_ws_ui_warn "Go toolchain not found — skipping agent build"
		_ws_ui_info  "Install Go 1.22+, then run:"
		_ws_ui_info  "  make -C agent dist && sudo make -C agent install AGENT_BINARY_DIR=${AGENT_BINARY_DIR}"
		return 0
	fi

	local GO_VERSION
	GO_VERSION=$(go version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
	local GO_MAJOR GO_MINOR
	GO_MAJOR=$(echo "${GO_VERSION}" | cut -d. -f1)
	GO_MINOR=$(echo "${GO_VERSION}" | cut -d. -f2)
	if [[ "${GO_MAJOR}" -lt 1 ]] || { [[ "${GO_MAJOR}" -eq 1 ]] && [[ "${GO_MINOR}" -lt 22 ]]; }; then
		_ws_ui_warn "Go ${GO_VERSION} found but 1.22+ is required — skipping agent build"
		_ws_ui_info  "Upgrade Go, then run:"
		_ws_ui_info  "  make -C agent dist && sudo make -C agent install AGENT_BINARY_DIR=${AGENT_BINARY_DIR}"
		return 0
	fi

	_ws_ui_info "Building wireshield-agent for linux-amd64 and linux-arm64 (Go ${GO_VERSION})..."
	if ! make -C "${AGENT_DIR}" dist >/dev/null 2>&1; then
		_ws_ui_warn "Agent build failed"
		_ws_ui_info  "Retry manually: make -C agent dist"
		return 0
	fi

	_ws_ui_info "Publishing binaries to ${AGENT_BINARY_DIR}..."
	if ! make -C "${AGENT_DIR}" install AGENT_BINARY_DIR="${AGENT_BINARY_DIR}" >/dev/null 2>&1; then
		_ws_ui_warn "Agent install failed"
		_ws_ui_info  "Retry manually: sudo make -C agent install AGENT_BINARY_DIR=${AGENT_BINARY_DIR}"
		return 0
	fi

	_ws_ui_success "wireshield-agent_linux_amd64 and wireshield-agent_linux_arm64 published"
	_ws_ui_success "Agents are ready — register them from the admin console → Agents tab"
}

function _ws_install_2fa_service() {
	# Install Python 2FA service and dependencies
	echo ""
	echo -e "  ${CYAN}2FA Service Setup${NC}"
	echo ""

	local VENV_PATH="/etc/wireshield/2fa/.venv"
	local SCRIPT_DIR
	SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
	
	# Create 2FA directory and config file
	mkdir -p /etc/wireshield/2fa
	chmod 700 /etc/wireshield/2fa
	
	# Generate a secure random SECRET_KEY for session security
	SECRET_KEY=$(openssl rand -base64 32 | tr -d '\n')
	
	cat > /etc/wireshield/2fa/config.env << EOF
# WireShield 2FA Configuration
# Generated during installation
# Use only WS_* prefixed names (systemd EnvironmentFile cannot parse 2FA_* or names starting with numbers)
WS_2FA_SECRET_KEY=${SECRET_KEY}
WS_2FA_DB_PATH=/etc/wireshield/2fa/auth.db
WS_2FA_HOST=0.0.0.0
WS_2FA_PORT=443
WS_2FA_HTTP_PORT=80
WS_2FA_LOG_LEVEL=INFO
WS_2FA_RATE_LIMIT_MAX_REQUESTS=30
WS_2FA_RATE_LIMIT_WINDOW=60
WS_2FA_SESSION_IDLE_TIMEOUT=3600
WS_2FA_DISCONNECT_GRACE_SECONDS=3600
WS_2FA_SSL_ENABLED=false
WS_2FA_SSL_TYPE=none
WS_2FA_DOMAIN=
WS_HOSTNAME_2FA=${SERVER_WG_IPV4}
EOF
	
	# Ensure Python3, pip and venv are available (install even if python3 already exists)
	_ws_ui_info "Ensuring Python3 pip/venv are installed..."
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
		apt-get update -y >/dev/null 2>&1 || true
		apt-get install -y python3 python3-pip python3-venv >/dev/null 2>&1 || true
		# Fallback for versioned venv packages on newer Ubuntu/Debian
		PYVER=$(python3 -V 2>/dev/null | awk '{print $2}')
		PYMM=${PYVER%.*}
		apt-get install -y "python${PYMM}-venv" >/dev/null 2>&1 || true
	elif [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'oracle' ]]; then
		if command -v dnf >/dev/null 2>&1; then
			dnf install -y python3 python3-pip python3-venv >/dev/null 2>&1 || true
		else
			yum install -y python3 python3-pip python3-venv >/dev/null 2>&1 || true
		fi
	elif [[ ${OS} == 'arch' ]]; then
		pacman -Sy --noconfirm python python-pip >/dev/null 2>&1 || true
	elif [[ ${OS} == 'alpine' ]]; then
		apk add python3 py3-pip py3-venv >/dev/null 2>&1 || true
	fi

	# Copy 2FA files from the current repository if available
	if [[ -d "${SCRIPT_DIR}/console-server" ]]; then
		_ws_ui_info "Copying 2FA service files..."
		cp -fr "${SCRIPT_DIR}/console-server/"* /etc/wireshield/2fa/ || true
	elif [[ -d /opt/wireshield/console-server ]]; then
		cp /opt/wireshield/console-server/* /etc/wireshield/2fa/ 2>/dev/null || true
	fi
	
	# Check if 2FA service already exists
	if [[ -f /etc/systemd/system/wireshield.service ]]; then
		_ws_ui_success "2FA service already installed"
		return 0
	fi
	if [[ -f /etc/systemd/system/wireshield-2fa.service ]]; then
		_ws_ui_info "Upgrading service name from wireshield-2fa to wireshield..."
		systemctl stop wireshield-2fa 2>/dev/null || true
		systemctl disable wireshield-2fa 2>/dev/null || true
		rm -f /etc/systemd/system/wireshield-2fa.service 2>/dev/null || true
		systemctl daemon-reload 2>/dev/null || true
	fi
	
	# Configure SSL/TLS
	_ws_configure_2fa_ssl
	
	# Install Python dependencies into a dedicated virtual environment
	python3 -m venv "${VENV_PATH}" 2>/dev/null || true
	# If venv creation failed due to missing ensurepip, try to install venv package and retry
	if [[ ! -x "${VENV_PATH}/bin/python" ]]; then
		_ws_ui_warn "Fixing missing ensurepip by installing venv package..."
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			PYVER=$(python3 -V 2>/dev/null | awk '{print $2}')
			PYMM=${PYVER%.*}
			apt-get install -y python3-venv "python${PYMM}-venv" >/dev/null 2>&1 || true
		elif [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'oracle' ]]; then
			if command -v dnf >/dev/null 2>&1; then dnf install -y python3-venv >/dev/null 2>&1 || true; else yum install -y python3-venv >/dev/null 2>&1 || true; fi
		elif [[ ${OS} == 'arch' ]]; then
			# venv is bundled with python on Arch; ensure pip is present
			pacman -Sy --noconfirm python python-pip >/dev/null 2>&1 || true
		elif [[ ${OS} == 'alpine' ]]; then
			apk add py3-venv >/dev/null 2>&1 || true
		fi
		python3 -m venv "${VENV_PATH}" 2>/dev/null || true
	fi
	if [[ -f /etc/wireshield/2fa/requirements.txt ]]; then
		"${VENV_PATH}/bin/pip" install -q --upgrade pip setuptools wheel 2>/dev/null || true
		"${VENV_PATH}/bin/pip" install -q -r /etc/wireshield/2fa/requirements.txt 2>/dev/null || {
			_ws_ui_warn "Some Python dependencies may not have installed correctly"
		}
	fi
	
	# SSL certificates already configured during _ws_configure_2fa_ssl
	# Skip if they already exist
	if [[ ! -f /etc/wireshield/2fa/cert.pem ]] || [[ ! -f /etc/wireshield/2fa/key.pem ]]; then
		_ws_ui_warn "SSL certificates not found, generating self-signed..."
		openssl req -x509 -newkey rsa:4096 \
			-keyout /etc/wireshield/2fa/key.pem \
			-out /etc/wireshield/2fa/cert.pem \
			-days 365 -nodes \
			-subj "/C=US/ST=State/L=City/O=WireShield/CN=wireshield" 2>/dev/null || true
		chmod 600 /etc/wireshield/2fa/key.pem 2>/dev/null || true
		chmod 644 /etc/wireshield/2fa/cert.pem 2>/dev/null || true
	fi
	
	# Verify app presence (robustness)
	if [[ ! -f /etc/wireshield/2fa/run.py ]]; then
		_ws_ui_warn "run.py missing, attempting copy from repo..."
		if [[ -f "${SCRIPT_DIR}/console-server/run.py" ]]; then
			cp -f "${SCRIPT_DIR}/console-server/run.py" /etc/wireshield/2fa/ || true
		fi
		if [[ -d "${SCRIPT_DIR}/console-server/static" ]]; then
			cp -fr "${SCRIPT_DIR}/console-server/static" /etc/wireshield/2fa/ || true
		fi
		if [[ -d "${SCRIPT_DIR}/console-server/app" ]]; then
			cp -fr "${SCRIPT_DIR}/console-server/app" /etc/wireshield/2fa/ || true
		fi
		if [[ -f "${SCRIPT_DIR}/console-server/requirements.txt" ]]; then
			cp -f "${SCRIPT_DIR}/console-server/requirements.txt" /etc/wireshield/2fa/ || true
		fi
	fi

	# Install systemd service file
	if [[ -f /etc/wireshield/2fa/wireshield.service ]]; then
		# Read config and create updated service file
		# Load WS_* values (avoid bash parsing errors with 2FA_* names)
		# shellcheck disable=SC1091
		source /etc/wireshield/2fa/config.env 2>/dev/null || true
		
		cat > /etc/systemd/system/wireshield.service << EOF
[Unit]
Description=WireShield 2FA Authentication Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/wireshield/2fa
EnvironmentFile=-/etc/wireshield/2fa/config.env
# Use WS_* variables to satisfy systemd's environment parser
Environment=WS_2FA_DB_PATH=/etc/wireshield/2fa/auth.db
Environment=WS_2FA_HOST=0.0.0.0
Environment=WS_2FA_PORT=443
Environment=WS_2FA_HTTP_PORT=80
Environment=WS_2FA_SSL_ENABLED=${WS_2FA_SSL_ENABLED:-false}
Environment=WS_2FA_SSL_TYPE=${WS_2FA_SSL_TYPE:-self-signed}
Environment=WS_2FA_DOMAIN=${WS_2FA_DOMAIN:-}
Environment=WS_HOSTNAME_2FA=${WS_HOSTNAME_2FA:-127.0.0.1}
Environment=WS_2FA_RATE_LIMIT_MAX_REQUESTS=${WS_2FA_RATE_LIMIT_MAX_REQUESTS:-30}
Environment=WS_2FA_RATE_LIMIT_WINDOW=${WS_2FA_RATE_LIMIT_WINDOW:-60}
ExecStart=${VENV_PATH}/bin/python /etc/wireshield/2fa/run.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
	else
		# Fallback: create minimal service file
		cat > /etc/systemd/system/wireshield.service << EOF
[Unit]
Description=WireShield 2FA Authentication Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/wireshield/2fa
EnvironmentFile=-/etc/wireshield/2fa/config.env
Environment=WS_2FA_DB_PATH=/etc/wireshield/2fa/auth.db
Environment=WS_2FA_HOST=0.0.0.0
Environment=WS_2FA_PORT=443
Environment=WS_2FA_HTTP_PORT=80
Environment=WS_2FA_RATE_LIMIT_MAX_REQUESTS=30
Environment=WS_2FA_RATE_LIMIT_WINDOW=60
ExecStart=${VENV_PATH}/bin/python /etc/wireshield/2fa/run.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
	fi
	
	# Enable and start the service
	systemctl daemon-reload 2>/dev/null || true
	systemctl enable wireshield 2>/dev/null || true
	systemctl start wireshield 2>/dev/null || true

	if systemctl is-active --quiet wireshield; then
		_ws_ui_success "2FA service installed and started"
	else
		_ws_ui_warn "2FA service did not start. Check: journalctl -u wireshield"
	fi

	# Open firewall for 2FA TCP ports (HTTP 80 and HTTPS 443) to allow external/NAT access
	if [[ -f /etc/wireshield/2fa/config.env ]]; then
		# shellcheck disable=SC1091
		source /etc/wireshield/2fa/config.env 2>/dev/null || true
	fi
	local _ws_2fa_port _ws_2fa_http_port
	_ws_2fa_port=${WS_2FA_PORT:-443}
	_ws_2fa_http_port=${WS_2FA_HTTP_PORT:-80}
	if pgrep firewalld >/dev/null 2>&1; then
		firewall-cmd --add-port ${_ws_2fa_port}/tcp --permanent 2>/dev/null || true
		firewall-cmd --add-port ${_ws_2fa_http_port}/tcp --permanent 2>/dev/null || true
		firewall-cmd --reload 2>/dev/null || true
	else
		iptables -I INPUT -p tcp --dport ${_ws_2fa_port} -j ACCEPT 2>/dev/null || true
		iptables -I INPUT -p tcp --dport ${_ws_2fa_http_port} -j ACCEPT 2>/dev/null || true
		ip6tables -I INPUT -p tcp --dport ${_ws_2fa_port} -j ACCEPT 2>/dev/null || true
		ip6tables -I INPUT -p tcp --dport ${_ws_2fa_http_port} -j ACCEPT 2>/dev/null || true
	fi

	# Post-install health check: ping /health and surface a clear status
	if [[ -f /etc/wireshield/2fa/config.env ]]; then
		# Prefer WS_* keys to avoid bash parsing errors
		# shellcheck disable=SC1091
		source /etc/wireshield/2fa/config.env 2>/dev/null || true
	fi

	local _scheme _host _port _health_url _ok=0 _resp
	_port=${WS_2FA_PORT:-443}
	if [[ "${WS_2FA_SSL_ENABLED}" == "true" || "${WS_2FA_SSL_ENABLED}" == "1" || "${WS_2FA_SSL_ENABLED}" == "yes" ]]; then
		_scheme="https"
	else
		_scheme="http"
	fi
	# Health check runs locally on the server - always use localhost
	# The WireGuard IP is only reachable when the VPN interface is up
	_host="127.0.0.1"
	_health_url="${_scheme}://${_host}:${_port}/health"

	_ws_ui_info "Checking 2FA service health at ${_health_url}..."
	for i in {1..30}; do
		# -s silent, -k ignore self-signed, -m timeout seconds
		_resp=$(curl -sk -m 2 "${_health_url}" || true)
		if echo "${_resp}" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"'; then
			_ok=1
			break
		fi
		sleep 1
	done

	if [[ ${_ok} -eq 1 ]]; then
		_ws_ui_success "2FA health: OK"
	else
		_ws_ui_warn "2FA health check failed. Service may still be starting."
		_ws_ui_info "Try: journalctl -u wireshield -n 60 | less"
	fi
}

function _ws_enable_2fa_for_client() {
	# Enable 2FA for a specific client and record allocated WG IPs
	local client_id="$1"
	local wg_ipv4="$2"
	local wg_ipv6="$3"
	[[ -z "$client_id" ]] && return 1

	# Initialize client in 2FA database with IP mapping
	if command -v python3 &>/dev/null && [[ -f /etc/wireshield/2fa/auth.db ]]; then
		python3 << PYEOF 2>/dev/null || true
import sqlite3
conn = sqlite3.connect('/etc/wireshield/2fa/auth.db')
c = conn.cursor()
# Ensure columns exist (migration)
try:
	c.execute('ALTER TABLE users ADD COLUMN wg_ipv4 TEXT')
except Exception:
	pass
try:
	c.execute('ALTER TABLE users ADD COLUMN wg_ipv6 TEXT')
except Exception:
	pass
c.execute('SELECT id FROM users WHERE client_id = ?', ('$client_id',))
row = c.fetchone()
if not row:
	c.execute('INSERT INTO users (client_id, enabled, wg_ipv4, wg_ipv6) VALUES (?, ?, ?, ?)', ('$client_id', 0, '$wg_ipv4', '$wg_ipv6'))
else:
	c.execute('UPDATE users SET wg_ipv4 = ?, wg_ipv6 = ? WHERE client_id = ?', ('$wg_ipv4', '$wg_ipv6', '$client_id'))
conn.commit()
conn.close()
PYEOF
	fi
}

function installWireGuard() {
	# Run setup questions first (safe defaults, validated input, confirmation)
	installQuestions

	# Check WireGuard kernel support
	checkWireGuardSupport

	# Install WireGuard tools and module using the detected package manager
	echo "Installing WireGuard..."
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		# Install wireguard package which includes kernel module and tools
		apt-get install -y wireguard iptables resolvconf qrencode ipset sqlite3
	elif [[ ${OS} == 'debian' ]]; then
		# For Debian 10 Buster, use backports repository
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt-get update
		apt-get install -y iptables resolvconf qrencode sqlite3
		apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		# Fedora 32+ has WireGuard in the default repositories
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode ipset sqlite
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		# For RHEL-based systems
		if [[ ${VERSION_ID} == 8* ]]; then
			yum install -y epel-release elrepo-release
			yum install -y kmod-wireguard
			yum install -y qrencode # not available on release 9
		fi
		yum install -y wireguard-tools iptables ipset sqlite
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables sqlite
	elif [[ ${OS} == 'arch' ]]; then
		# Arch Linux has latest WireGuard in official repositories
		pacman -Sy --needed --noconfirm wireguard-tools qrencode ipset sqlite
	elif [[ ${OS} == 'alpine' ]]; then
		# Alpine Linux supports WireGuard natively
		apk update
		apk add wireguard-tools iptables libqrencode-tools ipset sqlite
	fi

	# Ensure the newest available WireGuard packages are installed
	_ws_upgrade_wireguard_packages

	# Check if WireGuard was installed successfully
	if ! command -v wg &>/dev/null; then
		echo -e "${RED}Error: WireGuard installation failed. The 'wg' command is not available.${NC}"
		exit 1
	fi

	# Display installed WireGuard version after the refresh
	local wg_version
	wg_version=$(wg --version 2>/dev/null || wg version 2>/dev/null || echo "installed")
	echo -e "${GREEN}WireGuard tools installed/updated (post-upgrade):${NC} ${wg_version}"

	# Ensure configuration directory exists (not always present by default)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Persist installation parameters for later operations (add/revoke clients)
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
	SERVER_PUB_NIC=${SERVER_PUB_NIC}
	SERVER_LOCAL_IPV4=${SERVER_LOCAL_IPV4}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/params

	# Create the server interface configuration file
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	PORTAL_DNAT_TARGET="${SERVER_LOCAL_IPV4:-${SERVER_WG_IPV4}}"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 443 -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 80 -j ACCEPT
PostUp = iptables -t nat -A PREROUTING -i ${SERVER_WG_NIC} -d ${SERVER_PUB_IP} -p tcp --dport 443 -j DNAT --to-destination ${PORTAL_DNAT_TARGET}:443
PostUp = iptables -t nat -A PREROUTING -i ${SERVER_WG_NIC} -d ${SERVER_PUB_IP} -p tcp --dport 80 -j DNAT --to-destination ${PORTAL_DNAT_TARGET}:80
PostUp = ipset create ws_2fa_allowed_v4 hash:ip family inet -exist
PostUp = ipset create ws_2fa_allowed_v6 hash:ip family inet6 -exist
PostUp = iptables -t nat -N WS_2FA_REDIRECT 2>/dev/null || true
PostUp = iptables -t nat -F WS_2FA_REDIRECT
PostUp = iptables -t nat -A WS_2FA_REDIRECT -p tcp --dport 80 -j DNAT --to-destination ${PORTAL_DNAT_TARGET}:80
PostUp = iptables -t nat -A PREROUTING -i ${SERVER_WG_NIC} -p tcp --dport 80 -m set ! --match-set ws_2fa_allowed_v4 src -j WS_2FA_REDIRECT
PostUp = iptables -N WS_2FA_PORTAL 2>/dev/null || true
PostUp = iptables -F WS_2FA_PORTAL
PostUp = iptables -A WS_2FA_PORTAL -p tcp --dport 53 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -p udp --dport 53 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -d ${PORTAL_DNAT_TARGET} -p tcp --dport 443 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -d ${PORTAL_DNAT_TARGET} -p tcp --dport 80 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -j DROP
PostUp = iptables -A FORWARD -i ${SERVER_WG_NIC} -m set --match-set ws_2fa_allowed_v4 src -j ACCEPT
PostUp = iptables -A FORWARD -i ${SERVER_WG_NIC} -j WS_2FA_PORTAL
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I INPUT -p tcp --dport 443 -j ACCEPT
PostUp = ip6tables -I INPUT -p tcp --dport 80 -j ACCEPT
PostUp = ip6tables -t nat -N WS_2FA_REDIRECT6 2>/dev/null || true
PostUp = ip6tables -t nat -F WS_2FA_REDIRECT6
PostUp = ip6tables -t nat -A WS_2FA_REDIRECT6 -p tcp --dport 80 -j DNAT --to-destination [${SERVER_WG_IPV6}]:80
PostUp = ip6tables -t nat -A PREROUTING -i ${SERVER_WG_NIC} -p tcp --dport 80 -m set ! --match-set ws_2fa_allowed_v6 src -j WS_2FA_REDIRECT6
PostUp = ip6tables -N WS_2FA_PORTAL6 2>/dev/null || true
PostUp = ip6tables -F WS_2FA_PORTAL6
PostUp = ip6tables -A WS_2FA_PORTAL6 -p tcp --dport 53 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -p udp --dport 53 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -p tcp --dport 443 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -p tcp --dport 80 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -j DROP
PostUp = ip6tables -A FORWARD -i ${SERVER_WG_NIC} -m set --match-set ws_2fa_allowed_v6 src -j ACCEPT
PostUp = ip6tables -A FORWARD -i ${SERVER_WG_NIC} -j WS_2FA_PORTAL6
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp = ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
PostDown = iptables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D PREROUTING -i ${SERVER_WG_NIC} -d ${SERVER_PUB_IP} -p tcp --dport 443 -j DNAT --to-destination ${PORTAL_DNAT_TARGET}:443 2>/dev/null || true
PostDown = iptables -t nat -D PREROUTING -i ${SERVER_WG_NIC} -d ${SERVER_PUB_IP} -p tcp --dport 80 -j DNAT --to-destination ${PORTAL_DNAT_TARGET}:80 2>/dev/null || true
PostDown = iptables -t nat -D PREROUTING -i ${SERVER_WG_NIC} -p tcp --dport 80 -m set ! --match-set ws_2fa_allowed_v4 src -j WS_2FA_REDIRECT 2>/dev/null || true
PostDown = iptables -t nat -F WS_2FA_REDIRECT 2>/dev/null || true
PostDown = iptables -t nat -X WS_2FA_REDIRECT 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j WS_2FA_PORTAL 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -m set --match-set ws_2fa_allowed_v4 src -j ACCEPT 2>/dev/null || true
PostDown = iptables -F WS_2FA_PORTAL 2>/dev/null || true
PostDown = iptables -X WS_2FA_PORTAL 2>/dev/null || true
PostDown = ipset flush ws_2fa_allowed_v4 2>/dev/null || true
PostDown = ipset destroy ws_2fa_allowed_v4 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE 2>/dev/null || true
PostDown = ip6tables -D INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
PostDown = ip6tables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
PostDown = ip6tables -t nat -D PREROUTING -i ${SERVER_WG_NIC} -p tcp --dport 80 -m set ! --match-set ws_2fa_allowed_v6 src -j WS_2FA_REDIRECT6 2>/dev/null || true
PostDown = ip6tables -t nat -F WS_2FA_REDIRECT6 2>/dev/null || true
PostDown = ip6tables -t nat -X WS_2FA_REDIRECT6 2>/dev/null || true
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j WS_2FA_PORTAL6 2>/dev/null || true
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -m set --match-set ws_2fa_allowed_v6 src -j ACCEPT 2>/dev/null || true
PostDown = ip6tables -F WS_2FA_PORTAL6 2>/dev/null || true
PostDown = ip6tables -X WS_2FA_PORTAL6 2>/dev/null || true
PostDown = ipset flush ws_2fa_allowed_v6 2>/dev/null || true
PostDown = ipset destroy ws_2fa_allowed_v6 2>/dev/null || true
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE 2>/dev/null || true
PostDown = iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
PostDown = ip6tables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable IPv4/IPv6 forwarding and network performance tuning on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# TCP performance optimizations for VPN throughput
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1" >/etc/sysctl.d/wg.conf

	if [[ ${OS} == 'alpine' ]]; then
		sysctl -p /etc/sysctl.d/wg.conf
		rc-update add sysctl
		ln -s /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
		rc-service "wg-quick.${SERVER_WG_NIC}" start
		rc-update add "wg-quick.${SERVER_WG_NIC}"
	else
		sysctl --system

		systemctl start "wg-quick@${SERVER_WG_NIC}"
		systemctl enable "wg-quick@${SERVER_WG_NIC}"
	fi

	# Ensure automatic expiration cleanup at 12:00 AM daily
	_ws_ensure_auto_expiration >/dev/null 2>&1 || true

	# Initialize 2FA service
	_ws_install_2fa_service

	# Create the first client now; you can add more later from the menu
	newClient
	echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"


	# Check if WireGuard is running
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	fi
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${ORANGE}You can check if WireGuard is running with: rc-service wg-quick.${SERVER_WG_NIC} status${NC}"
		else
			echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		fi
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
	else # WireGuard is running
		echo -e "\n${GREEN}WireGuard is running successfully!${NC}"
		echo -e "${GREEN}Server public key: ${SERVER_PUB_KEY}${NC}"
		echo -e "${GREEN}Server listening on port: ${SERVER_PORT}/udp${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${GREEN}You can check the status of WireGuard with: rc-service wg-quick.${SERVER_WG_NIC} status${NC}"
		else
			echo -e "${GREEN}You can check the status of WireGuard with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		fi
		echo -e "${GREEN}View connected peers with: wg show${NC}"
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi

	# Build and publish agent binaries so the Agents tab is immediately usable.
	_ws_build_agent
}

function newClient() {
	# Interactively create a new peer (client): allocate IPs, generate keys,
	# update server config, write client configuration, and optionally show QR.
	# IMPORTANT: Localize and reset variables to avoid cross-call leakage that
	# can cause the function to skip prompts or behave unexpectedly.
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Create Client${NC}"
	_ws_ui_divider
	echo ""
	local CLIENT_NAME="" CLIENT_EXISTS=1
	local DOT_IP="" DOT_EXISTS=0
	local IPV4_EXISTS=1 IPV6_EXISTS=1
	local BASE_IP CLIENT_WG_IPV4 CLIENT_WG_IPV6
	local CLIENT_PRIV_KEY CLIENT_PUB_KEY CLIENT_PRE_SHARED_KEY
	local HOME_DIR CLIENT_CONFIG
	local EXPIRY_DAYS="" EXPIRY_DATE=""
	# If SERVER_PUB_IP is IPv6, add brackets if missing
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] && [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	_ws_ui_info "Alphanumeric, underscores, dashes. Max 15 characters."
	echo ""

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "$(echo -ne "  ${GRAY}Client name${NC}     > ")" -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			_ws_ui_warn "Client '${CLIENT_NAME}' already exists. Choose another name."
		fi
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "$(echo -ne "  ${GRAY}Client IPv4${NC}     > ${BASE_IP}.")" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			_ws_ui_warn "IPv4 ${CLIENT_WG_IPV4} already in use."
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "$(echo -ne "  ${GRAY}Client IPv6${NC}     > ${BASE_IP}::")" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV6_EXISTS} != 0 ]]; then
			_ws_ui_warn "IPv6 ${CLIENT_WG_IPV6} already in use."
		fi
	done

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	# Ask for expiration date (optional)
	echo ""
	_ws_ui_info "Leave empty for no expiration."
	read -rp "$(echo -ne "  ${GRAY}Expires in days${NC} > ")" -e EXPIRY_DAYS
	
	EXPIRY_DATE=""
	if [[ -n "${EXPIRY_DAYS}" ]] && [[ "${EXPIRY_DAYS}" =~ ^[0-9]+$ ]] && [[ ${EXPIRY_DAYS} -gt 0 ]]; then
		# Calculate expiration date (works on Linux and macOS)
		if date --version >/dev/null 2>&1; then
			# GNU date (Linux)
			EXPIRY_DATE=$(date -d "+${EXPIRY_DAYS} days" '+%Y-%m-%d')
		else
			# BSD date (macOS)
			EXPIRY_DATE=$(date -v+${EXPIRY_DAYS}d '+%Y-%m-%d')
		fi
		echo -e "${GREEN}Client will expire on: ${EXPIRY_DATE}${NC}"
	else
		echo -e "${GREEN}Client will not expire${NC}"
	fi

	# Canonical storage for client configs — same path used by the console
	# so both the CLI and the web UI find configs in a single place.
	local WS_CLIENTS_DIR="/etc/wireshield/clients"
	mkdir -p "${WS_CLIENTS_DIR}" 2>/dev/null || true
	chmod 700 "${WS_CLIENTS_DIR}" 2>/dev/null || true
	CLIENT_CONFIG="${WS_CLIENTS_DIR}/${CLIENT_NAME}.conf"

	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

# MTU 1420 prevents fragmentation issues over VPN tunnels
# See https://github.com/nitred/nr-wg-mtu-finder to find your optimal MTU
MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}
# Keep WireGuard handshakes active so 2FA session monitor stays accurate
PersistentKeepalive = 25" >"${CLIENT_CONFIG}"
	chmod 600 "${CLIENT_CONFIG}" 2>/dev/null || true

	# Add the client as a peer to the server configuration
	if [[ -n "${EXPIRY_DATE}" ]]; then
		echo -e "\n### Client ${CLIENT_NAME} | Expires: ${EXPIRY_DATE}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	# Enable 2FA for this client
	_ws_enable_2fa_for_client "${CLIENT_NAME}" "${CLIENT_WG_IPV4}" "${CLIENT_WG_IPV6}"

	# Generate QR code if qrencode is installed (handy for mobile clients)
	if command -v qrencode &>/dev/null; then
		echo ""
		echo -e "  ${WHITE}QR Code${NC}"
		echo ""
		qrencode -t ansiutf8 -l M -m 0 -s 1 <"${CLIENT_CONFIG}"
		echo ""
	fi

	_ws_ui_divider
	echo ""
	_ws_ui_success "Client created: ${WHITE}${CLIENT_NAME}${NC}"
	_ws_ui_kv "Config file" "${CLIENT_CONFIG}"
	if [[ -n "${EXPIRY_DATE}" ]]; then
		_ws_ui_kv "Expires" "${EXPIRY_DATE}"
	fi
	echo ""
	_ws_ui_info "Copy to your machine: scp root@<server>:${CLIENT_CONFIG} ."
	echo ""
}

function listClients() {
	# Print numbered list of existing clients (peers) from the server config.
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Client List${NC}"
	_ws_ui_divider

	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		_ws_ui_warn "No clients registered."
		return
	fi

	echo ""
	printf "  \033[0;90m%3s  %-22s %s\033[0m\n" "#" "Name" "Expires"
	_ws_ui_divider

	local count=0
	while IFS= read -r line; do
		if [[ $line =~ ^###[[:space:]]Client[[:space:]](.+) ]]; then
			count=$((count + 1))
			local client_info="${BASH_REMATCH[1]}"

			if [[ $client_info =~ ^([^[:space:]]+)[[:space:]]\|[[:space:]]Expires:[[:space:]]([0-9]{4}-[0-9]{2}-[0-9]{2})$ ]]; then
				local client_name="${BASH_REMATCH[1]}"
				local expiry_date="${BASH_REMATCH[2]}"
				printf "  \033[1;37m%3s\033[0m  %-22s \033[0;33m%s\033[0m\n" "$count" "$client_name" "$expiry_date"
			else
				printf "  \033[1;37m%3s\033[0m  %-22s \033[0;90m%s\033[0m\n" "$count" "$client_info" "never"
			fi
		fi
	done < "/etc/wireguard/${SERVER_WG_NIC}.conf"

	echo ""
	echo -e "  ${GRAY}${count} client(s) registered${NC}"
}

function revokeClient() {
	# Remove a client peer from the server config and delete related client
	# configuration files so the name can be safely reused.
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Revoke Client${NC}"
	_ws_ui_divider

	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		_ws_ui_warn "No clients registered."
		return
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# Remove the [Peer] block matching $CLIENT_NAME using the marker header
	# Support both header formats: with or without expiration suffix
	sed -i "/^### Client ${CLIENT_NAME} | Expires: .*$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf" 2>/dev/null || true
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${CLIENT_NAME}.conf"

	# also remove any matching client .conf files from common locations (/root and /home/*)
	# This ensures the user's configs are fully removed so the name can be reused safely
	SEARCH_DIRS=(/root /home)
	for base in "${SEARCH_DIRS[@]}"; do
		# remove client config files if they exist within depth 2
		find "$base" -maxdepth 2 -type f -name "${CLIENT_NAME}.conf" \
			-print -delete 2>/dev/null || true
	done

	# Apply changes to the live interface without bringing it fully down
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	_ws_ui_success "Client '${WHITE}${CLIENT_NAME}${NC}' revoked and .conf files removed."
}

function checkExpiredClients() {
	# Check for expired clients and remove them automatically
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Clean Up Expired${NC}"
	_ws_ui_divider
	echo ""
	
	# Get current date in YYYY-MM-DD format
	if date --version >/dev/null 2>&1; then
		# GNU date (Linux)
		CURRENT_DATE=$(date '+%Y-%m-%d')
	else
		# BSD date (macOS)
		CURRENT_DATE=$(date '+%Y-%m-%d')
	fi
	
	local expired_count=0
	local checked_count=0
	
	# Read all client entries with expiration dates
	while IFS= read -r line; do
		if [[ $line =~ ^###[[:space:]]Client[[:space:]]([^[:space:]]+)[[:space:]]\|[[:space:]]Expires:[[:space:]]([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
			CLIENT_NAME="${BASH_REMATCH[1]}"
			EXPIRY_DATE="${BASH_REMATCH[2]}"
			checked_count=$((checked_count + 1))
			
			# Convert dates to seconds for comparison
			if date --version >/dev/null 2>&1; then
				# GNU date (Linux)
				CURRENT_SECONDS=$(date -d "${CURRENT_DATE}" '+%s')
				EXPIRY_SECONDS=$(date -d "${EXPIRY_DATE}" '+%s')
			else
				# BSD date (macOS)
				CURRENT_SECONDS=$(date -j -f "%Y-%m-%d" "${CURRENT_DATE}" '+%s')
				EXPIRY_SECONDS=$(date -j -f "%Y-%m-%d" "${EXPIRY_DATE}" '+%s')
			fi
			
			if [[ ${CURRENT_SECONDS} -gt ${EXPIRY_SECONDS} ]]; then
				_ws_ui_warn "Removing: ${CLIENT_NAME} (expired ${EXPIRY_DATE})"
				
				# Remove the [Peer] block matching the client with expiration date
				# Using a more reliable pattern that escapes the pipe character
				sed -i "/^### Client ${CLIENT_NAME} | Expires: ${EXPIRY_DATE}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"
				
				# Also try to remove without expiration date format in case of pattern issues
				sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf" 2>/dev/null || true
				
				# Remove client config file from primary location
				HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
				rm -f "${HOME_DIR}/${CLIENT_NAME}.conf"
				
				# Remove from all common locations
				SEARCH_DIRS=(/root /home /etc/wireguard)
				for base in "${SEARCH_DIRS[@]}"; do
					find "$base" -maxdepth 2 -type f -name "${CLIENT_NAME}.conf" \
						-print -delete 2>/dev/null || true
				done
				
				_ws_ui_success "Client '${CLIENT_NAME}' removed"
				expired_count=$((expired_count + 1))
			fi
		fi
	done < "/etc/wireguard/${SERVER_WG_NIC}.conf"
	
	if [[ ${expired_count} -gt 0 ]]; then
		# Apply changes to the live interface
		wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
		echo ""
		_ws_ui_success "Removed ${expired_count} expired client(s)"
	else
		if [[ ${checked_count} -gt 0 ]]; then
			_ws_ui_success "No expired clients (checked ${checked_count} with expiry dates)"
		else
			_ws_ui_info "No clients with expiration dates found."
		fi
	fi
}

function _ws_ensure_auto_expiration() {
	# Silently ensure automatic daily check for expired clients via cron (12:00 AM)
	# Idempotent: safe to call multiple times; no terminal output
    
	# Create a cron-compatible script
	cat > /usr/local/bin/wireshield-check-expired <<'EOF'
#!/bin/bash
# WireShield automatic expiration checker

# Source the WireGuard params
if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
else
	exit 1
fi

# Get current date
if date --version >/dev/null 2>&1; then
	CURRENT_DATE=$(date '+%Y-%m-%d')
	CURRENT_SECONDS=$(date -d "${CURRENT_DATE}" '+%s')
else
	CURRENT_DATE=$(date '+%Y-%m-%d')
	CURRENT_SECONDS=$(date -j -f "%Y-%m-%d" "${CURRENT_DATE}" '+%s')
fi

expired_count=0

# Check and remove expired clients
while IFS= read -r line; do
	if [[ $line =~ ^###[[:space:]]Client[[:space:]]([^[:space:]]+)[[:space:]]\|[[:space:]]Expires:[[:space:]]([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
		CLIENT_NAME="${BASH_REMATCH[1]}"
		EXPIRY_DATE="${BASH_REMATCH[2]}"
		
		if date --version >/dev/null 2>&1; then
			EXPIRY_SECONDS=$(date -d "${EXPIRY_DATE}" '+%s')
		else
			EXPIRY_SECONDS=$(date -j -f "%Y-%m-%d" "${EXPIRY_DATE}" '+%s')
		fi
		
		if [[ ${CURRENT_SECONDS} -gt ${EXPIRY_SECONDS} ]]; then
			# Remove peer from config
			sed -i "/^### Client ${CLIENT_NAME} | Expires: ${EXPIRY_DATE}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"
			sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf" 2>/dev/null || true
			
			# Remove config files
			find /root /home /etc/wireguard -maxdepth 2 -type f -name "${CLIENT_NAME}.conf" -delete 2>/dev/null || true
			
			logger -t wireshield "Removed expired client: ${CLIENT_NAME} (expired on ${EXPIRY_DATE})"
			expired_count=$((expired_count + 1))
		fi
	fi
done < "/etc/wireguard/${SERVER_WG_NIC}.conf"

# Apply changes if any clients were removed
if [[ ${expired_count} -gt 0 ]]; then
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
	logger -t wireshield "Automatically removed ${expired_count} expired client(s)"
fi
EOF

	chmod +x /usr/local/bin/wireshield-check-expired
    
	# Add to crontab (runs daily at 12:00 AM)
	local cron_entry="0 0 * * * /usr/local/bin/wireshield-check-expired >/dev/null 2>&1"
    
	# Ensure entry exists
	if ! crontab -l 2>/dev/null | grep -q "wireshield-check-expired"; then
		(crontab -l 2>/dev/null; echo "$cron_entry") | crontab -
	fi
}

function uninstallWg() {
	# Complete uninstall of WireShield including WireGuard, 2FA service, and all related configs
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Uninstall${NC}"
	_ws_ui_divider
	echo ""
	echo -e "  ${BRED}This will permanently remove:${NC}"
	echo ""
	echo -e "  ${GRAY}•${NC} WireGuard and all VPN configurations"
	echo -e "  ${GRAY}•${NC} 2FA service, database, and certificates"
	echo -e "  ${GRAY}•${NC} SSL certificates and auto-renewal timers"
	echo -e "  ${GRAY}•${NC} All client configurations"
	echo ""
	_ws_ui_warn "Back up /etc/wireguard and /etc/wireshield first if needed."
	echo ""
	read -rp "$(echo -ne "  Proceed with removal? ${GRAY}[y/N]${NC} > ")" -e REMOVE
	REMOVE=${REMOVE:-N}
	if [[ $REMOVE == 'y' ]]; then
		# Ask about Let's Encrypt certs (only if installed that way)
		local REMOVE_LE_CERTS=N
		if [[ -f /etc/wireshield/2fa/config.env ]] && \
		   grep -q "^WS_2FA_SSL_TYPE=letsencrypt" /etc/wireshield/2fa/config.env 2>/dev/null; then
			echo ""
			read -rp "$(echo -ne "  Also delete Let's Encrypt certificates? ${GRAY}[y/N]${NC} > ")" -e REMOVE_LE_CERTS
			REMOVE_LE_CERTS=${REMOVE_LE_CERTS:-N}
		fi

		# Collect client names before removing /etc/wireguard
		CLIENT_NAMES=()
		if [[ -n "${SERVER_WG_NIC}" ]] && [[ -f "/etc/wireguard/${SERVER_WG_NIC}.conf" ]]; then
			while IFS= read -r name; do
				CLIENT_NAMES+=("${name}")
			done < <(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | awk '{print $3}')
		fi

		# Silent mode: automatically remove client .conf files as part of uninstall
		DELETE_CLIENT_FILES=Y

		checkOS

		# ── Step 1: Stop 2FA service FIRST so its watchdog can't re-insert
		#            iptables rules while we're tearing them down.
		_ws_ui_info "Stopping 2FA service..."
		if [[ ${OS} == 'alpine' ]]; then
			rc-service wireshield stop 2>/dev/null || true
			rc-update del wireshield 2>/dev/null || true
			rm -f /etc/init.d/wireshield 2>/dev/null || true
		else
			systemctl stop wireshield.service 2>/dev/null || true
			systemctl disable wireshield.service 2>/dev/null || true
			systemctl stop wireshield-2fa 2>/dev/null || true
			systemctl disable wireshield-2fa 2>/dev/null || true
			systemctl stop wireshield-2fa-renew.timer 2>/dev/null || true
			systemctl disable wireshield-2fa-renew.timer 2>/dev/null || true
			systemctl stop wireshield-2fa-renew.service 2>/dev/null || true
			systemctl disable wireshield-2fa-renew.service 2>/dev/null || true
		fi

		# ── Step 2: wg-quick down — cleanly triggers PostDown hooks, which
		#            remove most iptables/ipset rules installed by WireShield.
		if [[ -n "${SERVER_WG_NIC}" ]] && [[ -f "/etc/wireguard/${SERVER_WG_NIC}.conf" ]]; then
			_ws_ui_info "Shutting down WireGuard interface ${SERVER_WG_NIC}..."
			wg-quick down "${SERVER_WG_NIC}" 2>/dev/null || true
		fi

		_ws_ui_info "Removing WireGuard services..."
		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${SERVER_WG_NIC}" stop 2>/dev/null || true
			rc-update del "wg-quick.${SERVER_WG_NIC}" 2>/dev/null || true
			unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}" 2>/dev/null || true
			rc-update del sysctl 2>/dev/null || true
		else
			systemctl stop "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true
			systemctl disable "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true
		fi

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode 2>/dev/null || true
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode 2>/dev/null || true
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools qrencode 2>/dev/null || true
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms 2>/dev/null || true
				dnf copr disable -y jdoss/wireguard 2>/dev/null || true
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools 2>/dev/null || true
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode 2>/dev/null || true
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools qrencode 2>/dev/null || true
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode 2>/dev/null || true
		elif [[ ${OS} == 'alpine' ]]; then
			(cd qrencode-4.1.1 2>/dev/null && make uninstall 2>/dev/null) || true
			rm -rf qrencode-* 2>/dev/null || true
			apk del wireguard-tools libqrencode libqrencode-tools 2>/dev/null || true
		fi

		_ws_ui_info "Removing WireGuard configuration..."
		rm -rf /etc/wireguard 2>/dev/null || true
		rm -f /etc/sysctl.d/wg.conf 2>/dev/null || true

		# Remove 2FA gating firewall structures (defensive — wg-quick down
		# should have handled most of this, but re-run in case the interface
		# was already absent or PostDown failed).
		_ws_ui_info "Removing 2FA firewall rules..."
		iptables -D FORWARD -j WS_2FA_PORTAL 2>/dev/null || true
		iptables -F WS_2FA_PORTAL 2>/dev/null || true
		iptables -X WS_2FA_PORTAL 2>/dev/null || true
		iptables -t nat -D PREROUTING -j WS_2FA_REDIRECT 2>/dev/null || true
		iptables -t nat -F WS_2FA_REDIRECT 2>/dev/null || true
		iptables -t nat -X WS_2FA_REDIRECT 2>/dev/null || true
		ip6tables -D FORWARD -j WS_2FA_PORTAL6 2>/dev/null || true
		ip6tables -F WS_2FA_PORTAL6 2>/dev/null || true
		ip6tables -X WS_2FA_PORTAL6 2>/dev/null || true
		ip6tables -t nat -D PREROUTING -j WS_2FA_REDIRECT6 2>/dev/null || true
		ip6tables -t nat -F WS_2FA_REDIRECT6 2>/dev/null || true
		ip6tables -t nat -X WS_2FA_REDIRECT6 2>/dev/null || true
		ipset destroy ws_2fa_allowed_v4 2>/dev/null || true
		ipset destroy ws_2fa_allowed_v6 2>/dev/null || true

		# Remove runtime-inserted iptables rules that aren't tied to
		# wg-quick's PostDown: the global ESTABLISHED,RELATED FORWARD
		# rule and any residual WG-subnet MASQUERADE entries left behind
		# by old installs (pre-3.0.2 split-tunnel feature, now removed).
		_ws_ui_info "Removing runtime-inserted iptables rules..."
		while iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do
			iptables -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || break
		done
		if [[ -n "${SERVER_WG_IPV4}" ]]; then
			local wg_subnet="${SERVER_WG_IPV4%.*}.0/24"
			while iptables -t nat -S POSTROUTING 2>/dev/null | grep -q "${wg_subnet%/*}"; do
				local rule
				rule=$(iptables -t nat -S POSTROUTING 2>/dev/null | grep "${wg_subnet%/*}" | head -1 | sed 's/^-A /-D /')
				[[ -z "$rule" ]] && break
				# shellcheck disable=SC2086
				eval iptables -t nat $rule 2>/dev/null || break
			done
		fi

		# Remove activity logging rules (best effort)
		if pgrep firewalld >/dev/null 2>&1; then
			firewall-cmd --remove-rich-rule='rule family=ipv4 source address=0.0.0.0/0 log prefix="[WS-Audit] " level="info"' --permanent 2>/dev/null || true
			firewall-cmd --remove-rich-rule='rule family=ipv6 source address=::/0 log prefix="[WS-Audit] " level="info"' --permanent 2>/dev/null || true
			# Also remove non-permanent variants just in case
			firewall-cmd --remove-rich-rule='rule family=ipv4 source address=0.0.0.0/0 log prefix="[WS-Audit] " level="info"' 2>/dev/null || true
		else
			iptables -D FORWARD -i "${SERVER_WG_NIC}" -m state --state NEW -j LOG --log-prefix '[WS-Audit] ' --log-level 4 2>/dev/null || true
			ip6tables -D FORWARD -i "${SERVER_WG_NIC}" -m state --state NEW -j LOG --log-prefix '[WS-Audit] ' --log-level 4 2>/dev/null || true
		fi

		# Close 2FA service TCP ports
		local _ws_2fa_port_rm _ws_2fa_http_port_rm
		_ws_2fa_port_rm=443
		_ws_2fa_http_port_rm=80
		if [[ -f /etc/wireshield/2fa/config.env ]]; then
			# shellcheck disable=SC1091
			source /etc/wireshield/2fa/config.env 2>/dev/null || true
			_ws_2fa_port_rm=${WS_2FA_PORT:-443}
			_ws_2fa_http_port_rm=${WS_2FA_HTTP_PORT:-80}
		fi
		if pgrep firewalld >/dev/null 2>&1; then
			firewall-cmd --remove-port ${_ws_2fa_port_rm}/tcp --permanent 2>/dev/null || true
			firewall-cmd --remove-port ${_ws_2fa_http_port_rm}/tcp --permanent 2>/dev/null || true
			firewall-cmd --reload 2>/dev/null || true
		else
			iptables -D INPUT -p tcp --dport ${_ws_2fa_port_rm} -j ACCEPT 2>/dev/null || true
			iptables -D INPUT -p tcp --dport ${_ws_2fa_http_port_rm} -j ACCEPT 2>/dev/null || true
			ip6tables -D INPUT -p tcp --dport ${_ws_2fa_port_rm} -j ACCEPT 2>/dev/null || true
			ip6tables -D INPUT -p tcp --dport ${_ws_2fa_http_port_rm} -j ACCEPT 2>/dev/null || true
		fi

		# Remove automatic expiration cron job and helper script
		_ws_ui_info "Removing client expiration service..."
		rm -f /usr/local/bin/wireshield-check-expired 2>/dev/null || true
		# Remove crontab entry if present (ignore errors when crontab unset)
		if crontab -l 2>/dev/null | grep -q "wireshield-check-expired"; then
			crontab -l 2>/dev/null | sed '/wireshield-check-expired/d' | crontab - 2>/dev/null || true
		fi

		# Remove activity log archiving
		_ws_ui_info "Removing activity log services..."
		rm -f /usr/local/bin/wireshield-archive-logs 2>/dev/null || true
		rm -rf /var/log/wireshield 2>/dev/null || true
		if crontab -l 2>/dev/null | grep -q "wireshield-archive-logs"; then
			crontab -l 2>/dev/null | sed '/wireshield-archive-logs/d' | crontab - 2>/dev/null || true
		fi

		# Remove systemd service/timer unit files (services were already
		# stopped in Step 1). Glob pattern catches any wireshield-* variant.
		_ws_ui_info "Removing systemd unit files..."
		if [[ ${OS} != 'alpine' ]]; then
			rm -f /etc/systemd/system/wireshield*.service 2>/dev/null || true
			rm -f /etc/systemd/system/wireshield*.timer 2>/dev/null || true
			systemctl reset-failed 2>/dev/null || true
			systemctl daemon-reload 2>/dev/null || true
		fi

		# Remove 2FA directory (database, certificates, configs, console assets)
		_ws_ui_info "Removing 2FA configuration, database, and console data..."
		rm -rf /etc/wireshield 2>/dev/null || true

		# Remove Let's Encrypt symlinks if they exist
		rm -f /usr/local/bin/wireshield-renew-cert 2>/dev/null || true

		# Optionally remove Let's Encrypt certificates
		if [[ "${REMOVE_LE_CERTS}" == "y" || "${REMOVE_LE_CERTS}" == "Y" ]]; then
			_ws_ui_info "Removing Let's Encrypt certificates..."
			if command -v certbot &>/dev/null; then
				# Collect WireShield-issued certificate names (best-effort)
				local _ws_cert_names
				_ws_cert_names=$(certbot certificates 2>/dev/null \
					| awk -F ': ' '/Certificate Name/ {print $2}')
				if [[ -n "${_ws_cert_names}" ]]; then
					while IFS= read -r _cn; do
						[[ -z "$_cn" ]] && continue
						certbot delete --cert-name "$_cn" --non-interactive 2>/dev/null || true
					done <<< "${_ws_cert_names}"
				fi
			fi
		fi

		# Remove Python packages installed for 2FA (optional, only if user confirms)
		# Keep commented as removing python3 might break other services
		# apt-get remove -y python3-fastapi python3-uvicorn python3-pyotp 2>/dev/null || true

		# Remove client config files from user home directories
		_ws_ui_info "Removing client configurations..."
		SEARCH_DIRS=(/root /home)
		for cname in "${CLIENT_NAMES[@]}"; do
			for base in "${SEARCH_DIRS[@]}"; do
				# remove client config files if they exist within depth 2
				find "$base" -maxdepth 2 -type f \( -name "${cname}.conf" -o -name "${cname}.png" \) \
					-print -delete 2>/dev/null
			done
		done

		# Reload sysctl defaults
		if [[ ${OS} != 'alpine' ]]; then
			sysctl --system 2>/dev/null || true
		fi

		# Final verification — check the interface itself is gone
		local WG_STILL_UP=0
		if [[ -n "${SERVER_WG_NIC}" ]] && ip link show "${SERVER_WG_NIC}" &>/dev/null; then
			WG_STILL_UP=1
			# Last-resort: delete the interface directly
			ip link delete "${SERVER_WG_NIC}" 2>/dev/null || true
			ip link show "${SERVER_WG_NIC}" &>/dev/null || WG_STILL_UP=0
		fi

		if [[ ${WG_STILL_UP} -eq 1 ]]; then
			echo ""
			_ws_ui_error "WireGuard interface ${SERVER_WG_NIC} still present. Manual cleanup may be needed:"
			_ws_ui_info "  sudo ip link delete ${SERVER_WG_NIC}"
			exit 1
		else
			echo ""
			_ws_ui_divider
			echo ""
			_ws_ui_success "WireGuard interface removed"
			_ws_ui_success "2FA service stopped and removed"
			_ws_ui_success "Firewall rules, ipsets, and NAT entries cleaned"
			_ws_ui_success "SSL certificates and renewal timers removed"
			_ws_ui_success "Client configurations deleted"
			_ws_ui_success "Systemd units cleared and daemon reloaded"
			echo ""
			_ws_ui_info "Python packages remain installed (safe — may be used by other services)."
			_ws_ui_info "Distribution packages (wireguard-tools, qrencode) were removed where possible."
			echo ""
			exit 0
		fi
	else
		echo ""
		_ws_ui_info "Removal aborted."
	fi
}

function _ws_header() {
	# Dashboard-style header: brand line + live status pane.
	local peers active_sessions svc_status svc_dot svc_label
	local portal_status portal_dot portal_label
	local db="/etc/wireshield/2fa/auth.db"

	# Peer count from server config
	peers=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" 2>/dev/null || echo 0)

	# WireGuard service state
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status 2>/dev/null && svc_status="active" || svc_status="inactive"
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}" 2>/dev/null && svc_status="active" || svc_status="inactive"
	fi
	if [[ "${svc_status}" == "active" ]]; then
		svc_dot="${GREEN}●${NC}"
		svc_label="${GREEN}active${NC}"
	else
		svc_dot="${RED}●${NC}"
		svc_label="${RED}inactive${NC}"
	fi

	# 2FA portal service state (best-effort across init systems)
	portal_status="stopped"
	if systemctl is-active --quiet wireshield.service 2>/dev/null; then
		portal_status="running"
	elif [[ ${OS} == 'alpine' ]] && rc-service --quiet wireshield status 2>/dev/null; then
		portal_status="running"
	fi
	if [[ "${portal_status}" == "running" ]]; then
		portal_dot="${GREEN}●${NC}"
		portal_label="${GREEN}running${NC}"
	else
		portal_dot="${GRAY}○${NC}"
		portal_label="${GRAY}stopped${NC}"
	fi

	# Active 2FA sessions (non-expired) — best-effort, silent on failure
	active_sessions=0
	if [[ -r "${db}" ]] && command -v sqlite3 &>/dev/null; then
		active_sessions=$(sqlite3 "${db}" "SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now');" 2>/dev/null || echo 0)
	fi

	# Brand line
	echo ""
	echo -e "  ${WHITE}✻  WireShield${NC}  ${GRAY}v3.0.0${NC}   ${DIM}Zero-trust WireGuard VPN${NC}"
	_ws_ui_divider
	echo ""

	# Status dashboard
	printf "   ${GRAY}%-16s${NC} %b  ${DIM}%s · %s:%s${NC}\n" "WireGuard" "${svc_dot} ${svc_label}" "${SERVER_WG_NIC}" "${SERVER_PUB_IP}" "${SERVER_PORT}"
	printf "   ${GRAY}%-16s${NC} %b\n" "2FA Portal" "${portal_dot} ${portal_label}"
	printf "   ${GRAY}%-16s${NC} ${WHITE}%s${NC} ${DIM}configured${NC}  ${GRAY}·${NC}  ${WHITE}%s${NC} ${DIM}active session(s)${NC}\n" "Peers" "${peers}" "${active_sessions}"
	echo ""
}

function _ws_summary() {
	# Legacy compact one-liner retained for any external callers.
	local peers svc_status dot
	peers=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" 2>/dev/null || echo 0)
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status 2>/dev/null && svc_status="active" || svc_status="inactive"
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}" 2>/dev/null && svc_status="active" || svc_status="inactive"
	fi
	[[ "$svc_status" == "active" ]] && dot="${GREEN}●${NC}" || dot="${RED}●${NC}"
	echo -e "  ${GRAY}${SERVER_WG_NIC} · ${SERVER_PUB_IP}:${SERVER_PORT} · ${peers} clients ·${NC} ${dot} ${GRAY}${svc_status}${NC}"
}

function _ws_choose_client() {
	# Prompt the user to select one client from the existing list; prints the name.
	local number_of_clients
	number_of_clients=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")

	if [[ ${number_of_clients} -eq 0 ]]; then
		echo -e "  ${RED}✗${NC} No clients found." >&2
		return 1
	fi

	echo "" >&2
	echo -e "  ${CYAN}Select a client${NC}" >&2
	echo "" >&2
	local i=1
	while IFS= read -r name; do
		printf "  \033[1;37m%3s\033[0m  %s\n" "$i" "$name" >&2
		((i++))
	done < <(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3)
	echo "" >&2

	local choice
	until [[ ${choice} =~ ^[0-9]+$ ]] && [[ ${choice} -ge 1 ]] && [[ ${choice} -le ${number_of_clients} ]]; do
		read -rp "$(echo -ne "  \033[0;32m>\033[0m ")" choice
		if [[ ! ${choice} =~ ^[0-9]+$ ]]; then
			echo -e "  ${ORANGE}Please enter a valid number.${NC}" >&2
		fi
	done

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${choice}p"
}

function showClientQR() {
	# Render a QR code for a selected client's configuration (if available).
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Client QR Code${NC}"
	_ws_ui_divider

	if ! command -v qrencode &>/dev/null; then
		echo ""
		_ws_ui_warn "qrencode is not installed; cannot render QR in terminal."
		_ws_ui_info "You can still use the .conf file on your device."
		return 0
	fi

	local name home_dir cfg
	name=$(_ws_choose_client)

	if [[ -z "${name}" ]]; then
		_ws_ui_error "No client selected."
		return 1
	fi

	# Look in canonical location first, fall back to legacy per-user home
	cfg="/etc/wireshield/clients/${name}.conf"
	if [[ ! -f "${cfg}" ]]; then
		home_dir=$(getHomeDirForClient "${name}")
		cfg="${home_dir}/${name}.conf"
	fi

	if [[ ! -f "${cfg}" ]]; then
		_ws_ui_error "Config file not found for client '${name}'"
		return 1
	fi

	echo ""
	echo -e "  ${WHITE}${name}${NC}"
	echo ""
	# Strip comments and empty lines to reduce QR code size
	grep -vE '^\s*(#|$)' "${cfg}" | qrencode -t ansiutf8 -l L -m 1
}

function showStatus() {
	# Display WireGuard runtime status via `wg show`.
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Server Status${NC}"
	_ws_ui_divider
	echo ""
	wg show || true
}

function restartWireGuard() {
	# Restart the WireGuard interface service using the appropriate init system.
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Restart VPN${NC}"
	_ws_ui_divider
	echo ""
	if [[ ${OS} == 'alpine' ]]; then
		rc-service "wg-quick.${SERVER_WG_NIC}" restart
	else
		systemctl restart "wg-quick@${SERVER_WG_NIC}"
	fi
	_ws_ui_success "WireGuard (${SERVER_WG_NIC}) restarted"
}

function backupConfigs() {
	# Create a timestamped archive of /etc/wireguard for backup/portability.
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Backup${NC}"
	_ws_ui_divider
	echo ""
	local ts out
	ts=$(date +%Y%m%d-%H%M%S)
	out="/root/wireshield-backup-${ts}.tar.gz"
	if tar czf "${out}" /etc/wireguard 2>/dev/null; then
		_ws_ui_success "Backup saved to ${out}"
	else
		_ws_ui_error "Backup failed"
	fi
}

function viewAuditLogs() {
	# Display audit logs menu for users to view 2FA authentication logs.
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Audit Logs${NC}"
	_ws_ui_divider
	echo ""
	_ws_ui_menu_item "1" "View All" "Last 100 audit events"
	_ws_ui_menu_item "2" "Filter by User" "Logs for a specific client"
	_ws_ui_menu_item "3" "Statistics" "Audit event summary"
	_ws_ui_menu_item "4" "Export to CSV" "Save logs to file"
	_ws_ui_menu_item "b" "Back" ""
	echo ""

	local AUDIT_OPTION
	read -rp "$(echo -ne "  \033[0;32m>\033[0m ")" AUDIT_OPTION

	case "$AUDIT_OPTION" in
		1)
			echo ""
			sudo /etc/wireshield/2fa/2fa-helper.sh audit-logs
			;;
		2)
			echo ""
			read -rp "$(echo -ne "  Client ID \033[0;32m>\033[0m ")" client_id
			if [ -n "$client_id" ]; then
				sudo /etc/wireshield/2fa/2fa-helper.sh audit-logs-user "$client_id"
			fi
			;;
		3)
			echo ""
			sudo /etc/wireshield/2fa/2fa-helper.sh audit-stats
			;;
		4)
			echo ""
			read -rp "$(echo -ne "  Output path ${GRAY}[/tmp/wireshield_audit_logs.csv]${NC} \033[0;32m>\033[0m ")" output_file
			output_file=${output_file:-/tmp/wireshield_audit_logs.csv}
			sudo /etc/wireshield/2fa/2fa-helper.sh export-audit "$output_file"
			_ws_ui_success "Exported to ${output_file}"
			;;
		b|B|5)
			return
			;;
		*)
			_ws_ui_warn "Invalid option"
			;;
	esac
}

function removeClient2FA() {
	# Remove 2FA configuration for a specific client, allowing them to set it up again
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Remove Client 2FA${NC}"
	_ws_ui_divider

	# Check if 2FA service is installed
	if [[ ! -f /etc/wireshield/2fa/auth.db ]]; then
		echo ""
		_ws_ui_error "2FA database not found. Is 2FA service installed?"
		return 1
	fi

	local sqlite3_cmd="sqlite3 /etc/wireshield/2fa/auth.db"
	local client_list
	client_list=$($sqlite3_cmd "SELECT client_id, enabled, totp_secret FROM users ORDER BY client_id ASC;")

	if [[ -z "$client_list" ]]; then
		echo ""
		_ws_ui_warn "No clients have 2FA configured."
		return 1
	fi

	# Display formatted list
	echo ""
	printf "  \033[0;90m%3s  %-22s %s\033[0m\n" "#" "Client" "Status"
	_ws_ui_divider
	local index=1
	declare -a client_ids
	while IFS='|' read -r client_id enabled secret; do
		client_ids[$index]="$client_id"
		local status_str="${RED}disabled${NC}"
		[[ "$enabled" == "1" ]] && status_str="${GREEN}active${NC}"
		printf "  \033[1;37m%3s\033[0m  %-22s %b\n" "$index" "$client_id" "$status_str"
		((index++))
	done <<< "$client_list"

	echo ""
	read -rp "$(echo -ne "  Select client ${GRAY}(Enter to cancel)${NC} \033[0;32m>\033[0m ")" selection

	if [[ -z "$selection" ]] || [[ ! "$selection" =~ ^[0-9]+$ ]] || [[ $selection -lt 1 ]] || [[ $selection -gt ${#client_ids[@]} ]]; then
		_ws_ui_info "Cancelled"
		return 0
	fi

	local target_client="${client_ids[$selection]}"

	# Confirm removal
	echo ""
	_ws_ui_warn "This will remove 2FA for: ${WHITE}${target_client}${NC}"
	_ws_ui_info "The user will need to set up 2FA again on next connection."
	echo ""
	read -rp "$(echo -ne "  Type '${target_client}' to confirm \033[0;32m>\033[0m ")" confirm_input

	if [[ "$confirm_input" != "$target_client" ]]; then
		_ws_ui_info "Cancelled"
		return 0
	fi
	
	# Remove 2FA for this client
	echo ""
	echo "Removing 2FA for $target_client..."
	
	# Fetch current IPs before resetting/deleting
	local client_ips
	client_ips=$($sqlite3_cmd "SELECT wg_ipv4, wg_ipv6 FROM users WHERE client_id = '${target_client}';" 2>/dev/null)
	
	local ipv4=""
	local ipv6=""
	if [[ -n "$client_ips" ]]; then
		ipv4=$(echo "$client_ips" | cut -d'|' -f1)
		ipv6=$(echo "$client_ips" | cut -d'|' -f2)
	fi

	# Reset TOTP secret and disable user until they verify again
	$sqlite3_cmd "UPDATE users SET totp_secret = NULL, enabled = 0 WHERE client_id = '${target_client}';" 2>/dev/null
	
	# Delete all active sessions for this client
	$sqlite3_cmd "DELETE FROM sessions WHERE client_id = '${target_client}';" 2>/dev/null
	
	# Remove from ipset allowlist using the fetched IPs
	if command -v ipset &>/dev/null; then
		if [[ -n "$ipv4" ]]; then
			ipset del ws_2fa_allowed_v4 "$ipv4" 2>/dev/null || true
		fi
		if [[ -n "$ipv6" ]]; then
			ipset del ws_2fa_allowed_v6 "$ipv6" 2>/dev/null || true
		fi
	fi
	
	echo ""
	_ws_ui_success "2FA removed for ${WHITE}${target_client}${NC}"
	_ws_ui_info "User must verify 2FA again on next connection."
	
	# Log this action
	audit_log "$target_client" "2FA_REMOVED" "admin_action" "cli"
}


# ============================================================================
# Activity Logging & Auditing
# ============================================================================

function _ws_setup_log_archiving() {
	# Setup extraction and rotation of activity logs from journald to files
	# $1: retention days (default: read from params or 30)

	local retention="${1}"
	if [[ -z "${retention}" ]]; then
		if [[ -f /etc/wireguard/params ]]; then
			source /etc/wireguard/params
		fi
		retention="${ACTIVITY_LOG_RETENTION:-15}"
	fi

	# Create archive directory
	mkdir -p /var/log/wireshield/archives
	chmod 750 /var/log/wireshield
	chmod 750 /var/log/wireshield/archives

	# Create the archiving script
	cat > /usr/local/bin/wireshield-archive-logs <<EOF
#!/bin/bash
# WireShield Activity Log Archiver
# Extracts WS-Audit logs from journalctl and archives them daily.

LOG_DIR="/var/log/wireshield/archives"
RETENTION_DAYS=${retention}
DATE_YESTERDAY=\$(date -d "yesterday" '+%Y-%m-%d' 2>/dev/null || date -v-1d '+%Y-%m-%d')
LOG_FILE="\${LOG_DIR}/activity-\${DATE_YESTERDAY}.log"

# Extract logs for yesterday (00:00:00 to 23:59:59)
# We use journalctl with the specific tag.
# Note: journalctl --since and --until handle "yesterday" and "today" midnight correctly.

if journalctl --version &>/dev/null; then
    journalctl -k -g "WS-Audit" --since "yesterday" --until "today" --output=short-iso >> "\${LOG_FILE}"
fi

# Set permissions
chmod 640 "\${LOG_FILE}" 2>/dev/null

# Compress logs older than 1 day to save space (optional, skipping for simple text grep)
# gzip "\${LOG_DIR}/activity-*.log" ...

# Cleanup old logs
find "\${LOG_DIR}" -name "activity-*.log" -type f -mtime +\${RETENTION_DAYS} -delete
EOF

	chmod +x /usr/local/bin/wireshield-archive-logs

	# Add to crontab (runs daily at 00:10)
	local cron_job="10 0 * * * /usr/local/bin/wireshield-archive-logs >/dev/null 2>&1"
	(crontab -l 2>/dev/null | grep -v "wireshield-archive-logs"; echo "$cron_job") | crontab -
}

function toggleActivityLogging() {
	# Enable or Disable traffic logging via iptables/firewalld
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Toggle Activity Logging${NC}"
	_ws_ui_divider
	echo ""
	_ws_ui_info "Tracks NEW connections made by clients via iptables."
	echo ""

	# Check current status by looking for specific rule in wg0.conf
	# We look for the LOG rule in PostUp
	local log_enabled=0
	if grep -q "WS-Audit" "/etc/wireguard/${SERVER_WG_NIC}.conf"; then
		log_enabled=1
	fi

	if [[ ${log_enabled} -eq 1 ]]; then
		echo -e "Current status: ${GREEN}ENABLED${NC}"
		read -rp "Do you want to DISABLE activity logging? [y/N]: " -e CONFIRM
		if [[ ${CONFIRM} =~ ^[Yy]$ ]]; then
			# Remove rules
			# We use sed to delete lines containing "WS-Audit" from the config
			sed -i '/WS-Audit/d' "/etc/wireguard/${SERVER_WG_NIC}.conf"
			
			# Remove rules from runtime
			if pgrep firewalld >/dev/null 2>&1; then
				firewall-cmd --remove-rich-rule='rule family=ipv4 source address=0.0.0.0/0 log prefix="[WS-Audit] " level="info"' --permanent 2>/dev/null || true
				firewall-cmd --remove-rich-rule='rule family=ipv6 source address=::/0 log prefix="[WS-Audit] " level="info"' --permanent 2>/dev/null || true
				firewall-cmd --reload
			else
				# iptables: try to remove the specific LOG rule from FORWARD chain
				iptables -D FORWARD -i "${SERVER_WG_NIC}" -m state --state NEW -j LOG --log-prefix '[WS-Audit] ' --log-level 4 2>/dev/null || true
				ip6tables -D FORWARD -i "${SERVER_WG_NIC}" -m state --state NEW -j LOG --log-prefix '[WS-Audit] ' --log-level 4 2>/dev/null || true
			fi

			echo -e "${GREEN}Activity logging has been disabled.${NC}"
			wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
		fi
	else
		echo -e "Current status: ${ORANGE}DISABLED${NC}"
		read -rp "Do you want to ENABLE activity logging? [y/N]: " -e CONFIRM
		if [[ ${CONFIRM} =~ ^[Yy]$ ]]; then
			# Append PostUp/PostDown logging rules to the [Interface] section of wg0.conf
			
			local log_rule_v4=""
			local log_rule_v6=""
			
			if pgrep firewalld >/dev/null 2>&1; then
				# For firewalld, we add rich rules.
				# Note: Limiting to source address of the VPN subnet is better practice.
				log_rule_v4="PostUp = firewall-cmd --add-rich-rule='rule family=ipv4 source address=${SERVER_WG_IPV4}/24 log prefix=\"[WS-Audit] \" level=\"info\"'"
				log_rule_v6="PostUp = firewall-cmd --add-rich-rule='rule family=ipv6 source address=${SERVER_WG_IPV6}/64 log prefix=\"[WS-Audit] \" level=\"info\"'"
				# And PostDown
				local down_rule_v4="PostDown = firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${SERVER_WG_IPV4}/24 log prefix=\"[WS-Audit] \" level=\"info\"'"
				local down_rule_v6="PostDown = firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${SERVER_WG_IPV6}/64 log prefix=\"[WS-Audit] \" level=\"info\"'"
				
				# Insert into config
				# We want to insert these after other PostUp rules
				sed -i "/^PostUp = .*MASQUERADE/a ${log_rule_v4}\n${log_rule_v6}" "/etc/wireguard/${SERVER_WG_NIC}.conf"
				sed -i "/^PostDown = .*MASQUERADE/a ${down_rule_v4}\n${down_rule_v6}" "/etc/wireguard/${SERVER_WG_NIC}.conf"
				
				# Apply runtime
				firewall-cmd --add-rich-rule="rule family=ipv4 source address=${SERVER_WG_IPV4}/24 log prefix=\"[WS-Audit] \" level=\"info\""
				firewall-cmd --add-rich-rule="rule family=ipv6 source address=${SERVER_WG_IPV6}/64 log prefix=\"[WS-Audit] \" level=\"info\""

			else
				# Standard iptables
				# We log NEW connections coming from the wireguard interface
				log_rule_v4="PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -m state --state NEW -j LOG --log-prefix '[WS-Audit] ' --log-level 4"
				log_rule_v6="PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -m state --state NEW -j LOG --log-prefix '[WS-Audit] ' --log-level 4"
				
				local down_rule_v4="PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -m state --state NEW -j LOG --log-prefix '[WS-Audit] ' --log-level 4"
				local down_rule_v6="PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -m state --state NEW -j LOG --log-prefix '[WS-Audit] ' --log-level 4"
				
				# Insert into config
				sed -i "/^PostUp = .*MASQUERADE/a ${log_rule_v4}\n${log_rule_v6}" "/etc/wireguard/${SERVER_WG_NIC}.conf"
				sed -i "/^PostDown = .*MASQUERADE/a ${down_rule_v4}\n${down_rule_v6}" "/etc/wireguard/${SERVER_WG_NIC}.conf"
				
				# Apply runtime
				iptables -I FORWARD -i "${SERVER_WG_NIC}" -m state --state NEW -j LOG --log-prefix '[WS-Audit] ' --log-level 4
				ip6tables -I FORWARD -i "${SERVER_WG_NIC}" -m state --state NEW -j LOG --log-prefix '[WS-Audit] ' --log-level 4
			fi

			# Ensure archiving is set up
			_ws_setup_log_archiving
			
			echo -e "${GREEN}Activity logging has been enabled.${NC}"
			echo "Traffic will be logged to system journal and archived to /var/log/wireshield/archives."
			wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
		fi
	fi
}

function configureLogRetention() {
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Log Retention${NC}"
	_ws_ui_divider
	echo ""
	_ws_ui_info "Logs older than the retention period are automatically deleted."
	
	# Read current retention from config
	local current_retention="30"
	local config_file="/etc/wireshield/2fa/config.env"
	if [[ -f "${config_file}" ]]; then
		local env_val=$(grep "^WS_2FA_ACTIVITY_LOG_RETENTION_DAYS=" "${config_file}" | cut -d'=' -f2)
		[[ -n "$env_val" ]] && current_retention="$env_val"
	fi

	read -rp "$(echo -ne "  ${GRAY}Retention days${NC}  > ")" -e -i "${current_retention}" DAYS
	DAYS=${DAYS:-$current_retention}

	if [[ ! "${DAYS}" =~ ^[0-9]+$ ]] || [[ "${DAYS}" -le 0 ]]; then
		_ws_ui_warn "Invalid input. Please enter a positive number."
		return
	fi

	# Update config.env
	if [[ -f "${config_file}" ]]; then
		if grep -q "^WS_2FA_ACTIVITY_LOG_RETENTION_DAYS=" "${config_file}"; then
			sed -i "s/^WS_2FA_ACTIVITY_LOG_RETENTION_DAYS=.*/WS_2FA_ACTIVITY_LOG_RETENTION_DAYS=${DAYS}/" "${config_file}"
		else
			echo "WS_2FA_ACTIVITY_LOG_RETENTION_DAYS=${DAYS}" >> "${config_file}"
		fi
	else
		mkdir -p /etc/wireshield/2fa
		echo "WS_2FA_ACTIVITY_LOG_RETENTION_DAYS=${DAYS}" > "${config_file}"
	fi

	_ws_ui_success "Retention period updated to ${DAYS} days."
	_ws_ui_info "Restart service for changes to take effect: sudo systemctl restart wireshield"
}

function viewUserActivityLogs() {
	echo ""
	echo -e "  ${WHITE}WireShield${NC} ${GRAY}/View Activity Logs${NC}"
	_ws_ui_divider
	echo ""

	# Check if database exists
	if [[ ! -f /etc/wireshield/2fa/auth.db ]]; then
		_ws_ui_error "Activity log database not found."
		return
	fi
	
	local sqlite3_cmd="sqlite3 /etc/wireshield/2fa/auth.db"
	
	# Check if there are any logs
	local log_count=$($sqlite3_cmd "SELECT COUNT(*) FROM activity_log;" 2>/dev/null)
	if [[ -z "$log_count" ]] || [[ "$log_count" -eq 0 ]]; then
		_ws_ui_warn "No activity logs found in database."
		echo "Make sure activity logging is enabled and traffic is flowing."
		return
	fi
	
	echo "Select filter:"
	echo "   1) View all logs (last 100)"
	echo "   2) Filter by specific user/client"
	read -rp "Option [1-2]: " -e OPT
	
	local where_clause=""
	local selected_client=""
	
	if [[ "$OPT" == "2" ]]; then
		# Get list of users with activity
		echo ""
		echo "Users with activity logs:"
		local user_list=$($sqlite3_cmd "SELECT DISTINCT client_id FROM activity_log WHERE client_id IS NOT NULL ORDER BY client_id;" 2>/dev/null)
		
		if [[ -z "$user_list" ]]; then
			_ws_ui_warn "No user-associated logs found."
			return
		fi
		
		local i=1
		declare -a clients
		while IFS= read -r client; do
			clients[$i]="$client"
			echo "   $i) $client"
			((i++))
		done <<< "$user_list"
		
		echo ""
		read -rp "Select user number [1-$((i-1))]: " USER_NUM
		
		if [[ ! "$USER_NUM" =~ ^[0-9]+$ ]] || [[ "$USER_NUM" -lt 1 ]] || [[ "$USER_NUM" -ge "$i" ]]; then
			_ws_ui_warn "Invalid selection."
			return
		fi
		
		selected_client="${clients[$USER_NUM]}"
		where_clause="WHERE client_id = '${selected_client}'"
		echo -e "Showing logs for user: ${GREEN}${selected_client}${NC}"
	else
		echo -e "Showing logs for ${GREEN}ALL USERS${NC}"
	fi
	
	_ws_ui_info "Retrieving logs from database..."
	echo ""
	
	# Query database with optional domain resolution
	local query="
		SELECT 
			a.timestamp,
			COALESCE(a.client_id, 'System') as client,
			a.direction,
			a.protocol,
			a.src_ip,
			a.src_port,
			a.dst_ip,
			a.dst_port,
			COALESCE(d.domain, '-') as domain
		FROM activity_log a
		LEFT JOIN dns_cache d ON d.ip_address = a.dst_ip
		${where_clause}
		ORDER BY a.timestamp DESC
		LIMIT 100;
	"
	
	# Format output with column headers
	echo "┌────────────────────┬────────────┬──────┬────────┬─────────────────┬──────┬─────────────────┬──────┬────────────────────┐"
	printf "│ %-18s │ %-10s │ %-4s │ %-6s │ %-15s │ %-4s │ %-15s │ %-4s │ %-18s │\n" "Time" "Client" "Dir" "Proto" "Source IP" "Port" "Dest IP" "Port" "Domain"
	echo "├────────────────────┼────────────┼──────┼────────┼─────────────────┼──────┼─────────────────┼──────┼────────────────────┤"
	
	$sqlite3_cmd "$query" 2>/dev/null | while IFS='|' read -r ts client dir proto src_ip src_port dst_ip dst_port domain; do
		# Truncate long values
		client=$(echo "$client" | cut -c1-10)
		dir=$(echo "$dir" | cut -c1-4)
		proto=$(echo "$proto" | cut -c1-6)
		src_ip=$(echo "$src_ip" | cut -c1-15)
		src_port=$(echo "${src_port:-0}" | cut -c1-4)
		dst_ip=$(echo "$dst_ip" | cut -c1-15)
		dst_port=$(echo "${dst_port:-0}" | cut -c1-4)
		domain=$(echo "${domain:--}" | cut -c1-18)
		
		printf "│ %-18s │ %-10s │ %-4s │ %-6s │ %-15s │ %-4s │ %-15s │ %-4s │ %-18s │\n" "$ts" "$client" "$dir" "$proto" "$src_ip" "$src_port" "$dst_ip" "$dst_port" "$domain"
	done
	
	echo "└────────────────────┴────────────┴──────┴────────┴─────────────────┴──────┴─────────────────┴──────┴────────────────────┘"
	echo ""
	echo -e "${GREEN}Showing up to 100 most recent logs.${NC}"
}

function activityLogsMenu() {
	while true; do
		clear
		echo ""
		echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Activity Logs${NC}"
		_ws_ui_divider
		echo ""
		_ws_ui_menu_item "1" "Toggle Logging" "Enable or disable traffic capture"
		_ws_ui_menu_item "2" "Retention Period" "Configure log retention days"
		_ws_ui_menu_item "3" "View Logs" "Browse activity records"
		_ws_ui_menu_item "b" "Back" ""
		echo ""

		local OPT
		read -rp "$(echo -ne "  \033[0;32m>\033[0m ")" OPT

		case "$OPT" in
			1) toggleActivityLogging ;;
			2) configureLogRetention ;;
			3) viewUserActivityLogs ;;
			b|B|4) return ;;
			*) ;;
		esac
		echo ""
		read -rp "  Press Enter to continue..." _
	done
}

function audit_log() {
	# Simple audit log function for CLI actions
	local client_id="$1"
	local action="$2"
	local status="$3"
	local ip_address="${4:-cli}"
	
	local sqlite3_cmd="sqlite3 /etc/wireshield/2fa/auth.db"
	$sqlite3_cmd "INSERT INTO audit_log (client_id, action, status, ip_address) VALUES ('${client_id}', '${action}', '${status}', '${ip_address}');" 2>/dev/null || true
}

function consoleAccessMenu() {
	# Submenu for managing Web Console access permissions
	while true; do
		clear
		echo ""
		echo -e "  ${WHITE}WireShield${NC} ${GRAY}/Console Access${NC}"
		_ws_ui_divider
		echo ""
		echo -e "  ${GRAY}Dashboard${NC}  https://${SERVER_PUB_IP}:${WS_2FA_PORT:-443}/console"

		# Check DB
		if [[ ! -f /etc/wireshield/2fa/auth.db ]]; then
			echo ""
			_ws_ui_error "2FA database not found."
			read -rp "  Press Enter to return..." _
			return
		fi

		local sqlite3_cmd="sqlite3 /etc/wireshield/2fa/auth.db"
		local user_list
		user_list=$($sqlite3_cmd "SELECT client_id, console_access FROM users ORDER BY client_id ASC;" 2>/dev/null)

		if [[ -z "$user_list" ]]; then
			echo ""
			_ws_ui_warn "No users found in 2FA database."
		else
			echo ""
			printf "  \033[0;90m%3s  %-22s %s\033[0m\n" "#" "Client" "Access"
			_ws_ui_divider
			local i=1
			declare -a ids
			declare -a statuses

			while IFS='|' read -r client_id access; do
				ids[$i]="$client_id"
				statuses[$i]="$access"
				local dot="${RED}○ denied${NC}"
				[[ "$access" == "1" ]] && dot="${GREEN}● allowed${NC}"
				printf "  \033[1;37m%3s\033[0m  %-22s %b\n" "$i" "$client_id" "$dot"
				((i++))
			done <<< "$user_list"
		fi

		echo ""
		_ws_ui_info "Enter number to toggle access, or ${WHITE}b${NC}${DIM} to go back${NC}"
		echo ""

		local SEL
		read -rp "$(echo -ne "  \033[0;32m>\033[0m ")" SEL

		if [[ "$SEL" == "q" ]] || [[ "$SEL" == "b" ]] || [[ -z "$SEL" ]]; then
			return
		fi

		if [[ "$SEL" =~ ^[0-9]+$ ]] && [[ "$SEL" -ge 1 ]] && [[ "$SEL" -lt $i ]]; then
			local target="${ids[$SEL]}"
			local current="${statuses[$SEL]}"
			local new_status=1
			local verb="granted"
			if [[ "$current" == "1" ]]; then
				new_status=0
				verb="revoked"
			fi

			$sqlite3_cmd "UPDATE users SET console_access = ${new_status} WHERE client_id = '${target}';"
			echo ""
			_ws_ui_success "Access ${verb} for ${WHITE}${target}${NC}"
			sleep 1
		fi
	done
}

function manageMenu() {
	# Main interactive loop — categorized menu with inline descriptions.
	while true; do
		clear
		_ws_header

		_ws_ui_section "Client Management"
		_ws_ui_menu_item "1" "Create Client" "Add a new VPN peer"
		_ws_ui_menu_item "2" "List Clients" "Show all registered clients"
		_ws_ui_menu_item "3" "Display Client QR" "Render config as QR code"
		_ws_ui_menu_item "4" "Revoke Client" "Remove a client's access"
		_ws_ui_menu_item "5" "Clean Up Expired" "Remove expired clients"

		_ws_ui_section "Server Operations"
		_ws_ui_menu_item "6" "View Status" "WireGuard runtime info"
		_ws_ui_menu_item "7" "Restart VPN" "Restart the WireGuard service"
		_ws_ui_menu_item "8" "Backup Config" "Archive /etc/wireguard"

		_ws_ui_section "Security & Logging"
		_ws_ui_menu_item "9" "Audit Logs" "View 2FA authentication events"
		_ws_ui_menu_item "10" "Remove Client 2FA" "Reset a client's authenticator"
		_ws_ui_menu_item "11" "Activity Logs" "Traffic logging management"
		_ws_ui_menu_item "12" "Console Access" "Web dashboard permissions"

		_ws_ui_section "System"
		_ws_ui_menu_item "13" "Uninstall" "Remove WireShield completely"
		_ws_ui_menu_item "q" "Exit" ""
		echo ""
		_ws_ui_divider
		echo -e "  ${DIM}Select an option (1-13, q to exit)${NC}"

		local MENU_OPTION=""
		read -rp "$(echo -ne "  ${GREEN}›${NC} ")" MENU_OPTION

		case "${MENU_OPTION}" in
		1) newClient ;;
		2) listClients ;;
		3) showClientQR ;;
		4) revokeClient ;;
		5) checkExpiredClients ;;
		6) showStatus ;;
		7) restartWireGuard ;;
		8) backupConfigs ;;
		9) viewAuditLogs ;;
		10) removeClient2FA ;;
		11) activityLogsMenu ;;
		12) consoleAccessMenu ;;
		13) uninstallWg ;;
		q|Q|14) exit 0 ;;
		*) continue ;;
		esac

		echo ""
		read -rp "  Press Enter to continue..." _
	done
}

# ================ Programmatic API (automation) =================

# Ensure /etc/wireguard/params is loaded (idempotent)
function _ws_ensure_params_loaded() {
	if [[ -z "${SERVER_WG_NIC}" ]] && [[ -e /etc/wireguard/params ]]; then
		# shellcheck disable=SC1091
		source /etc/wireguard/params
		if [[ -z "${SERVER_LOCAL_IPV4}" ]] && [[ -n "${SERVER_PUB_NIC}" ]]; then
			SERVER_LOCAL_IPV4=$(get_interface_ipv4 "${SERVER_PUB_NIC}")
		fi
		if [[ -z "${SERVER_LOCAL_IPV4}" ]] && [[ -n "${SERVER_WG_IPV4}" ]]; then
			SERVER_LOCAL_IPV4="${SERVER_WG_IPV4}"
		fi
	fi
}

# Minimal JSON string escaper (handles quotes and backslashes)
function _ws_json_escape() {
	local s="$1"
	s=${s//\\/\\\\}
	s=${s//\"/\\\"}
	s=${s//$'\n'/} # strip newlines
	echo -n "$s"
}

# ws_list_clients_json: print JSON array of clients with name and optional expiry
# Usage: ws_list_clients_json
function ws_list_clients_json() {
	_ws_ensure_params_loaded
	local cfg="/etc/wireguard/${SERVER_WG_NIC}.conf"
	if [[ ! -f "$cfg" ]]; then
		echo '[]'
		return 0
	fi

	local out="[" first=1
	while IFS= read -r line; do
		if [[ $line =~ ^###[[:space:]]Client[[:space:]](.+) ]]; then
			local info="${BASH_REMATCH[1]}" name expiry=""
			if [[ $info =~ ^([^[:space:]]+)[[:space:]]\|[[:space:]]Expires:[[:space:]]([0-9]{4}-[0-9]{2}-[0-9]{2})$ ]]; then
				name="${BASH_REMATCH[1]}"
				expiry="${BASH_REMATCH[2]}"
			else
				name="$info"
				expiry=""
			fi
			if [[ $first -eq 0 ]]; then out+=" , "; fi
			first=0
			out+="{\"name\":\"$(_ws_json_escape "$name")\",\"expires\":"
			if [[ -n "$expiry" ]]; then
				out+="\"$expiry\""
			else
				out+="null"
			fi
			out+="}"
		fi
	done < "$cfg"
	out+="]"
	echo -n "$out"
}

# ws_get_client_config NAME: print the client config content to stdout
function ws_get_client_config() {
	_ws_ensure_params_loaded
	local name="$1"
	if [[ -z "$name" ]]; then
		echo "Error: missing client name" 1>&2
		return 2
	fi
	# Canonical location first, then legacy per-user home for backwards compat
	local cfg home_dir
	cfg="/etc/wireshield/clients/${name}.conf"
	if [[ ! -f "$cfg" ]]; then
		home_dir=$(getHomeDirForClient "$name")
		cfg="${home_dir}/${name}.conf"
	fi
	if [[ ! -f "$cfg" ]]; then
		echo "Error: config not found for client '$name'" 1>&2
		return 1
	fi
	cat "$cfg"
}

# ws_revoke_client NAME: revoke by name (non-interactive)
function ws_revoke_client() {
	_ws_ensure_params_loaded
	local name="$1"
	if [[ -z "$name" ]]; then
		echo "Error: missing client name" 1>&2
		return 2
	fi
	local cfg="/etc/wireguard/${SERVER_WG_NIC}.conf"
	if [[ ! -f "$cfg" ]]; then
		echo "Error: server config not found: $cfg" 1>&2
		return 1
	fi
	# Remove both header variants
	sed -i "/^### Client ${name} | Expires: .*$/,/^$/d" "$cfg" 2>/dev/null || true
	sed -i "/^### Client ${name}\$/,/^$/d" "$cfg"

	# Remove client config files from all known locations (canonical +
	# legacy per-user homes from older installs).
	local home_dir
	home_dir=$(getHomeDirForClient "$name")
	rm -f "/etc/wireshield/clients/${name}.conf"
	rm -f "${home_dir}/${name}.conf"
	find /root /home /etc/wireguard -maxdepth 2 -type f -name "${name}.conf" -delete 2>/dev/null || true

	# Apply live
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
	echo "{\"revoked\":true,\"name\":\"$(_ws_json_escape "$name")\"}"
}

# ws_add_client --name <name> [--days N | --expires YYYY-MM-DD]
#                [--ipv4-last OCTET] [--ipv6-id ID]
# Non-interactive: allocates free IPs if not provided; prints JSON summary.
function ws_add_client() {
	_ws_ensure_params_loaded
	local name="" days="" expires="" ipv4_last="" ipv6_id=""
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--name) name="$2"; shift 2;;
			--days) days="$2"; shift 2;;
			--expires) expires="$2"; shift 2;;
			--ipv4-last) ipv4_last="$2"; shift 2;;
			--ipv6-id) ipv6_id="$2"; shift 2;;
			*) echo "Unknown option: $1" 1>&2; return 2;;
		esac
	done
	if [[ -z "$name" ]]; then
		echo "Error: --name is required" 1>&2
		return 2
	fi
	if ! [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] || [[ ${#name} -ge 16 ]]; then
		echo "Error: invalid client name" 1>&2
		return 2
	fi

	local cfg="/etc/wireguard/${SERVER_WG_NIC}.conf"
	if grep -q -E "^### Client ${name}$" "$cfg"; then
		echo "Error: client exists" 1>&2
		return 1
	fi

	# Determine IPv4 last octet
	local base_v4 last dot_exists
	base_v4=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	if [[ -n "$ipv4_last" ]]; then
		last="$ipv4_last"
	else
	    for last in {2..254}; do
		    # Look for an existing peer using this IPv4 in the server config
		    # Match the AllowedIPs line to avoid false positives
		    dot_exists=$(grep -c -E "^AllowedIPs = ${base_v4}\\.${last}/32" "$cfg")
		    if [[ $dot_exists == 0 ]]; then break; fi
	    done
	fi
	local client_v4="${base_v4}.${last}"

	# Determine IPv6 id
	local base_v6
	base_v6=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	if [[ -z "$ipv6_id" ]]; then ipv6_id="$last"; fi
	local client_v6="${base_v6}::${ipv6_id}"

	# Keys
	local priv pub psk
	priv=$(wg genkey)
	pub=$(echo "$priv" | wg pubkey)
	psk=$(wg genpsk)

	# Expiry date
	local exp=""
	if [[ -n "$expires" ]]; then
		exp="$expires"
	elif [[ -n "$days" ]] && [[ "$days" =~ ^[0-9]+$ ]] && [[ $days -gt 0 ]]; then
		if date --version >/dev/null 2>&1; then
			exp=$(date -d "+${days} days" '+%Y-%m-%d')
		else
			exp=$(date -v+${days}d '+%Y-%m-%d')
		fi
	fi

	# Client file — same canonical path used by newClient() and the console
	local client_cfg endpoint
	local WS_CLIENTS_DIR="/etc/wireshield/clients"
	mkdir -p "${WS_CLIENTS_DIR}" 2>/dev/null || true
	chmod 700 "${WS_CLIENTS_DIR}" 2>/dev/null || true
	client_cfg="${WS_CLIENTS_DIR}/${name}.conf"
	endpoint="${SERVER_PUB_IP}:${SERVER_PORT}"
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]] && [[ ${SERVER_PUB_IP} != *"["* ]] && [[ ${SERVER_PUB_IP} != *"]"* ]]; then
		endpoint="[${SERVER_PUB_IP}]:${SERVER_PORT}"
	fi
	cat >"$client_cfg" <<CFG
[Interface]
PrivateKey = ${priv}
Address = ${client_v4}/32,${client_v6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${psk}
Endpoint = ${endpoint}
AllowedIPs = ${ALLOWED_IPS}
CFG

	# Append peer to server config
	if [[ -n "$exp" ]]; then
		echo -e "\n### Client ${name} | Expires: ${exp}
[Peer]
PublicKey = ${pub}
PresharedKey = ${psk}
AllowedIPs = ${client_v4}/32,${client_v6}/128" >>"$cfg"
	else
		echo -e "\n### Client ${name}
[Peer]
PublicKey = ${pub}
PresharedKey = ${psk}
AllowedIPs = ${client_v4}/32,${client_v6}/128" >>"$cfg"
	fi

	chmod 600 "$client_cfg"
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	# JSON summary
	echo -n "{\"name\":\"$(_ws_json_escape "$name")\",\"ipv4\":\"${client_v4}\",\"ipv6\":\"${client_v6}\",\"expires\":"
	if [[ -n "$exp" ]]; then echo -n "\"$exp\""; else echo -n "null"; fi
	echo -n ",\"config_path\":\"$(_ws_json_escape "$client_cfg")\"}"
}

# ws_check_expired_json: run expiration cleanup and print JSON {removed:[names]}
function ws_check_expired_json() {
	_ws_ensure_params_loaded
	local cfg="/etc/wireguard/${SERVER_WG_NIC}.conf"; [[ -f "$cfg" ]] || { echo '{"removed":[]}'; return 0; }
	local removed=() name exp
	# Get current date seconds
	local now_s
	if date --version >/dev/null 2>&1; then
		now_s=$(date '+%s')
	else
		now_s=$(date '+%s')
	fi
	while IFS= read -r line; do
		if [[ $line =~ ^###[[:space:]]Client[[:space:]]([^[:space:]]+)[[:space:]]\|[[:space:]]Expires:[[:space:]]([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
			name="${BASH_REMATCH[1]}"; exp="${BASH_REMATCH[2]}"
			local exp_s
			if date --version >/dev/null 2>&1; then
				exp_s=$(date -d "$exp" '+%s')
			else
				exp_s=$(date -j -f "%Y-%m-%d" "$exp" '+%s')
			fi
			if [[ $now_s -gt $exp_s ]]; then
				# delete blocks
				sed -i "/^### Client ${name} | Expires: ${exp}\$/,/^$/d" "$cfg"
				sed -i "/^### Client ${name}\$/,/^$/d" "$cfg" 2>/dev/null || true
				# remove files
				find /root /home /etc/wireguard -maxdepth 2 -type f -name "${name}.conf" -delete 2>/dev/null || true
				removed+=("$name")
			fi
		fi
	done < "$cfg"
	if [[ ${#removed[@]} -gt 0 ]]; then
		wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
	fi
	# print JSON
	echo -n '{"removed":['
	local i
	for ((i=0; i<${#removed[@]}; i++)); do
		if [[ $i -gt 0 ]]; then echo -n ','; fi
		echo -n "\"$(_ws_json_escape "${removed[$i]}")\""
	done
	echo -n ']}'
}

# Only run the interactive menu if this script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	# Check for root, virt, OS...
	initialCheck

	# Check if WireGuard is already installed and load params
	if [[ -e /etc/wireguard/params ]]; then
		source /etc/wireguard/params
		# Ensure automatic expiration cron is configured for existing installs
		_ws_ensure_auto_expiration >/dev/null 2>&1 || true
		manageMenu
	else
		installWireGuard
	fi
fi
