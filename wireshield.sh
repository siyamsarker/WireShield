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
# Version: 2.3.0
# ============================================================================

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

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

	# Render the install wizard intro box with a UTF-8 or ASCII fallback.
	_ws_print_installation_wizard_box() {
		if [[ ${USE_ASCII_BOX:-0} -eq 1 ]]; then
			printf "%b\n" "${ORANGE}============================================================${NC}"
			printf "%b\n" "${ORANGE}=                  Installation Wizard                   =${NC}"
			printf "%b\n" "${ORANGE}============================================================${NC}"
			printf "\n"
			printf "%s\n" "This setup wizard will guide you through the VPN configuration."
			printf "%s\n" "Default values are optimized for most use cases."
			printf "\n"
			printf "%s\n" "  -> Press Enter to accept defaults"
			printf "%s\n" "  -> Customize values as needed for your environment"
			printf "%s\n" "  -> Press Ctrl+C at any time to exit the installer"
			printf "\n"
			printf "%b\n" "${ORANGE}============================================================${NC}"
		else
			echo -e "${ORANGE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
			echo -e "${ORANGE}┃${NC}                       ${ORANGE}⚙  Installation Wizard${NC}                           ${ORANGE}┃${NC}"
			echo -e "${ORANGE}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫${NC}"
			echo -e "${ORANGE}┃${NC}                                                                        ${ORANGE}┃${NC}"
			echo -e "${ORANGE}┃${NC}  This setup wizard will guide you through the VPN configuration.      ${ORANGE}┃${NC}"
			echo -e "${ORANGE}┃${NC}  Default values are optimized for most use cases.                     ${ORANGE}┃${NC}"
			echo -e "${ORANGE}┃${NC}                                                                        ${ORANGE}┃${NC}"
			echo -e "${ORANGE}┃${NC}  ${GREEN}→${NC} Press ${GREEN}Enter${NC} to accept defaults                                      ${ORANGE}┃${NC}"
			echo -e "${ORANGE}┃${NC}  ${GREEN}→${NC} Customize values as needed for your environment                   ${ORANGE}┃${NC}"
			echo -e "${ORANGE}┃${NC}  ${GREEN}→${NC} Press ${GREEN}Ctrl+C${NC} at any time to exit the installer                     ${ORANGE}┃${NC}"
			echo -e "${ORANGE}┃${NC}                                                                        ${ORANGE}┃${NC}"
			echo -e "${ORANGE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
		fi
	}

		# Ensure locale is set so UTF-8 boxes render correctly; otherwise fall back to ASCII.
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
		echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════════════╗${NC}"
		echo -e "${GREEN}║                                                                                   ║${NC}"
		echo -e "${GREEN}║${NC}      ██╗    ██╗██╗██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗      ${GREEN}║${NC}"
		echo -e "${GREEN}║${NC}      ██║    ██║██║██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗     ${GREEN}║${NC}"
		echo -e "${GREEN}║${NC}      ██║ █╗ ██║██║██████╔╝█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║     ${GREEN}║${NC}"
		echo -e "${GREEN}║${NC}      ██║███╗██║██║██╔══██╗██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║     ${GREEN}║${NC}"
		echo -e "${GREEN}║${NC}      ╚███╔███╔╝██║██║  ██║███████╗███████║██║  ██║██║███████╗███████╗██████╔╝     ${GREEN}║${NC}"
		echo -e "${GREEN}║${NC}      ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝       ${GREEN}║${NC}"
		echo -e "${GREEN}║                                                                                   ║${NC}"
		echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════════════╝${NC}"
		echo ""
		echo -e "                 ${GREEN}● Secure${NC}  ${ORANGE}● Simple${NC}  ${GREEN}● Enterprise-Grade${NC}                 "
		echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
		echo -e "          ${GREEN}Professional WireGuard VPN Deployment System${NC}"
		echo ""
		echo -e "         Version ${GREEN}2.3.0${NC} • Built with ${RED}❤${NC}  by ${GREEN}Siyam Sarker${NC}"
		echo -e "         Repository: ${GREEN}github.com/siyamsarker/WireShield${NC}"
		echo ""
		echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
		echo -e ""
		_ws_print_installation_wizard_box
		echo ""

		# Detect public IPv4 or IPv6 address and pre-fill for the user
		SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
		if [[ -z ${SERVER_PUB_IP} ]]; then
			# Detect public IPv6 address
			SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
		fi
		read -rp "IPv4 or IPv6 public address (or hostname): " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

		# Detect public interface and pre-fill for the user
		SERVER_NIC="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
		until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]] && interface_exists "${SERVER_PUB_NIC}"; do
			read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
			if ! interface_exists "${SERVER_PUB_NIC}"; then
				echo -e "${ORANGE}Interface '${SERVER_PUB_NIC}' does not exist. Please enter an existing interface (e.g., ${SERVER_NIC}).${NC}"
			fi
		done

		SERVER_LOCAL_IPV4=$(get_interface_ipv4 "${SERVER_PUB_NIC}")
		if [[ -z ${SERVER_LOCAL_IPV4} ]]; then
			SERVER_LOCAL_IPV4=$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d'/' -f1 | head -1)
		fi

		until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
			read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
		done

		until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
			read -rp "Server WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
		done

		if [[ -z ${SERVER_LOCAL_IPV4} ]]; then
			SERVER_LOCAL_IPV4="${SERVER_WG_IPV4}"
		fi

		until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
			read -rp "Server WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
		done

		# Generate random number within private ports range
		RANDOM_PORT=$(shuf -i49152-65535 -n1)
		until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
			read -rp "Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
		done

		# Adguard DNS by default
		until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
			read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
		done
		until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
			read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
			if [[ ${CLIENT_DNS_2} == "" ]]; then
				CLIENT_DNS_2="${CLIENT_DNS_1}"
			fi
		done

		until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
			echo -e "\nWireGuard uses a parameter called AllowedIPs to determine what is routed over the VPN."
			read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
			if [[ ${ALLOWED_IPS} == "" ]]; then
				ALLOWED_IPS="0.0.0.0/0,::/0"
			fi
		done

		# Final confirmation summary with concise, modern copy for whiptail/CLI
		SUMMARY=$(cat <<-EOT
		WireShield install plan
		───────────────────────
		Public address : ${SERVER_PUB_IP}
		Public NIC     : ${SERVER_PUB_NIC}
		WG interface   : ${SERVER_WG_NIC}
		WG IPv4        : ${SERVER_WG_IPV4}/24
		WG IPv6        : ${SERVER_WG_IPV6}/64
		WG Port        : ${SERVER_PORT}/udp
		Client DNS     : ${CLIENT_DNS_1}, ${CLIENT_DNS_2}
		Allowed IPs    : ${ALLOWED_IPS}

		Install target: ${SERVER_PUB_IP}:${SERVER_PORT}
		Owner         : Siyam Sarker
		EOT
		)

		if command -v whiptail &>/dev/null; then
			whiptail --title "Review & confirm" \
				--yes-button "Start install" \
				--no-button "Edit" \
				--yesno "${SUMMARY}\nProceed with installation now?" 22 78
			if [[ $? -eq 0 ]]; then
				break
			else
				echo -e "${ORANGE}Let's adjust your inputs...${NC}\n"
			fi
		else
			echo -e "\n${SUMMARY}"
			read -rp "Proceed with installation? [Y/n]: " -e CONFIRM
			CONFIRM=${CONFIRM:-Y}
			if [[ ${CONFIRM} =~ ^[Yy]$ ]]; then
				break
			else
				echo -e "${ORANGE}Let's adjust your inputs...${NC}\n"
			fi
		fi
	done

	echo ""
	echo "Great—settings locked in. Starting WireShield setup now."
	echo "A first client will be generated automatically at the end."
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
	echo -e "${ORANGE}=== WireShield 2FA SSL/TLS Configuration ===${NC}"
	echo ""
	echo "The 2FA web interface requires HTTPS for security."
	echo ""
	
	# Ask if user wants SSL/TLS
	read -rp "Configure SSL/TLS for 2FA service? (y/n): " -e USE_SSL
	if [[ "${USE_SSL}" != "y" && "${USE_SSL}" != "Y" ]]; then
		echo -e "${ORANGE}⚠ Warning: 2FA will run without SSL (only recommended for localhost)${NC}"
		echo "2FA_SSL_ENABLED=false" >> /etc/wireshield/2fa/config.env
		return 0
	fi
	
	echo ""
	echo "Choose SSL certificate type:"
	echo "  1) Let's Encrypt (Domain name required, auto-renewal)"
	echo "  2) Self-signed (IP address or any hostname, no auto-renewal)"
	echo ""
	read -rp "Enter choice (1 or 2): " -e SSL_TYPE
	
	if [[ "${SSL_TYPE}" == "1" ]]; then
		# Let's Encrypt with domain
		# Use bash-safe variable name internally, but still write 2FA_* keys to config.env
		read -rp "Enter domain name for 2FA service (e.g., vpn.example.com): " -e WS_2FA_DOMAIN
		
		if [[ -z "${WS_2FA_DOMAIN}" ]]; then
			echo -e "${RED}Error: Domain name required for Let's Encrypt${NC}"
			return 1
		fi
		# Basic domain sanity: must not be an IP and must look like a hostname
		if [[ ${WS_2FA_DOMAIN} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
			echo -e "${RED}Error: Let's Encrypt requires a DNS name (not an IP)${NC}"
			return 1
		fi
		if [[ ! ${WS_2FA_DOMAIN} =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*)(\.[a-zA-Z0-9](-?[a-zA-Z0-9])*)+$ ]]; then
			echo -e "${RED}Error: Invalid domain format for Let's Encrypt: ${WS_2FA_DOMAIN}${NC}"
			return 1
		fi
		
		echo -e "${ORANGE}Setting up Let's Encrypt certificate for ${WS_2FA_DOMAIN}...${NC}"
		
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
				echo -e "${ORANGE}⚠ Let's Encrypt setup incomplete. Using self-signed certificate.${NC}"
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
ExecStart=/usr/bin/certbot renew --quiet --post-hook "systemctl reload wireshield-2fa"

[Install]
WantedBy=multi-user.target
EOFSERVICE

				systemctl daemon-reload 2>/dev/null || true
				systemctl enable wireshield-2fa-renew.timer 2>/dev/null || true
				# Immediate dry-run to surface renewal issues early
				certbot renew --dry-run --quiet 2>/dev/null || echo -e "${ORANGE}⚠ Certbot dry-run failed; check ports 80/443 and DNS for ${WS_2FA_DOMAIN}${NC}"
				
				echo -e "${GREEN}✓ Let's Encrypt certificate configured${NC}"
				echo -e "${GREEN}✓ Auto-renewal enabled${NC}"
				# Write both WS_* and 2FA_* for compatibility
				echo "WS_2FA_SSL_ENABLED=true" >> /etc/wireshield/2fa/config.env
				echo "WS_2FA_SSL_TYPE=letsencrypt" >> /etc/wireshield/2fa/config.env
				echo "WS_2FA_DOMAIN=${WS_2FA_DOMAIN}" >> /etc/wireshield/2fa/config.env
				return 0
			fi
		fi
	fi
	
	# Self-signed certificate (for IP or localhost)
	read -rp "Enter IP address or hostname (e.g., 127.0.0.1 or vpn.local): " -e WS_HOSTNAME_2FA
	
	if [[ -z "${WS_HOSTNAME_2FA}" ]]; then
		WS_HOSTNAME_2FA="127.0.0.1"
	fi
	
	echo -e "${ORANGE}Generating self-signed certificate for ${WS_HOSTNAME_2FA}...${NC}"
	
	openssl req -x509 -newkey rsa:4096 \
		-keyout /etc/wireshield/2fa/key.pem \
		-out /etc/wireshield/2fa/cert.pem \
		-days 365 -nodes \
		-subj "/C=US/ST=State/L=City/O=WireShield/CN=${WS_HOSTNAME_2FA}" 2>/dev/null || true
	
	chmod 600 /etc/wireshield/2fa/key.pem
	chmod 644 /etc/wireshield/2fa/cert.pem
	
	echo -e "${GREEN}✓ Self-signed certificate configured${NC}"
	# Write WS_* names only (systemd EnvironmentFile cannot parse 2FA_*)
	echo "WS_2FA_SSL_ENABLED=true" >> /etc/wireshield/2fa/config.env
	echo "WS_2FA_SSL_TYPE=self-signed" >> /etc/wireshield/2fa/config.env
	echo "WS_HOSTNAME_2FA=${WS_HOSTNAME_2FA}" >> /etc/wireshield/2fa/config.env
}

function _ws_install_2fa_service() {
	# Install Python 2FA service and dependencies
	echo "Setting up WireShield 2FA service..."

	local VENV_PATH="/etc/wireshield/2fa/.venv"
	local SCRIPT_DIR
	SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
	
	# Create 2FA directory and config file
	mkdir -p /etc/wireshield/2fa
	chmod 700 /etc/wireshield/2fa
	cat > /etc/wireshield/2fa/config.env << 'EOF'
# WireShield 2FA Configuration
# Generated during installation
# Use only WS_* prefixed names (systemd EnvironmentFile cannot parse 2FA_* or names starting with numbers)
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
WS_HOSTNAME_2FA=127.0.0.1
EOF
	
	# Ensure Python3, pip and venv are available (install even if python3 already exists)
	echo "Ensuring Python3 pip/venv are installed..."
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
	if [[ -d "${SCRIPT_DIR}/2fa-auth" ]]; then
		cp -f "${SCRIPT_DIR}/2fa-auth/app.py" /etc/wireshield/2fa/ 2>/dev/null || true
		cp -f "${SCRIPT_DIR}/2fa-auth/requirements.txt" /etc/wireshield/2fa/ 2>/dev/null || true
		cp -f "${SCRIPT_DIR}/2fa-auth/2fa-helper.sh" /etc/wireshield/2fa/ 2>/dev/null || true
		cp -f "${SCRIPT_DIR}/2fa-auth/generate-certs.sh" /etc/wireshield/2fa/ 2>/dev/null || true
		# Optional: bundled service file (we still write one below for consistency)
		cp -f "${SCRIPT_DIR}/2fa-auth/wireshield-2fa.service" /etc/wireshield/2fa/ 2>/dev/null || true
	elif [[ -d /opt/wireshield/2fa-auth ]]; then
		cp /opt/wireshield/2fa-auth/* /etc/wireshield/2fa/ 2>/dev/null || true
	fi
	
	# Check if 2FA service already exists
	if [[ -f /etc/systemd/system/wireshield-2fa.service ]]; then
		echo -e "${GREEN}2FA service already installed${NC}"
		return 0
	fi
	
	# Copy 2FA files from source (assumes they exist)
	if [[ -d /opt/wireshield/2fa-auth ]]; then
		cp /opt/wireshield/2fa-auth/* /etc/wireshield/2fa/ 2>/dev/null || true
	fi
	
	# Configure SSL/TLS
	_ws_configure_2fa_ssl
	
	# Install Python dependencies into a dedicated virtual environment
	python3 -m venv "${VENV_PATH}" 2>/dev/null || true
	# If venv creation failed due to missing ensurepip, try to install venv package and retry
	if [[ ! -x "${VENV_PATH}/bin/python" ]]; then
		echo -e "${ORANGE}Attempting to fix missing ensurepip by installing venv package...${NC}"
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
			echo -e "${ORANGE}Warning: Some Python dependencies may not have installed correctly${NC}"
		}
	fi
	
	# SSL certificates already configured during _ws_configure_2fa_ssl
	# Skip if they already exist
	if [[ ! -f /etc/wireshield/2fa/cert.pem ]] || [[ ! -f /etc/wireshield/2fa/key.pem ]]; then
		echo -e "${ORANGE}⚠ SSL certificates not found, generating self-signed...${NC}"
		openssl req -x509 -newkey rsa:4096 \
			-keyout /etc/wireshield/2fa/key.pem \
			-out /etc/wireshield/2fa/cert.pem \
			-days 365 -nodes \
			-subj "/C=US/ST=State/L=City/O=WireShield/CN=wireshield-2fa" 2>/dev/null || true
		chmod 600 /etc/wireshield/2fa/key.pem 2>/dev/null || true
		chmod 644 /etc/wireshield/2fa/cert.pem 2>/dev/null || true
	fi
	
	# Verify app presence (robustness)
	if [[ ! -f /etc/wireshield/2fa/app.py ]]; then
		echo -e "${ORANGE}app.py missing in /etc/wireshield/2fa, attempting copy from repo...${NC}"
		if [[ -f "${SCRIPT_DIR}/2fa-auth/app.py" ]]; then
			cp -f "${SCRIPT_DIR}/2fa-auth/app.py" /etc/wireshield/2fa/ || true
		fi
	fi

	# Install systemd service file
	if [[ -f /etc/wireshield/2fa/wireshield-2fa.service ]]; then
		# Read config and create updated service file
		# Load WS_* values (avoid bash parsing errors with 2FA_* names)
		# shellcheck disable=SC1091
		source /etc/wireshield/2fa/config.env 2>/dev/null || true
		
		cat > /etc/systemd/system/wireshield-2fa.service << EOF
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
ExecStart=${VENV_PATH}/bin/python /etc/wireshield/2fa/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
	else
		# Fallback: create minimal service file
		cat > /etc/systemd/system/wireshield-2fa.service << EOF
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
ExecStart=${VENV_PATH}/bin/python /etc/wireshield/2fa/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
	fi
	
	# Enable and start the service
	systemctl daemon-reload 2>/dev/null || true
	systemctl enable wireshield-2fa 2>/dev/null || true
	systemctl start wireshield-2fa 2>/dev/null || true

	if systemctl is-active --quiet wireshield-2fa; then
		echo -e "${GREEN}2FA service installed and started${NC}"
	else
		echo -e "${ORANGE}2FA service did not start successfully. Check 'journalctl -u wireshield-2fa' for details.${NC}"
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
	if [[ -n "${WS_2FA_DOMAIN}" ]]; then
		_host="${WS_2FA_DOMAIN}"
	elif [[ -n "${WS_HOSTNAME_2FA}" ]]; then
		_host="${WS_HOSTNAME_2FA}"
	else
		_host="127.0.0.1"
	fi
	_health_url="${_scheme}://${_host}:${_port}/health"

	echo -e "${ORANGE}Checking 2FA service health at: ${_health_url}${NC}"
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
		echo -e "${GREEN}✓ 2FA health: OK${NC}"
	else
		echo -e "${ORANGE}⚠ 2FA health check failed. Service may still be starting or unreachable.${NC}"
		echo -e "${ORANGE}  Try: journalctl -u wireshield-2fa -n 60 | less${NC}"
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
		apt-get install -y wireguard iptables resolvconf qrencode ipset
	elif [[ ${OS} == 'debian' ]]; then
		# For Debian 10 Buster, use backports repository
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt-get update
		apt-get install -y iptables resolvconf qrencode
		apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		# Fedora 32+ has WireGuard in the default repositories
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode ipset
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		# For RHEL-based systems
		if [[ ${VERSION_ID} == 8* ]]; then
			yum install -y epel-release elrepo-release
			yum install -y kmod-wireguard
			yum install -y qrencode # not available on release 9
		fi
		yum install -y wireguard-tools iptables ipset
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		# Arch Linux has latest WireGuard in official repositories
		pacman -Sy --needed --noconfirm wireguard-tools qrencode ipset
	elif [[ ${OS} == 'alpine' ]]; then
		# Alpine Linux supports WireGuard natively
		apk update
		apk add wireguard-tools iptables libqrencode-tools ipset
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
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
PostDown = iptables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D PREROUTING -i ${SERVER_WG_NIC} -d ${SERVER_PUB_IP} -p tcp --dport 443 -j DNAT --to-destination ${PORTAL_DNAT_TARGET}:443 2>/dev/null || true
PostDown = iptables -t nat -D PREROUTING -i ${SERVER_WG_NIC} -d ${SERVER_PUB_IP} -p tcp --dport 80 -j DNAT --to-destination ${PORTAL_DNAT_TARGET}:80 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j WS_2FA_PORTAL 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -m set --match-set ws_2fa_allowed_v4 src -j ACCEPT 2>/dev/null || true
PostDown = iptables -F WS_2FA_PORTAL 2>/dev/null || true
PostDown = iptables -X WS_2FA_PORTAL 2>/dev/null || true
PostDown = ipset flush ws_2fa_allowed_v4 2>/dev/null || true
PostDown = ipset destroy ws_2fa_allowed_v4 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE 2>/dev/null || true
PostDown = ip6tables -D INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
PostDown = ip6tables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j WS_2FA_PORTAL6 2>/dev/null || true
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -m set --match-set ws_2fa_allowed_v6 src -j ACCEPT 2>/dev/null || true
PostDown = ip6tables -F WS_2FA_PORTAL6 2>/dev/null || true
PostDown = ip6tables -X WS_2FA_PORTAL6 2>/dev/null || true
PostDown = ipset flush ws_2fa_allowed_v6 2>/dev/null || true
PostDown = ipset destroy ws_2fa_allowed_v6 2>/dev/null || true
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE 2>/dev/null || true" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable IPv4/IPv6 forwarding on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

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
}

function newClient() {
	# Interactively create a new peer (client): allocate IPs, generate keys,
	# update server config, write client configuration, and optionally show QR.
	# IMPORTANT: Localize and reset variables to avoid cross-call leakage that
	# can cause the function to skip prompts or behave unexpectedly.
	echo -e "${ORANGE}(Press Ctrl+C to return to menu at any time)${NC}"
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
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Client configuration"
	echo ""
	echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Client name: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
			echo ""
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
		read -rp "Client WireGuard IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
			echo ""
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV6_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
			echo ""
		fi
	done

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	# Ask for expiration date (optional)
	echo ""
	echo "Client expiration (optional)"
	echo "Leave empty for no expiration, or enter number of days until expiration"
	read -rp "Expires in (days): " -e EXPIRY_DAYS
	
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

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Create client file with simple name
	CLIENT_CONFIG="${HOME_DIR}/${CLIENT_NAME}.conf"

	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

# Uncomment the next line to set a custom MTU
# This might impact performance, so use it only if you know what you are doing
# See https://github.com/nitred/nr-wg-mtu-finder to find your optimal MTU
# MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}
# Keep WireGuard handshakes active so 2FA session monitor stays accurate
PersistentKeepalive = 25" >"${CLIENT_CONFIG}"

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
		echo -e "${GREEN}\nHere is your client config file as a QR Code (optimized size):\n${NC}"
		# Use a smaller module size and low margin to keep QR within a reasonable terminal footprint
		# -t ansiutf8: colored block output compatible with most modern terminals
		# -l M: medium error correction (balance size vs redundancy)
		# -m 0: no extra margin
		# -s 1: smallest module scale (qrencode will choose minimal that still renders)
		# If scanning reliability becomes an issue, increase -s to 2 or -m to 1.
		qrencode -t ansiutf8 -l M -m 0 -s 1 <"${CLIENT_CONFIG}"
		echo ""
	fi

	echo ""
	echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
	echo -e "${GREEN}✓ Client configuration created successfully!${NC}"
	echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
	echo -e "${GREEN}Client name: ${CLIENT_NAME}${NC}"
	echo -e "${GREEN}Config file: ${CLIENT_CONFIG}${NC}"
	if [[ -n "${EXPIRY_DATE}" ]]; then
		echo -e "${ORANGE}Expires on: ${EXPIRY_DATE}${NC}"
	fi
	echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
	echo -e "${ORANGE}Troubleshooting:${NC} If you cannot find the .conf later, try:"
	echo -e "  sudo ls -l /root/*.conf /home/*/*.conf 2>/dev/null"
	echo -e "To copy to your machine: scp root@<server>:/root/${CLIENT_NAME}.conf ."
	echo ""
}

function listClients() {
    # Print numbered list of existing clients (peers) from the server config.
	echo -e "${ORANGE}(Press Ctrl+C to return to menu)${NC}"
	echo ""
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		return
	fi

	echo ""
	echo -e "${GREEN}Current clients:${NC}"
	echo ""
	
	local count=0
	while IFS= read -r line; do
		if [[ $line =~ ^###[[:space:]]Client[[:space:]](.+) ]]; then
			count=$((count + 1))
			local client_info="${BASH_REMATCH[1]}"
			
			# Check if there's an expiration date
			if [[ $client_info =~ ^([^[:space:]]+)[[:space:]]\|[[:space:]]Expires:[[:space:]]([0-9]{4}-[0-9]{2}-[0-9]{2})$ ]]; then
				local client_name="${BASH_REMATCH[1]}"
				local expiry_date="${BASH_REMATCH[2]}"
				echo -e "   ${count}) ${client_name} ${ORANGE}(expires: ${expiry_date})${NC}"
			else
				echo -e "   ${count}) ${client_info}"
			fi
		fi
	done < "/etc/wireguard/${SERVER_WG_NIC}.conf"
}

function revokeClient() {
	# Remove a client peer from the server config and delete related client
	# configuration files so the name can be safely reused.
	echo -e "${ORANGE}(Press Ctrl+C to return to menu)${NC}"
	echo ""
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
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

	echo -e "${GREEN}Client '${CLIENT_NAME}' has been fully revoked and related .conf files removed.${NC}"
}

function checkExpiredClients() {
	# Check for expired clients and remove them automatically
	echo -e "${ORANGE}(Press Ctrl+C to return to menu)${NC}"
	echo ""
	echo -e "${GREEN}Checking for expired clients...${NC}\n"
	
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
				echo -e "${ORANGE}Removing expired client: ${CLIENT_NAME} (expired on ${EXPIRY_DATE})${NC}"
				
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
				
				echo -e "${GREEN}  ✓ Client '${CLIENT_NAME}' completely removed${NC}"
				expired_count=$((expired_count + 1))
			fi
		fi
	done < "/etc/wireguard/${SERVER_WG_NIC}.conf"
	
	if [[ ${expired_count} -gt 0 ]]; then
		# Apply changes to the live interface
		wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
		echo -e "\n${GREEN}✓ Removed ${expired_count} expired client(s)${NC}"
	else
		if [[ ${checked_count} -gt 0 ]]; then
			echo -e "${GREEN}✓ No expired clients found (checked ${checked_count} client(s) with expiration dates)${NC}"
		else
			echo -e "${GREEN}✓ No clients with expiration dates found${NC}"
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
	echo -e "\n${RED}⚠ Warning:${NC} You are about to uninstall WireShield completely."
	echo -e "${ORANGE}This will remove:${NC}"
	echo "  • WireGuard and all VPN configurations"
	echo "  • 2FA service (FastAPI, database, certificates)"
	echo "  • SSL certificates (Let's Encrypt symlinks, self-signed certs)"
	echo "  • Auto-renewal timers and services"
	echo "  • All client configurations"
	echo ""
	echo -e "${ORANGE}Back up /etc/wireguard and /etc/wireshield if you wish to keep settings.${NC}\n"
	read -rp "Proceed with complete removal? [y/N]: " -e REMOVE
	REMOVE=${REMOVE:-N}
	if [[ $REMOVE == 'y' ]]; then
		# Collect client names before removing /etc/wireguard
		CLIENT_NAMES=()
		if [[ -f "/etc/wireguard/${SERVER_WG_NIC}.conf" ]]; then
			while IFS= read -r name; do
				CLIENT_NAMES+=("${name}")
			done < <(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | awk '{print $3}')
		fi

		# Silent mode: automatically remove client .conf files as part of uninstall
		DELETE_CLIENT_FILES=Y

		checkOS

		echo -e "${ORANGE}Removing WireGuard services...${NC}"
		
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

		echo -e "${ORANGE}Removing WireGuard configuration...${NC}"
		rm -rf /etc/wireguard 2>/dev/null || true
		rm -f /etc/sysctl.d/wg.conf 2>/dev/null || true

		# Remove 2FA gating firewall structures
		echo -e "${ORANGE}Removing 2FA gating firewall rules...${NC}"
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
		echo -e "${ORANGE}Removing client expiration service...${NC}"
		rm -f /usr/local/bin/wireshield-check-expired 2>/dev/null || true
		# Remove crontab entry if present (ignore errors when crontab unset)
		if crontab -l 2>/dev/null | grep -q "wireshield-check-expired"; then
			crontab -l 2>/dev/null | sed '/wireshield-check-expired/d' | crontab - 2>/dev/null || true
		fi

		# Remove 2FA service and related services
		echo -e "${ORANGE}Removing 2FA services...${NC}"
		systemctl stop wireshield-2fa 2>/dev/null || true
		systemctl disable wireshield-2fa 2>/dev/null || true
		systemctl stop wireshield-2fa-renew.timer 2>/dev/null || true
		systemctl disable wireshield-2fa-renew.timer 2>/dev/null || true
		systemctl stop wireshield-2fa-renew.service 2>/dev/null || true
		systemctl disable wireshield-2fa-renew.service 2>/dev/null || true

		# Remove systemd service files
		rm -f /etc/systemd/system/wireshield-2fa.service 2>/dev/null || true
		rm -f /etc/systemd/system/wireshield-2fa-renew.timer 2>/dev/null || true
		rm -f /etc/systemd/system/wireshield-2fa-renew.service 2>/dev/null || true
		systemctl daemon-reload 2>/dev/null || true

		# Remove 2FA directory (database, certificates, configs)
		echo -e "${ORANGE}Removing 2FA configuration and database...${NC}"
		rm -rf /etc/wireshield 2>/dev/null || true

		# Remove Let's Encrypt symlinks if they exist
		rm -f /usr/local/bin/wireshield-renew-cert 2>/dev/null || true

		# Remove Python packages installed for 2FA (optional, only if user confirms)
		# Keep commented as removing python3 might break other services
		# apt-get remove -y python3-fastapi python3-uvicorn python3-pyotp 2>/dev/null || true

		# Remove client config files from user home directories
		echo -e "${ORANGE}Removing client configurations...${NC}"
		SEARCH_DIRS=(/root /home)
		for cname in "${CLIENT_NAMES[@]}"; do
			for base in "${SEARCH_DIRS[@]}"; do
				# remove client config files if they exist within depth 2
				find "$base" -maxdepth 2 -type f -name "${cname}.conf" \
					-print -delete 2>/dev/null
			done
		done

		if [[ ${OS} == 'alpine' ]]; then
			rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status &>/dev/null 2>&1
		else
			# Reload sysctl
			sysctl --system 2>/dev/null || true

			# Check if WireGuard is running
			systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true
		fi
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo -e "${RED}✗ WireGuard service still running. Manual cleanup may be needed.${NC}"
			exit 1
		else
			echo ""
			echo -e "${GREEN}✓ WireGuard uninstalled successfully${NC}"
			echo -e "${GREEN}✓ 2FA service removed completely${NC}"
			echo -e "${GREEN}✓ SSL certificates and auto-renewal cleaned up${NC}"
			echo -e "${GREEN}✓ All client configurations removed${NC}"
			echo -e "${GREEN}✓ All systemd services and timers removed${NC}"
			echo ""
			echo -e "${ORANGE}Note:${NC} Python packages remain installed (safe, may be used by other services)"
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function _ws_header() {
    # Draw a simple header for the interactive menu.
	echo -e "${GREEN}WireShield — Modern VPN Management${NC}"
	echo "Project: https://github.com/siyamsarker/WireShield"
	echo ""
}

function _ws_summary() {
    # Show a concise summary of interface, endpoint, peer count, and service status.
	local peers
	peers=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" 2>/dev/null || echo 0)
	echo "Interface  : ${SERVER_WG_NIC}"
	echo "Endpoint   : ${SERVER_PUB_IP}:${SERVER_PORT}"
	echo "Clients    : ${peers}"
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status && echo "Service    : Active" || echo "Service    : Inactive"
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}" && echo "Service    : Active" || echo "Service    : Inactive"
	fi
	echo ""
}

function _ws_choose_client() {
    # Prompt the user to select one client from the existing list; prints the name.
	local number_of_clients
	number_of_clients=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	
	if [[ ${number_of_clients} -eq 0 ]]; then
		echo -e "${RED}No clients found.${NC}" >&2
		return 1
	fi
	
	echo "Select a client:" >&2
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') ' >&2
	
	local choice
	until [[ ${choice} =~ ^[0-9]+$ ]] && [[ ${choice} -ge 1 ]] && [[ ${choice} -le ${number_of_clients} ]]; do
		read -rp "Client [1-${number_of_clients}]: " choice
		if [[ ! ${choice} =~ ^[0-9]+$ ]]; then
			echo -e "${ORANGE}Please enter a valid number.${NC}" >&2
		fi
	done
	
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${choice}p"
}

function showClientQR() {
    # Render a QR code for a selected client's configuration (if available).
	echo -e "${ORANGE}(Press Ctrl+C to return to menu)${NC}"
	echo ""
	if ! command -v qrencode &>/dev/null; then
		echo -e "${ORANGE}qrencode is not installed; cannot render QR in terminal.${NC}"
		echo "You can still use the .conf file on your device."
		return 0
	fi
	
	local name home_dir cfg
	name=$(_ws_choose_client)
	
	# Check if client selection failed
	if [[ -z "${name}" ]]; then
		echo -e "${RED}No client selected.${NC}"
		return 1
	fi
	
	home_dir=$(getHomeDirForClient "${name}")
	cfg="${home_dir}/${name}.conf"
	
	if [[ ! -f "${cfg}" ]]; then
		echo -e "${RED}Config file for client '${name}' was not found:${NC}"
		echo -e "  ${cfg}"
		return 1
	fi
	
	echo -e "${GREEN}\nQR Code for ${name}:${NC}\n"
	qrencode -t ansiutf8 -l L <"${cfg}"
	echo ""
}

function showStatus() {
    # Display WireGuard runtime status via `wg show`.
	echo -e "${ORANGE}(Press Ctrl+C to return to menu)${NC}"
	echo ""
	echo -e "${GREEN}WireGuard status:${NC}"
	wg show || true
}

function restartWireGuard() {
    # Restart the WireGuard interface service using the appropriate init system.
	echo -e "${ORANGE}(Press Ctrl+C to return to menu)${NC}"
	echo ""
	echo "Restarting WireGuard (${SERVER_WG_NIC})..."
	if [[ ${OS} == 'alpine' ]]; then
		rc-service "wg-quick.${SERVER_WG_NIC}" restart
	else
		systemctl restart "wg-quick@${SERVER_WG_NIC}"
	fi
	echo "Done."
}

function backupConfigs() {
    # Create a timestamped archive of /etc/wireguard for backup/portability.
	echo -e "${ORANGE}(Press Ctrl+C to return to menu)${NC}"
	echo ""
	local ts out
	ts=$(date +%Y%m%d-%H%M%S)
	out="/root/wireshield-backup-${ts}.tar.gz"
	tar czf "${out}" /etc/wireguard 2>/dev/null && echo -e "${GREEN}Backup saved to ${out}${NC}" || echo -e "${RED}Backup failed.${NC}"
}

function viewAuditLogs() {
    # Display audit logs menu for users to view 2FA authentication logs.
	echo -e "${ORANGE}(Press Ctrl+C to return to menu)${NC}"
	echo ""
	
	local AUDIT_OPTION
	echo "=== Audit Logs ==="
	echo "   1) View all audit logs (last 100)"
	echo "   2) View logs for specific user"
	echo "   3) View audit statistics"
	echo "   4) Export audit logs to CSV"
	echo "   5) Back to menu"
	read -rp "Select option [1-5]: " AUDIT_OPTION
	
	case "$AUDIT_OPTION" in
		1)
			echo ""
			sudo /etc/wireshield/2fa/2fa-helper.sh audit-logs
			;;
		2)
			echo ""
			read -rp "Enter client/user ID: " client_id
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
			read -rp "Enter output file path [/tmp/wireshield_audit_logs.csv]: " output_file
			output_file=${output_file:-/tmp/wireshield_audit_logs.csv}
			sudo /etc/wireshield/2fa/2fa-helper.sh export-audit "$output_file"
			echo -e "${GREEN}Audit logs exported to: ${output_file}${NC}"
			;;
		5)
			return
			;;
		*)
			echo "Invalid option"
			;;
	esac
}

function removeCient2FA() {
    # Remove 2FA configuration for a specific client, allowing them to set it up again
	echo ""
	echo -e "${ORANGE}=== Remove Client 2FA ===${NC}"
	echo ""
	
	# Check if 2FA service is installed
	if [[ ! -f /etc/wireshield/2fa/auth.db ]]; then
		echo -e "${RED}Error: 2FA database not found. Is 2FA service installed?${NC}"
		return 1
	fi
	
	# List all clients with 2FA configured
	echo "Clients with 2FA configured:"
	echo ""
	
	local sqlite3_cmd="sqlite3 /etc/wireshield/2fa/auth.db"
	local client_list
	client_list=$($sqlite3_cmd "SELECT client_id, enabled, totp_secret FROM users ORDER BY client_id ASC;" 2>/dev/null)
	
	if [[ -z "$client_list" ]]; then
		echo -e "${RED}No clients have 2FA configured.${NC}"
		return 1
	fi
	
	# Display formatted list
	local index=1
	declare -a client_ids
	while IFS='|' read -r client_id enabled secret; do
		client_ids[$index]="$client_id"
		local status="DISABLED"
		[[ "$enabled" == "1" ]] && status="ACTIVE"
		echo "   $index) $client_id [$status]"
		((index++))
	done <<< "$client_list"
	
	echo ""
	read -rp "Select client number to remove 2FA (or press Enter to cancel): " selection
	
	if [[ -z "$selection" ]] || [[ ! "$selection" =~ ^[0-9]+$ ]] || [[ $selection -lt 1 ]] || [[ $selection -gt ${#client_ids[@]} ]]; then
		echo "Cancelled."
		return 0
	fi
	
	local target_client="${client_ids[$selection]}"
	
	# Confirm removal
	echo ""
	echo -e "${ORANGE}WARNING: This will remove 2FA for client: ${GREEN}${target_client}${NC}"
	echo "The user will need to set up 2FA again to access the VPN."
	echo ""
	read -rp "Type the client ID '${target_client}' to confirm: " confirm_input
	
	if [[ "$confirm_input" != "$target_client" ]]; then
		echo "Cancelled."
		return 0
	fi
	
	# Remove 2FA for this client
	echo ""
	echo "Removing 2FA for $target_client..."
	
	# Reset TOTP secret and disable user until they verify again
	$sqlite3_cmd "UPDATE users SET totp_secret = NULL, enabled = 0, wg_ipv4 = NULL, wg_ipv6 = NULL WHERE client_id = '${target_client}';" 2>/dev/null
	
	# Delete all active sessions for this client
	$sqlite3_cmd "DELETE FROM sessions WHERE client_id = '${target_client}';" 2>/dev/null
	
	# Remove from ipset allowlist
	if command -v ipset &>/dev/null; then
		ipset del ws_2fa_allowed_v4 "$(ipset list ws_2fa_allowed_v4 2>/dev/null | grep "^$target_client" | awk '{print $1}')" 2>/dev/null || true
		ipset del ws_2fa_allowed_v6 "$(ipset list ws_2fa_allowed_v6 2>/dev/null | grep "^$target_client" | awk '{print $1}')" 2>/dev/null || true
	fi
	
	echo -e "${GREEN}✓ 2FA removed for client: ${target_client}${NC}"
	echo "  User must now verify 2FA again on next connection."
	echo ""
	
	# Log this action
	audit_log "$target_client" "2FA_REMOVED" "admin_action" "cli"
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

function manageMenu() {
    # Main interactive loop used after installation to manage clients and server.
	while true; do
		clear
		_ws_header
		_ws_summary

		local MENU_OPTION
		if command -v whiptail &>/dev/null; then
			# Center the prompt text within the specified width (approximate centering)
			local MENU_HEIGHT=20 MENU_WIDTH=72 MENU_CHOICES=12
			local _prompt="Select a management task"
			local _pad=$(( (MENU_WIDTH - ${#_prompt}) / 2 ))
			((_pad<0)) && _pad=0
			local _prompt_centered
			_prompt_centered=$(printf "%*s%s" "${_pad}" "" "${_prompt}")
			MENU_OPTION=$(whiptail --title "WireShield — Main Menu" --menu "${_prompt_centered}" ${MENU_HEIGHT} ${MENU_WIDTH} ${MENU_CHOICES} \
				1 "Create Client" \
				2 "List Clients" \
				3 "Display Client QR" \
				4 "Revoke Client Access" \
				5 "Clean Up Expired Clients" \
				6 "View Server Status" \
				7 "Restart VPN Service" \
				8 "View Audit Logs" \
				9 "Backup Configuration" \
				10 "Remove Client 2FA" \
				11 "Uninstall WireShield" \
				12 "Exit" 3>&1 1>&2 2>&3) || MENU_OPTION=12
		else
			local msg="Select a management task"
			echo ""
			echo "================ ${msg} ================"
			echo "   1) Create Client"
			echo "   2) List Clients"
			echo "   3) Display Client QR"
			echo "   4) Revoke Client Access"
			echo "   5) Clean Up Expired Clients"
			echo "   6) View Server Status"
			echo "   7) Restart VPN Service"
			echo "   8) View Audit Logs"
			echo "   9) Backup Configuration"
			echo "  10) Remove Client 2FA"
			echo "  11) Uninstall WireShield"
			echo "  12) Exit"
			until [[ ${MENU_OPTION} =~ ^[1-9]$|^10$|^11$|^12$ ]]; do
				read -rp "Select an option [1-12]: " MENU_OPTION
			done
		fi

		case "${MENU_OPTION}" in
		1)
			newClient ;;
		2)
			listClients ;;
		3)
			showClientQR ;;
		4)
			revokeClient ;;
		5)
			checkExpiredClients ;;
		6)
			showStatus ;;
		7)
			restartWireGuard ;;
		8)
			viewAuditLogs ;;
		9)
			backupConfigs ;;
		10)
			removeCient2FA ;;
		11)
			uninstallWg ;;
		12)
			exit 0 ;;
		esac

		echo ""
		read -rp "Press Enter to continue..." _
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
	local home_dir cfg
	home_dir=$(getHomeDirForClient "$name")
	cfg="${home_dir}/${name}.conf"
	if [[ ! -f "$cfg" ]]; then
		echo "Error: config not found for client '$name' at $cfg" 1>&2
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

	# Remove client config files
	local home_dir
	home_dir=$(getHomeDirForClient "$name")
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

	# Client file
	local home_dir client_cfg endpoint
	home_dir=$(getHomeDirForClient "$name")
	client_cfg="${home_dir}/${name}.conf"
	endpoint="${SERVER_PUB_IP}:${SERVER_PORT}"
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]] && [[ ${SERVER_PUB_IP} != *"["* || ${SERVER_PUB_IP} != *"]"* ]]; then
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
