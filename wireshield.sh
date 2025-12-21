#!/bin/bash

# ==============================================================================
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
#     chmod +x ./wireshield.sh && sudo ./wireshield.sh
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
function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		echo "Great—settings locked in. Starting WireShield setup now."
		echo "A first client will be generated automatically at the end."
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

	# helper: check interface existence
	interface_exists() {
		ip link show dev "$1" >/dev/null 2>&1
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
		echo -e "                      ${GREEN}Secure. Simple. Fast.${NC}                      "
		echo -e "${ORANGE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
		echo -e "${GREEN}▓▒░${NC} Secure WireGuard VPN Installer & Manager ${GREEN}░▒▓${NC}"
		echo ""
		echo -e "Version ${GREEN}2.3.0${NC} • Made with ${RED}❤️${NC}  by ${GREEN}Siyam Sarker${NC}"
		echo -e "📦 ${GREEN}https://github.com/siyamsarker/WireShield${NC}"
		echo ""
		echo -e "${ORANGE}Quick Setup: Answer a few questions and get started in under 2 minutes!${NC}"
		echo ""
		echo -e "${ORANGE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
		echo -e "${ORANGE}┃${NC}                         ${ORANGE}⚙${NC}  Setup Configuration                         ${ORANGE}┃${NC}"
		echo -e "${ORANGE}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫${NC}"
		echo -e "${ORANGE}┃${NC}  I need to ask you a few questions before starting. Keep               ${ORANGE}┃${NC}"
		echo -e "${ORANGE}┃${NC}  defaults and press ${GREEN}Enter${NC} if you are ok.                               ${ORANGE}┃${NC}"
		echo -e "${ORANGE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
		echo ""
		echo -e "${ORANGE}Tip:${NC} Use arrow keys to navigate. Press ${GREEN}Ctrl+C${NC} to exit at any time."
		echo -e "${GREEN}WireShield v2.3.0${NC} – Professional WireGuard VPN Management"
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

		until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
			read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
		done

		until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
			read -rp "Server WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
		done

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

		# Final confirmation summary
		SUMMARY=$(cat <<-EOT
		Public address : ${SERVER_PUB_IP}
		Public NIC     : ${SERVER_PUB_NIC}
		WG interface   : ${SERVER_WG_NIC}
		WG IPv4        : ${SERVER_WG_IPV4}/24
		WG IPv6        : ${SERVER_WG_IPV6}/64
		WG Port        : ${SERVER_PORT}/udp
		Client DNS 1   : ${CLIENT_DNS_1}
		Client DNS 2   : ${CLIENT_DNS_2}
		Allowed IPs    : ${ALLOWED_IPS}

		Made with ❤️  by Siyam Sarker
		EOT
		)

		if command -v whiptail &>/dev/null; then
			whiptail --title "Confirm settings" --yesno "Please review your WireShield settings:\n\n${SUMMARY}\n\nProceed with installation?" 22 78
			if [[ $? -eq 0 ]]; then
				break
			else
				echo -e "${ORANGE}Let's update your settings...${NC}\n"
			fi
		else
			echo -e "\nPlease review your WireShield settings:\n${SUMMARY}"
			read -rp "Proceed with installation? [Y/n]: " -e CONFIRM
			CONFIRM=${CONFIRM:-Y}
			if [[ ${CONFIRM} =~ ^[Yy]$ ]]; then
				break
			else
				echo -e "${ORANGE}Let's update your settings...${NC}\n"
			fi
		fi
	done

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
	echo "You will be able to generate a client at the end of the installation."
	read -n1 -r -p "Press any key to continue..."
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
		read -rp "Enter domain name for 2FA service (e.g., vpn.example.com): " -e 2FA_DOMAIN
		
		if [[ -z "${2FA_DOMAIN}" ]]; then
			echo -e "${RED}Error: Domain name required for Let's Encrypt${NC}"
			return 1
		fi
		# Basic domain sanity: must not be an IP and must look like a hostname
		if [[ ${2FA_DOMAIN} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
			echo -e "${RED}Error: Let's Encrypt requires a DNS name (not an IP)${NC}"
			return 1
		fi
		if [[ ! ${2FA_DOMAIN} =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*)(\.[a-zA-Z0-9](-?[a-zA-Z0-9])*)+$ ]]; then
			echo -e "${RED}Error: Invalid domain format for Let's Encrypt: ${2FA_DOMAIN}${NC}"
			return 1
		fi
		
		echo -e "${ORANGE}Setting up Let's Encrypt certificate for ${2FA_DOMAIN}...${NC}"
		
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
			certbot certonly --standalone --non-interactive --agree-tos -m "admin@${2FA_DOMAIN}" \
				-d "${2FA_DOMAIN}" 2>/dev/null || {
				echo -e "${ORANGE}⚠ Let's Encrypt setup incomplete. Using self-signed certificate.${NC}"
				SSL_TYPE="2"
			}
		fi
		
		if [[ "${SSL_TYPE}" == "1" ]]; then
			# Symlink Let's Encrypt certs
			SSL_CERT_PATH="/etc/letsencrypt/live/${2FA_DOMAIN}/fullchain.pem"
			SSL_KEY_PATH="/etc/letsencrypt/live/${2FA_DOMAIN}/privkey.pem"
			
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
				certbot renew --dry-run --quiet 2>/dev/null || echo -e "${ORANGE}⚠ Certbot dry-run failed; check ports 80/443 and DNS for ${2FA_DOMAIN}${NC}"
				
				echo -e "${GREEN}✓ Let's Encrypt certificate configured${NC}"
				echo -e "${GREEN}✓ Auto-renewal enabled${NC}"
				echo "2FA_SSL_ENABLED=true" >> /etc/wireshield/2fa/config.env
				echo "2FA_SSL_TYPE=letsencrypt" >> /etc/wireshield/2fa/config.env
				echo "2FA_DOMAIN=${2FA_DOMAIN}" >> /etc/wireshield/2fa/config.env
				return 0
			fi
		fi
	fi
	
	# Self-signed certificate (for IP or localhost)
	read -rp "Enter IP address or hostname (e.g., 127.0.0.1 or vpn.local): " -e HOSTNAME_2FA
	
	if [[ -z "${HOSTNAME_2FA}" ]]; then
		HOSTNAME_2FA="127.0.0.1"
	fi
	
	echo -e "${ORANGE}Generating self-signed certificate for ${HOSTNAME_2FA}...${NC}"
	
	openssl req -x509 -newkey rsa:4096 \
		-keyout /etc/wireshield/2fa/key.pem \
		-out /etc/wireshield/2fa/cert.pem \
		-days 365 -nodes \
		-subj "/C=US/ST=State/L=City/O=WireShield/CN=${HOSTNAME_2FA}" 2>/dev/null || true
	
	chmod 600 /etc/wireshield/2fa/key.pem
	chmod 644 /etc/wireshield/2fa/cert.pem
	
	echo -e "${GREEN}✓ Self-signed certificate configured${NC}"
	echo "2FA_SSL_ENABLED=true" >> /etc/wireshield/2fa/config.env
	echo "2FA_SSL_TYPE=self-signed" >> /etc/wireshield/2fa/config.env
	echo "HOSTNAME_2FA=${HOSTNAME_2FA}" >> /etc/wireshield/2fa/config.env
}

function _ws_install_2fa_service() {
	# Install Python 2FA service and dependencies
	echo "Setting up WireShield 2FA service..."

	local VENV_PATH="/etc/wireshield/2fa/.venv"
	
	# Create 2FA directory and config file
	mkdir -p /etc/wireshield/2fa
	chmod 700 /etc/wireshield/2fa
	cat > /etc/wireshield/2fa/config.env << 'EOF'
# WireShield 2FA Configuration
# Generated during installation
2FA_DB_PATH=/etc/wireshield/2fa/auth.db
2FA_HOST=0.0.0.0
2FA_PORT=8443
2FA_LOG_LEVEL=INFO
2FA_RATE_LIMIT_MAX_REQUESTS=30
2FA_RATE_LIMIT_WINDOW=60
2FA_SSL_ENABLED=false
2FA_SSL_TYPE=none
2FA_DOMAIN=
HOSTNAME_2FA=127.0.0.1
EOF
	
	# Ensure Python 3 and pip are available
	if ! command -v python3 &>/dev/null; then
		echo "Installing Python 3..."
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			apt-get install -y python3 python3-pip python3-venv
		elif [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'oracle' ]]; then
			dnf install -y python3 python3-pip python3-venv || yum install -y python3 python3-pip python3-venv
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Sy --noconfirm python python-pip
		elif [[ ${OS} == 'alpine' ]]; then
			apk add python3 py3-pip py3-venv
		fi
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
	
	# Install systemd service file
	if [[ -f /etc/wireshield/2fa/wireshield-2fa.service ]]; then
		# Read config and create updated service file
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
Environment="2FA_DB_PATH=/etc/wireshield/2fa/auth.db"
Environment="2FA_HOST=0.0.0.0"
Environment="2FA_PORT=8443"
Environment="2FA_SSL_ENABLED=${2FA_SSL_ENABLED:-false}"
Environment="2FA_SSL_TYPE=${2FA_SSL_TYPE:-self-signed}"
Environment="2FA_DOMAIN=${2FA_DOMAIN:-}"
Environment="HOSTNAME_2FA=${HOSTNAME_2FA:-127.0.0.1}"
Environment="2FA_RATE_LIMIT_MAX_REQUESTS=${2FA_RATE_LIMIT_MAX_REQUESTS:-30}"
Environment="2FA_RATE_LIMIT_WINDOW=${2FA_RATE_LIMIT_WINDOW:-60}"
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
Environment="2FA_DB_PATH=/etc/wireshield/2fa/auth.db"
Environment="2FA_HOST=0.0.0.0"
Environment="2FA_PORT=8443"
Environment="2FA_RATE_LIMIT_MAX_REQUESTS=30"
Environment="2FA_RATE_LIMIT_WINDOW=60"
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
	
	echo -e "${GREEN}2FA service installed and started${NC}"
}

function _ws_enable_2fa_for_client() {
	# Enable 2FA for a specific client
	local client_id="$1"
	[[ -z "$client_id" ]] && return 1
	
	# Initialize client in 2FA database
	if command -v python3 &>/dev/null && [[ -f /etc/wireshield/2fa/auth.db ]]; then
		python3 << PYEOF 2>/dev/null || true
import sqlite3
try:
	conn = sqlite3.connect('/etc/wireshield/2fa/auth.db')
	c = conn.cursor()
	c.execute('SELECT id FROM users WHERE client_id = ?', ('$client_id',))
	if not c.fetchone():
		c.execute('INSERT INTO users (client_id, enabled) VALUES (?, ?)', ('$client_id', 0))
		conn.commit()
	conn.close()
except:
	pass
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
		apt-get install -y wireguard iptables resolvconf qrencode
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
		dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		# For RHEL-based systems
		if [[ ${VERSION_ID} == 8* ]]; then
			yum install -y epel-release elrepo-release
			yum install -y kmod-wireguard
			yum install -y qrencode # not available on release 9
		fi
		yum install -y wireguard-tools iptables
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		# Arch Linux has latest WireGuard in official repositories
		pacman -Sy --needed --noconfirm wireguard-tools qrencode
	elif [[ ${OS} == 'alpine' ]]; then
		# Alpine Linux supports WireGuard natively
		apk update
		apk add wireguard-tools iptables libqrencode-tools
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

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
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
# PersistentKeepalive helps with NAT traversal and keeps connection alive
# Uncomment the next line if you're behind NAT or firewall
# PersistentKeepalive = 25" >"${CLIENT_CONFIG}"

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
	_ws_enable_2fa_for_client "${CLIENT_NAME}"

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

function manageMenu() {
    # Main interactive loop used after installation to manage clients and server.
	while true; do
		clear
		_ws_header
		_ws_summary

		local MENU_OPTION
		if command -v whiptail &>/dev/null; then
			# Center the prompt text within the specified width (approximate centering)
			local MENU_HEIGHT=20 MENU_WIDTH=72 MENU_CHOICES=10
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
				10 "Uninstall WireShield" \
				11 "Exit" 3>&1 1>&2 2>&3) || MENU_OPTION=11
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
			echo "  10) Uninstall WireShield"
			echo "  11) Exit"
			until [[ ${MENU_OPTION} =~ ^[1-9]$|^10$|^11$ ]]; do
				read -rp "Select an option [1-11]: " MENU_OPTION
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
			uninstallWg ;;
		11)
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
