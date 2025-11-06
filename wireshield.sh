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
# Version: 2.0.0
# ============================================================================

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

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
		echo -e "Version ${GREEN}2.0.0${NC} • Made with ${RED}❤️${NC}  by ${GREEN}Siyam Sarker${NC}"
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
		echo -e "${GREEN}WireShield v2.0.0${NC} – Professional WireGuard VPN Management"
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

	# Check if WireGuard was installed successfully
	if ! command -v wg &>/dev/null; then
		echo -e "${RED}Error: WireGuard installation failed. The 'wg' command is not available.${NC}"
		exit 1
	fi

	# Display installed WireGuard version
	echo -e "${GREEN}WireGuard tools installed successfully!${NC}"
	wg --version 2>/dev/null || echo "WireGuard tools version: $(wg version 2>/dev/null || echo 'installed')"

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

	# Create the first client now; you can add more later from the menu
	newClient
	echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

	# Optionally offer to install the web dashboard
	_ws_offer_dashboard_install

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
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
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
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
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
	# Uninstall WireGuard and remove configuration. Single confirmation,
	# then performs a best-effort cleanup of client config files under /root and /home.
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall WireGuard and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove WireGuard? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
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

		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${SERVER_WG_NIC}" stop
			rc-update del "wg-quick.${SERVER_WG_NIC}"
			unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
			rc-update del sysctl
		else
			systemctl stop "wg-quick@${SERVER_WG_NIC}"
			systemctl disable "wg-quick@${SERVER_WG_NIC}"
		fi

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools qrencode
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		elif [[ ${OS} == 'alpine' ]]; then
			(cd qrencode-4.1.1 || exit && make uninstall)
			rm -rf qrencode-* || exit
			apk del wireguard-tools libqrencode libqrencode-tools
		fi

		# Remove server configuration directory
		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		# Remove automatic expiration cron job and helper script
		# Delete helper if present
		rm -f /usr/local/bin/wireshield-check-expired
		# Remove crontab entry if present (ignore errors when crontab unset)
		if crontab -l 2>/dev/null | grep -q "wireshield-check-expired"; then
			crontab -l 2>/dev/null | sed '/wireshield-check-expired/d' | crontab - 2>/dev/null || true
		fi

		# Remove client config files from user home directories (canonical and simplified names)
		SEARCH_DIRS=(/root /home)
		for cname in "${CLIENT_NAMES[@]}"; do
			for base in "${SEARCH_DIRS[@]}"; do
				# remove client config files if they exist within depth 2
				find "$base" -maxdepth 2 -type f -name "${cname}.conf" \
					-print -delete 2>/dev/null
			done
		done

		# Remove Web Dashboard service and config if present
		if systemctl list-unit-files | grep -q '^wireshield-dashboard.service'; then
			systemctl disable --now wireshield-dashboard 2>/dev/null || true
			rm -f /etc/systemd/system/wireshield-dashboard.service
			systemctl daemon-reload || true
		fi
		rm -f /usr/local/bin/wireshield-dashboard
		rm -rf /etc/wireshield

		# Remove Nginx configuration for WireShield dashboard
		if command -v nginx >/dev/null 2>&1; then
			# Remove config files
			rm -f /etc/nginx/sites-available/wireshield-dashboard
			rm -f /etc/nginx/sites-enabled/wireshield-dashboard
			rm -f /etc/nginx/conf.d/wireshield-dashboard.conf
			
			# Test config and reload if valid
			if nginx -t 2>/dev/null; then
				systemctl reload nginx 2>/dev/null || true
			fi
			
			# Optionally remove Nginx if it was installed for WireShield
			read -rp "Remove Nginx as well? [y/N]: " -e REMOVE_NGINX
			REMOVE_NGINX=${REMOVE_NGINX:-N}
			if [[ ${REMOVE_NGINX} =~ ^[Yy]$ ]]; then
				systemctl stop nginx 2>/dev/null || true
				systemctl disable nginx 2>/dev/null || true
				
				if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
					apt-get remove -y nginx nginx-common
				elif [[ ${OS} == 'fedora' ]]; then
					dnf remove -y nginx
				elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'oracle' ]]; then
					yum remove -y nginx
				elif [[ ${OS} == 'arch' ]]; then
					pacman -Rs --noconfirm nginx
				elif [[ ${OS} == 'alpine' ]]; then
					apk del nginx
				fi
				echo "Nginx removed."
			else
				echo "Nginx configuration for WireShield removed, but Nginx itself kept."
			fi
		fi

		if [[ ${OS} == 'alpine' ]]; then
			rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status &>/dev/null
		else
			# Reload sysctl
			sysctl --system

			# Check if WireGuard is running
			systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		fi
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard failed to uninstall properly."
			exit 1
		else
			echo "WireGuard uninstalled successfully."
			echo "All detected client .conf files have been removed from /root and /home."
			echo "Removed WireShield cron job and helper script for auto-expiration."
			echo "Removed WireShield Web Dashboard binary, service unit, config, and Nginx configuration (if present)."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function _ws_header() {
    # Draw a simple header for the interactive menu.
	echo -e "${GREEN}Welcome to WireShield ✨${NC}"
	echo "Repository: https://github.com/siyamsarker/WireShield"
	echo ""
}

# Offer to install the optional web dashboard (prebuilt or build-from-source)
function _ws_offer_dashboard_install() {
	echo ""
	read -rp "Install WireShield Web Dashboard (binds to 127.0.0.1:51821)? [Y/n]: " -e DASH
	DASH=${DASH:-Y}
	if [[ ${DASH} =~ ^[Yy]$ ]]; then
		# Ask for bind address and optional Nginx
		local default_listen="127.0.0.1:51821" listen_addr="" setup_nginx="" public_host=""
		read -rp "Dashboard bind address [ip:port] (recommended: 127.0.0.1:51821): " -e -i "$default_listen" listen_addr
		listen_addr=${listen_addr:-$default_listen}

		read -rp "Configure Nginx reverse proxy for a domain or IP? [y/N]: " -e setup_nginx
		setup_nginx=${setup_nginx:-N}
		
		# Accept either y/Y or direct domain/IP entry
		if [[ ${setup_nginx} =~ ^[Yy]$ ]]; then
			read -rp "Enter domain or IP to serve (e.g., vpn.example.com or 54.254.156.85): " -e public_host
		elif [[ -n "${setup_nginx}" && ! ${setup_nginx} =~ ^[Nn]$ ]]; then
			# User directly entered domain/IP instead of y/N
			public_host="${setup_nginx}"
		fi

		_ws_install_dashboard_inline "$listen_addr" "$public_host"
	fi
}

# Inline dashboard installer (Linux + systemd). Builds Go binary if needed, writes config, and sets up systemd.
function _ws_install_dashboard_inline() {
	set -e
	local BIN_NAME PREFIX CONFIG_DIR SERVICE_FILE REPO_ROOT OS ARCH
	BIN_NAME=wireshield-dashboard
	PREFIX=/usr/local/bin
	CONFIG_DIR=/etc/wireshield
	SERVICE_FILE=/etc/systemd/system/wireshield-dashboard.service
	local LISTEN_ADDR NGX_HOST
	LISTEN_ADDR=${1:-"127.0.0.1:51821"}
	NGX_HOST=${2:-""}
	# repo root is the directory containing this script
	REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

	# Track whether we created a fresh dashboard config to print credentials at the very end
	local PRINT_CREDS=0 ADMIN_USER="admin" INIT_PW=""

	# Detect platform (Linux expected)
	OS=$(uname -s | tr '[:upper:]' '[:lower:]')
	if [[ "$OS" != "linux" ]]; then
		echo -e "${RED}The web dashboard install is supported on Linux servers (systemd) only.${NC}"
		return 1
	fi

	# Ensure Go toolchain
	if ! command -v go >/dev/null 2>&1; then
		echo "Installing Go toolchain..."
		local PM=""
		if command -v apt-get >/dev/null 2>&1; then PM=apt-get; fi
		if command -v dnf >/dev/null 2>&1; then PM=dnf; fi
		if command -v yum >/dev/null 2>&1; then PM=yum; fi
		if command -v pacman >/dev/null 2>&1; then PM=pacman; fi
		if command -v apk >/dev/null 2>&1; then PM=apk; fi
		case "$PM" in
			apt-get) apt-get update -y && apt-get install -y golang || true;;
			dnf) dnf install -y golang || true;;
			yum) yum install -y golang || true;;
			pacman) pacman -Sy --noconfirm go || true;;
			apk) apk add --no-cache go || true;;
		esac
		if ! command -v go >/dev/null 2>&1; then
			# Fallback to official tarball (Linux only)
			ARCH=$(uname -m)
			case "$ARCH" in
				x86_64|amd64) ARCH=amd64;;
				aarch64|arm64) ARCH=arm64;;
				i386|i686) ARCH=386;;
				*) echo -e "${RED}Unsupported ARCH for Go tarball: $ARCH${NC}"; return 1;;
			esac
			local GOV TAR url tmpdir
			GOV=1.22.0
			TAR="go${GOV}.linux-${ARCH}.tar.gz"
			url="https://go.dev/dl/${TAR}"
			tmpdir=$(mktemp -d)
			trap 'rm -rf "$tmpdir"' RETURN
			echo "Downloading Go: $url"
			curl -fsSL "$url" -o "$tmpdir/go.tgz"
			rm -rf /usr/local/go
			tar -C /usr/local -xzf "$tmpdir/go.tgz"
			export PATH="/usr/local/go/bin:$PATH"
		fi
	fi

	echo "Building dashboard from source..."
	
	# Check if go.mod exists in REPO_ROOT (cloned repo scenario)
	if [[ ! -f "$REPO_ROOT/go.mod" ]]; then
		# Standalone script scenario: clone the repo to build
		echo "Cloning WireShield repository to build dashboard..."
		local TEMP_CLONE
		TEMP_CLONE=$(mktemp -d)
		trap 'rm -rf "$TEMP_CLONE"' RETURN
		git clone --depth=1 https://github.com/siyamsarker/WireShield.git "$TEMP_CLONE" || {
			echo -e "${RED}Failed to clone repository. Ensure git is installed.${NC}"
			return 1
		}
		(cd "$TEMP_CLONE" && go build -o "$BIN_NAME" ./cmd/wireshield-dashboard)
		install -m 0755 "$TEMP_CLONE/$BIN_NAME" "$PREFIX/$BIN_NAME"
	else
		# Cloned repo scenario: build directly
		(cd "$REPO_ROOT" && go build -o "$BIN_NAME" ./cmd/wireshield-dashboard)
		install -m 0755 "$REPO_ROOT/$BIN_NAME" "$PREFIX/$BIN_NAME"
	fi

	mkdir -p "$CONFIG_DIR"
	if [[ ! -f "$CONFIG_DIR/dashboard-config.json" ]]; then
		echo "Initializing dashboard config..."
		local randpw
		randpw=$(openssl rand -hex 12 2>/dev/null || head -c 12 /dev/urandom | hexdump -v -e '/1 "%02x"')
		"$PREFIX/$BIN_NAME" -init-admin admin -init-admin-pass "$randpw" -config "$CONFIG_DIR/dashboard-config.json"
		# Defer printing credentials until installation completes
		INIT_PW="$randpw"
		PRINT_CREDS=1
	fi

	# Resolve script path for dashboard integration
	local WS_SCRIPT_PATH CURRENT_SCRIPT
	
	# Find the current running script (realpath if available for symlink resolution)
	if command -v realpath >/dev/null 2>&1; then
		CURRENT_SCRIPT=$(realpath "${BASH_SOURCE[0]}" 2>/dev/null || readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")
	else
		CURRENT_SCRIPT="${BASH_SOURCE[0]}"
		# Make it absolute if relative
		[[ "$CURRENT_SCRIPT" != /* ]] && CURRENT_SCRIPT="$(pwd)/$CURRENT_SCRIPT"
	fi
	
	# Verify we have a valid source script before proceeding
	if [[ ! -f "$CURRENT_SCRIPT" ]]; then
		echo -e "${RED}Error: Cannot locate current script at $CURRENT_SCRIPT${NC}"
		return 1
	fi
	
	# Ensure the script is in a permanent location for the dashboard to use
	# Always install/update to /usr/local/bin and /root for redundancy
	echo "Installing wireshield.sh to system locations for dashboard access..."
	
	# Install to /usr/local/bin (preferred, on PATH)
	if install -m 0755 "$CURRENT_SCRIPT" /usr/local/bin/wireshield.sh 2>/dev/null; then
		echo "✓ Installed to /usr/local/bin/wireshield.sh"
		WS_SCRIPT_PATH="/usr/local/bin/wireshield.sh"
	else
		echo -e "${YELLOW}⚠ Could not install to /usr/local/bin, trying /root...${NC}"
		if install -m 0755 "$CURRENT_SCRIPT" /root/wireshield.sh 2>/dev/null; then
			echo "✓ Installed to /root/wireshield.sh"
			WS_SCRIPT_PATH="/root/wireshield.sh"
		else
			echo -e "${RED}Error: Failed to install script to /usr/local/bin or /root${NC}"
			echo -e "${RED}Check permissions and try running with sudo${NC}"
			return 1
		fi
	fi
	
	# Also install to /root as backup if we succeeded with /usr/local/bin
	if [[ "$WS_SCRIPT_PATH" == "/usr/local/bin/wireshield.sh" ]]; then
		if install -m 0755 "$CURRENT_SCRIPT" /root/wireshield.sh 2>/dev/null; then
			echo "✓ Backup copy installed to /root/wireshield.sh"
		fi
	fi
	
	# Verify the primary script path exists and is executable
	if [[ ! -f "$WS_SCRIPT_PATH" ]]; then
		echo -e "${RED}Error: Script not found at $WS_SCRIPT_PATH after installation${NC}"
		return 1
	fi
	
	if [[ ! -x "$WS_SCRIPT_PATH" ]]; then
		echo -e "${YELLOW}⚠ Script is not executable, fixing permissions...${NC}"
		chmod +x "$WS_SCRIPT_PATH" || {
			echo -e "${RED}Error: Could not make script executable${NC}"
			return 1
		}
	fi
	
	echo -e "${GREEN}✓ Dashboard will use script: $WS_SCRIPT_PATH${NC}"

	cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=WireShield Web Dashboard
After=network.target

[Service]
Type=simple
User=root
Group=root
Environment=WIRE_SHIELD_SCRIPT=$WS_SCRIPT_PATH
ExecStart=/usr/local/bin/wireshield-dashboard -config /etc/wireshield/dashboard-config.json -listen ${LISTEN_ADDR}
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

	echo "Dashboard started on http://${LISTEN_ADDR} (can be changed with: sudo systemctl edit wireshield-dashboard or editing the config)."

	# If requested, set up Nginx reverse proxy
	if [[ -n "$NGX_HOST" ]]; then
		_ws_setup_nginx_reverse_proxy "$NGX_HOST" "$LISTEN_ADDR"
	fi

	# Finally, print the credentials if this was a fresh install
	if [[ "$PRINT_CREDS" -eq 1 ]]; then
		echo ""
		echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
		echo -e "${GREEN}Dashboard credentials:${NC}"
		echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
		echo -e "  Username: ${ORANGE}${ADMIN_USER}${NC}"
		echo -e "  Password: ${ORANGE}${INIT_PW}${NC}"
		echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
		echo -e "${YELLOW}⚠️  Save these credentials now! Change the password after first login.${NC}"
		echo ""
	fi
}

# Configure Nginx reverse proxy to forward to the dashboard
function _ws_setup_nginx_reverse_proxy() {
	local SERVER_NAME="$1" LISTEN="$2" PM CONF_PATH ENABLE_SYMLINK=0
	if [[ -z "$SERVER_NAME" ]]; then return 0; fi

	# Install nginx if missing
	if ! command -v nginx >/dev/null 2>&1; then
		echo "Installing Nginx..."
		if command -v apt-get >/dev/null 2>&1; then
			apt-get update -y && apt-get install -y nginx
		elif command -v dnf >/dev/null 2>&1; then
			dnf install -y nginx
		elif command -v yum >/dev/null 2>&1; then
			yum install -y nginx
		elif command -v pacman >/dev/null 2>&1; then
			pacman -Sy --noconfirm nginx
		elif command -v apk >/dev/null 2>&1; then
			apk add --no-cache nginx
		else
			echo -e "${ORANGE}Could not determine package manager to install Nginx. Skipping Nginx setup.${NC}"
			return 0
		fi
		systemctl enable --now nginx || true
	fi

	# Choose config location
	if [[ -d /etc/nginx/sites-available ]]; then
		CONF_PATH=/etc/nginx/sites-available/wireshield-dashboard
		ENABLE_SYMLINK=1
	else
		CONF_PATH=/etc/nginx/conf.d/wireshield-dashboard.conf
		ENABLE_SYMLINK=0
	fi

	# Extract upstream port from LISTEN (default 51821)
	local UP_PORT
	UP_PORT=$(echo "$LISTEN" | awk -F: '{print $NF}')
	if [[ -z "$UP_PORT" ]]; then UP_PORT=51821; fi

	cat > "$CONF_PATH" <<NGINX
server {
	listen 80;
	server_name ${SERVER_NAME} _;

	location / {
		proxy_pass http://127.0.0.1:${UP_PORT};
		proxy_http_version 1.1;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto \$scheme;
	}
}
NGINX

	if [[ $ENABLE_SYMLINK -eq 1 ]]; then
		ln -sf "$CONF_PATH" /etc/nginx/sites-enabled/wireshield-dashboard
	fi

	# Test and reload Nginx
	if nginx -t; then
		systemctl reload nginx
		echo -e "${GREEN}Nginx reverse proxy configured for http://${SERVER_NAME}/ → 127.0.0.1:${UP_PORT}${NC}"
		echo -e "${ORANGE}Remember to open TCP/80 (and 443 if you later enable HTTPS) in your firewall/security group.${NC}"
	else
		echo -e "${RED}Nginx configuration test failed. Please check the config and logs.${NC}"
	fi
}

function _ws_summary() {
    # Show a concise summary of interface, endpoint, peer count, and service status.
	local peers
	peers=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" 2>/dev/null || echo 0)
	echo "Interface : ${SERVER_WG_NIC}"
	echo "Endpoint  : ${SERVER_PUB_IP}:${SERVER_PORT}"
	echo "Clients   : ${peers}"
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status && echo "Status    : running" || echo "Status    : not running"
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}" && echo "Status    : running" || echo "Status    : not running"
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
	echo -e "${GREEN}WireGuard status:${NC}"
	wg show || true
}

function restartWireGuard() {
    # Restart the WireGuard interface service using the appropriate init system.
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
	local ts out
	ts=$(date +%Y%m%d-%H%M%S)
	out="/root/wireshield-backup-${ts}.tar.gz"
	tar czf "${out}" /etc/wireguard 2>/dev/null && echo -e "${GREEN}Backup saved to ${out}${NC}" || echo -e "${RED}Backup failed.${NC}"
}

function manageMenu() {
    # Main interactive loop used after installation to manage clients and server.
	while true; do
		clear
		_ws_header
		_ws_summary

		local MENU_OPTION
		if command -v whiptail &>/dev/null; then
			MENU_OPTION=$(whiptail --title "WireShield" --menu "Choose an action" 20 72 10 \
				1 "Add a new client" \
				2 "List clients" \
				3 "Show QR for a client" \
				4 "Revoke a client" \
				5 "Check expired clients" \
				6 "Show server status" \
				7 "Restart WireShield" \
				8 "Backup configuration" \
				9 "Uninstall WireShield" \
				10 "Exit" 3>&1 1>&2 2>&3) || MENU_OPTION=10
		else
			echo "What do you want to do?"
			echo "   1) Add a new client"
			echo "   2) List clients"
			echo "   3) Show QR for a client"
			echo "   4) Revoke existing client"
			echo "   5) Check expired clients"
			echo "   6) Show server status"
			echo "   7) Restart WireShield"
			echo "   8) Backup configuration"
			echo "   9) Uninstall WireShield"
			echo "  10) Exit"
			until [[ ${MENU_OPTION} =~ ^[1-9]$|^10$ ]]; do
				read -rp "Select an option [1-10]: " MENU_OPTION
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
			backupConfigs ;;
		9)
			uninstallWg ;;
		10)
			exit 0 ;;
		esac

		echo ""
		read -rp "Press Enter to continue..." _
	done
}

# ================ Programmatic API (for dashboard/automation) =================

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
