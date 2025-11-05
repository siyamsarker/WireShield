#!/bin/bash

###############################################################################
# WireShield Dashboard - Production Upgrade Script
# This script upgrades the dashboard to the latest version on a production server
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║       WireShield Dashboard Production Upgrade             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}"
   exit 1
fi

# Check if systemd is available
if ! command -v systemctl &> /dev/null; then
    echo -e "${RED}systemd is required but not found${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 1: Stopping dashboard service...${NC}"
systemctl stop wireshield-dashboard || true

echo -e "${YELLOW}Step 2: Backing up current configuration...${NC}"
if [ -f "/etc/wireshield/dashboard-config.json" ]; then
    cp /etc/wireshield/dashboard-config.json /etc/wireshield/dashboard-config.json.backup
    echo -e "${GREEN}✓ Config backed up to /etc/wireshield/dashboard-config.json.backup${NC}"
fi

echo -e "${YELLOW}Step 3: Updating repository...${NC}"
# Check if WireShield directory exists
INSTALL_DIR=""
for dir in /root/WireShield /opt/WireShield /home/*/WireShield; do
    if [ -d "$dir/.git" ]; then
        INSTALL_DIR="$dir"
        break
    fi
done

if [ -z "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}WireShield repository not found. Cloning fresh copy...${NC}"
    INSTALL_DIR="/opt/WireShield"
    mkdir -p /opt
    cd /opt
    git clone https://github.com/siyamsarker/WireShield.git
    cd WireShield
else
    echo -e "${GREEN}✓ Found repository at: $INSTALL_DIR${NC}"
    cd "$INSTALL_DIR"
    git fetch origin
    git reset --hard origin/master
    git pull origin master
fi

echo -e "${YELLOW}Step 4: Installing/Updating Go dependencies...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}Installing Go...${NC}"
    # Install Go based on package manager
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y golang-go
    elif command -v dnf &> /dev/null; then
        dnf install -y golang
    elif command -v yum &> /dev/null; then
        yum install -y golang
    else
        echo -e "${RED}Please install Go 1.22+ manually${NC}"
        exit 1
    fi
fi

echo -e "${YELLOW}Step 5: Building dashboard binary...${NC}"
cd "$INSTALL_DIR"
go build -o /usr/local/bin/wireshield-dashboard ./cmd/wireshield-dashboard
chmod +x /usr/local/bin/wireshield-dashboard
echo -e "${GREEN}✓ Dashboard binary built and installed${NC}"

echo -e "${YELLOW}Step 6: Ensuring wireshield.sh is in correct location...${NC}"
# Find the script
SCRIPT_PATH=""
if [ -f "$INSTALL_DIR/wireshield.sh" ]; then
    SCRIPT_PATH="$INSTALL_DIR/wireshield.sh"
elif [ -f "/root/wireshield.sh" ]; then
    SCRIPT_PATH="/root/wireshield.sh"
elif [ -f "/usr/local/bin/wireshield.sh" ]; then
    SCRIPT_PATH="/usr/local/bin/wireshield.sh"
fi

if [ -n "$SCRIPT_PATH" ]; then
    # Always copy to /root for dashboard access
    cp "$SCRIPT_PATH" /root/wireshield.sh
    chmod +x /root/wireshield.sh
    echo -e "${GREEN}✓ Script installed at /root/wireshield.sh${NC}"
else
    echo -e "${RED}Error: wireshield.sh not found${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 7: Updating systemd service...${NC}"
# Check if service file exists
if [ ! -f "/etc/systemd/system/wireshield-dashboard.service" ]; then
    echo -e "${YELLOW}Creating systemd service...${NC}"
    cat > /etc/systemd/system/wireshield-dashboard.service <<EOF
[Unit]
Description=WireShield Web Dashboard
After=network.target

[Service]
Type=simple
User=root
Group=root
Environment=WIRE_SHIELD_SCRIPT=/root/wireshield.sh
ExecStart=/usr/local/bin/wireshield-dashboard -config /etc/wireshield/dashboard-config.json -listen 127.0.0.1:51821
Restart=on-failure
RestartSec=5s

NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
else
    # Update environment variable in existing service
    if ! grep -q "Environment=WIRE_SHIELD_SCRIPT" /etc/systemd/system/wireshield-dashboard.service; then
        # Add environment variable after [Service]
        sed -i '/\[Service\]/a Environment=WIRE_SHIELD_SCRIPT=/root/wireshield.sh' /etc/systemd/system/wireshield-dashboard.service
    else
        # Update existing environment variable
        sed -i 's|Environment=WIRE_SHIELD_SCRIPT=.*|Environment=WIRE_SHIELD_SCRIPT=/root/wireshield.sh|' /etc/systemd/system/wireshield-dashboard.service
    fi
fi

echo -e "${YELLOW}Step 8: Reloading systemd and starting service...${NC}"
systemctl daemon-reload
systemctl enable wireshield-dashboard
systemctl start wireshield-dashboard

echo -e "${YELLOW}Step 9: Verifying installation...${NC}"
sleep 2

# Check if service is running
if systemctl is-active --quiet wireshield-dashboard; then
    echo -e "${GREEN}✓ Dashboard service is running${NC}"
else
    echo -e "${RED}✗ Dashboard service failed to start${NC}"
    echo -e "${YELLOW}Checking logs:${NC}"
    journalctl -u wireshield-dashboard -n 20 --no-pager
    exit 1
fi

# Check if script is accessible
if [ -f "/root/wireshield.sh" ] && [ -x "/root/wireshield.sh" ]; then
    echo -e "${GREEN}✓ Script is accessible at /root/wireshield.sh${NC}"
else
    echo -e "${RED}✗ Script not found or not executable${NC}"
    exit 1
fi

# Get dashboard port
DASHBOARD_PORT=$(grep -oP '(?<=-listen )[0-9.]+:[0-9]+' /etc/systemd/system/wireshield-dashboard.service || echo "127.0.0.1:51821")

echo -e "\n${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║             Upgrade Completed Successfully!               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BLUE}Dashboard URL:${NC} http://$DASHBOARD_PORT"
echo -e "${BLUE}Service Status:${NC} systemctl status wireshield-dashboard"
echo -e "${BLUE}View Logs:${NC} journalctl -u wireshield-dashboard -f"
echo -e "${BLUE}Restart:${NC} systemctl restart wireshield-dashboard"
echo ""
