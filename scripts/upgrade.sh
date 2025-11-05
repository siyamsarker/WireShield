#!/bin/bash

###############################################################################
# WireShield - Production Upgrade Script (Full Project)
# Safely upgrades WireShield (CLI script + Dashboard) to the latest version.
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║            WireShield Production Upgrade (Full)           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}"
   exit 1
fi

# Check if systemd is available (required for dashboard management)
if ! command -v systemctl &> /dev/null; then
    echo -e "${RED}systemd is required but not found${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 1: Stopping dashboard service (if running)...${NC}"
systemctl stop wireshield-dashboard || true

echo -e "${YELLOW}Step 2: Backing up current dashboard configuration...${NC}"
if [ -f "/etc/wireshield/dashboard-config.json" ]; then
    cp /etc/wireshield/dashboard-config.json /etc/wireshield/dashboard-config.json.backup
    echo -e "${GREEN}✓ Config backed up to /etc/wireshield/dashboard-config.json.backup${NC}"
fi

echo -e "${YELLOW}Step 3: Updating repository...${NC}"
# Detect or clone repository
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

echo -e "${YELLOW}Step 4: Ensuring Go toolchain (for dashboard build)...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}Installing Go...${NC}"
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

echo -e "${YELLOW}Step 5: Upgrading CLI script (wireshield.sh)...${NC}"
# Source of truth: repo copy in $INSTALL_DIR
if [ -f "$INSTALL_DIR/wireshield.sh" ]; then
    cp "$INSTALL_DIR/wireshield.sh" /root/wireshield.sh
    chmod +x /root/wireshield.sh
    echo -e "${GREEN}✓ CLI script installed at /root/wireshield.sh${NC}"
    # Optional convenience path for admins
    cp "$INSTALL_DIR/wireshield.sh" /usr/local/bin/wireshield.sh 2>/dev/null || true
    chmod +x /usr/local/bin/wireshield.sh 2>/dev/null || true
else
    echo -e "${RED}Error: repo copy of wireshield.sh not found at $INSTALL_DIR/wireshield.sh${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 6: Building dashboard binary...${NC}"
cd "$INSTALL_DIR"
go build -o /usr/local/bin/wireshield-dashboard ./cmd/wireshield-dashboard
chmod +x /usr/local/bin/wireshield-dashboard
echo -e "${GREEN}✓ Dashboard binary built and installed at /usr/local/bin/wireshield-dashboard${NC}"

echo -e "${YELLOW}Step 7: Ensuring systemd service is configured...${NC}"
SERVICE_FILE="/etc/systemd/system/wireshield-dashboard.service"
if [ ! -f "$SERVICE_FILE" ]; then
    echo -e "${YELLOW}Creating systemd service...${NC}"
    cat > "$SERVICE_FILE" <<EOF
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
    # Ensure environment variable is present and points to /root/wireshield.sh
    if ! grep -q "Environment=WIRE_SHIELD_SCRIPT" "$SERVICE_FILE"; then
        sed -i '/\[Service\]/a Environment=WIRE_SHIELD_SCRIPT=/root/wireshield.sh' "$SERVICE_FILE"
    else
        sed -i 's|Environment=WIRE_SHIELD_SCRIPT=.*|Environment=WIRE_SHIELD_SCRIPT=/root/wireshield.sh|' "$SERVICE_FILE"
    fi
fi

echo -e "${YELLOW}Step 8: Reloading systemd and starting dashboard...${NC}"
systemctl daemon-reload
systemctl enable wireshield-dashboard || true
systemctl start wireshield-dashboard || true

echo -e "${YELLOW}Step 9: Verifying services...${NC}"
sleep 2

# Check dashboard service
if systemctl is-active --quiet wireshield-dashboard; then
    echo -e "${GREEN}✓ Dashboard service is running${NC}"
else
    echo -e "${RED}✗ Dashboard service failed to start${NC}"
    echo -e "${YELLOW}Recent logs:${NC}"
    journalctl -u wireshield-dashboard -n 30 --no-pager || true
fi

# Confirm script accessibility for dashboard
if [ -f "/root/wireshield.sh" ] && [ -x "/root/wireshield.sh" ]; then
    echo -e "${GREEN}✓ CLI script is accessible at /root/wireshield.sh${NC}"
else
    echo -e "${RED}✗ CLI script not found or not executable at /root/wireshield.sh${NC}"
fi

# Determine dashboard bind
DASHBOARD_ADDR=$(grep -oP '(?<=-listen )[0-9.]+:[0-9]+' "$SERVICE_FILE" || echo "127.0.0.1:51821")

echo -e "\n${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                Upgrade Completed Successfully             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BLUE}Dashboard URL:${NC} http://$DASHBOARD_ADDR"
echo -e "${BLUE}Dashboard Service:${NC} systemctl status wireshield-dashboard"
echo -e "${BLUE}CLI Script:${NC} /root/wireshield.sh (and /usr/local/bin/wireshield.sh)"
echo -e "${BLUE}Logs:${NC} journalctl -u wireshield-dashboard -f"
echo ""
