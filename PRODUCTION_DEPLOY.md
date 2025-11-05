# WireShield Dashboard - Production Deployment Guide

## 🚀 Quick Production Deployment

This guide ensures error-free deployment of the WireShield Dashboard to production.

### Prerequisites

- Linux server with systemd
- Root or sudo access
- WireGuard installed and configured
- Go 1.22+ (will be installed automatically if needed)

### Step 1: Fresh Installation

```bash
# Download the script
wget https://raw.githubusercontent.com/siyamsarker/WireShield/master/wireshield.sh

# Make it executable
chmod +x wireshield.sh

# Run the installer with dashboard option
sudo ./wireshield.sh
# Choose option: "Web Dashboard (Install/Setup)"
```

### Step 2: Verify Installation

```bash
# Check if the script is in the correct location
ls -la /root/wireshield.sh

# Check if the dashboard binary is installed
ls -la /usr/local/bin/wireshield-dashboard

# Check the systemd service
sudo systemctl status wireshield-dashboard

# Check the environment variable
sudo systemctl show wireshield-dashboard | grep WIRE_SHIELD_SCRIPT
```

### Step 3: Access the Dashboard

1. By default, the dashboard runs on `http://127.0.0.1:51821`
2. If you set up Nginx reverse proxy during installation, access via your configured domain
3. Login with the credentials you set during installation

### 🔧 Troubleshooting Production Issues

#### Issue 1: "bash: line 1: /root/wireshield.sh: No such file or directory"

**Solution:**
```bash
# Find where the script is located
find / -name "wireshield.sh" 2>/dev/null

# If found, update the systemd service
sudo systemctl edit wireshield-dashboard

# Add this line (replace with actual path):
[Service]
Environment="WIRE_SHIELD_SCRIPT=/actual/path/to/wireshield.sh"

# Save and restart
sudo systemctl daemon-reload
sudo systemctl restart wireshield-dashboard
```

#### Issue 2: Dashboard showing "Uninstall initiated" or broken menus

**Causes:**
- Script path not correctly set
- Dashboard binary outdated
- Configuration corrupted

**Solution:**
```bash
# 1. Stop the dashboard
sudo systemctl stop wireshield-dashboard

# 2. Rebuild the dashboard binary
cd /path/to/WireShield
go build -o /usr/local/bin/wireshield-dashboard ./cmd/wireshield-dashboard

# 3. Ensure script is at /root/wireshield.sh
sudo cp wireshield.sh /root/wireshield.sh
sudo chmod +x /root/wireshield.sh

# 4. Update systemd service to use correct path
sudo systemctl edit wireshield-dashboard
# Add: Environment="WIRE_SHIELD_SCRIPT=/root/wireshield.sh"

# 5. Restart the service
sudo systemctl daemon-reload
sudo systemctl restart wireshield-dashboard
```

#### Issue 3: Dashboard not starting

**Check logs:**
```bash
# View dashboard logs
sudo journalctl -u wireshield-dashboard -f

# Check for common errors:
# - Config file missing: Check /etc/wireshield/dashboard-config.json
# - Binary missing: Reinstall with go build
# - Port in use: Change listen address in config
```

### 📦 Manual Build & Deploy (If Needed)

```bash
# 1. Clone or update repository
git clone https://github.com/siyamsarker/WireShield.git
cd WireShield
git pull origin master

# 2. Build the dashboard binary
go build -o /usr/local/bin/wireshield-dashboard ./cmd/wireshield-dashboard

# 3. Copy script to standard location
sudo cp wireshield.sh /root/wireshield.sh
sudo chmod +x /root/wireshield.sh

# 4. Create systemd service
sudo tee /etc/systemd/system/wireshield-dashboard.service > /dev/null <<EOF
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

# 5. Initialize admin credentials (first time only)
/usr/local/bin/wireshield-dashboard -init-admin admin -init-admin-pass your_secure_password

# 6. Start the service
sudo systemctl daemon-reload
sudo systemctl enable --now wireshield-dashboard

# 7. Check status
sudo systemctl status wireshield-dashboard
```

### ✅ Production Checklist

- [ ] WireGuard is installed and running
- [ ] Script exists at `/root/wireshield.sh` and is executable
- [ ] Dashboard binary exists at `/usr/local/bin/wireshield-dashboard`
- [ ] Systemd service has `Environment=WIRE_SHIELD_SCRIPT=/root/wireshield.sh`
- [ ] Config file exists at `/etc/wireshield/dashboard-config.json`
- [ ] Dashboard service is running: `systemctl status wireshield-dashboard`
- [ ] Dashboard is accessible via browser
- [ ] All menus work (Dashboard, Clients, Add Client, Status, Settings)
- [ ] Can add/revoke clients successfully
- [ ] QR codes generate correctly
- [ ] Config downloads work

### 🔐 Security Recommendations

1. **Firewall Configuration:**
   ```bash
   # Only allow access from specific IPs
   sudo ufw allow from YOUR_IP to any port 51821
   ```

2. **Use Nginx Reverse Proxy with SSL:**
   ```bash
   # The installer can set up Nginx automatically
   # Or follow standard Nginx + Let's Encrypt setup
   ```

3. **Strong Admin Password:**
   ```bash
   # Change admin password from dashboard Settings menu
   # Or reinitialize: 
   /usr/local/bin/wireshield-dashboard -init-admin admin -init-admin-pass NEW_SECURE_PASSWORD
   ```

### 📝 Common Commands

```bash
# Start dashboard
sudo systemctl start wireshield-dashboard

# Stop dashboard
sudo systemctl stop wireshield-dashboard

# Restart dashboard
sudo systemctl restart wireshield-dashboard

# View logs
sudo journalctl -u wireshield-dashboard -f

# Reload after editing service file
sudo systemctl daemon-reload

# Check service status
sudo systemctl status wireshield-dashboard
```

### 🆘 Emergency Recovery

If dashboard is completely broken:

```bash
# 1. Stop everything
sudo systemctl stop wireshield-dashboard

# 2. Backup config
sudo cp /etc/wireshield/dashboard-config.json /root/dashboard-config.backup

# 3. Remove and reinstall
sudo systemctl disable wireshield-dashboard
sudo rm /etc/systemd/system/wireshield-dashboard.service
sudo rm /usr/local/bin/wireshield-dashboard

# 4. Reinstall using wireshield.sh
sudo ./wireshield.sh
# Choose: Web Dashboard (Install/Setup)

# 5. Restore admin if needed
sudo cp /root/dashboard-config.backup /etc/wireshield/dashboard-config.json
sudo systemctl restart wireshield-dashboard
```

---

**For support or issues, check the logs first:**
```bash
sudo journalctl -u wireshield-dashboard --no-pager -n 100
```

**Ensure you're running the latest version:**
```bash
cd /path/to/WireShield
git pull origin master
go build -o /usr/local/bin/wireshield-dashboard ./cmd/wireshield-dashboard
sudo systemctl restart wireshield-dashboard
```
