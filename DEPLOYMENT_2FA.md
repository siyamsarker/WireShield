# WireShield 2FA Deployment Guide

This guide walks through deploying and testing the complete WireShield 2FA system.

## Overview

WireShield now includes **pre-connection 2FA authentication** using Google Authenticator (TOTP):

1. **Users create VPN clients** via CLI
2. **On first connection**, users are redirected to a secure web UI
3. **Users set up Google Authenticator** by scanning a QR code
4. **Subsequent connections** require TOTP verification
5. **Sessions remain valid** until disconnect (24-hour default timeout)

## Architecture

```
┌─────────────────┐
│  User Device    │  Step 1: WireGuard client attempts connection
│  (WireGuard)    │
└────────┬────────┘
         │
         │ UDP/51820
         │
┌────────▼──────────────────┐
│  WireShield VPN Server     │
│  ┌──────────────────────┐  │  Step 2: Firewall intercepts,
│  │  Firewall Rules      │  │  redirects to 2FA service
│  │  (iptables/fw)       │  │
│  └──────────┬───────────┘  │
│             │              │
│  ┌──────────▼───────────┐  │  Step 3: 2FA service
│  │  2FA Service         │  │  (FastAPI on port 8443)
│  │  (Port 8443, HTTPS)  │  │
│  │  ┌────────────────┐  │  │
│  │  │  SQLite DB     │  │  │  Step 4: TOTP secrets
│  │  │  - User secrets│  │  │  stored in DB
│  │  │  - Sessions    │  │  │
│  │  │  - Audit logs  │  │  │
│  │  └────────────────┘  │  │
│  └──────────────────────┘  │
└────────────────────────────┘
```

## Installation

### Automatic Installation (Recommended)

```bash
# 1. Clone or download WireShield
cd /opt/wireshield

# 2. Make the script executable
chmod +x wireshield.sh

# 3. Run as root
sudo ./wireshield.sh

# Follow the prompts:
# - Server IP (your VPN public IP)
# - Network interface (eth0, wlan0, etc.)
# - Port (default 51820)
# - DNS servers (8.8.8.8, 1.1.1.1)
# 
# The script will:
# ✓ Install WireGuard
# ✓ Install Python 3 + dependencies
# ✓ Set up 2FA service
# ✓ Generate SSL certificates
# ✓ Start systemd service
# ✓ Create first VPN client
```

### Manual Installation

If automatic fails, install manually:

```bash
# 1. Install WireGuard (see main README)
sudo ./wireshield.sh # Install WireGuard only, skip 2FA setup

# 2. Copy 2FA files
sudo mkdir -p /etc/wireshield/2fa
sudo cp 2fa-auth/* /etc/wireshield/2fa/
sudo chmod 755 /etc/wireshield/2fa/*.sh

# 3. Install Python dependencies
sudo pip3 install -r /etc/wireshield/2fa/requirements.txt

# 4. Generate SSL certificates
sudo bash /etc/wireshield/2fa/generate-certs.sh 365

# 5. Install systemd service
sudo cp /etc/wireshield/2fa/wireshield-2fa.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable wireshield-2fa
sudo systemctl start wireshield-2fa

# 6. Verify
sudo systemctl status wireshield-2fa
```

## Verification

### Check Installation

```bash
# 1. Verify WireGuard
sudo wg show

# Expected output:
# interface: wg0
# public key: <key>
# listening port: 51820

# 2. Verify 2FA service
sudo systemctl status wireshield-2fa

# Expected output:
# ● wireshield-2fa.service - WireShield 2FA Authentication Service
#   Loaded: loaded (...)
#   Active: active (running)

# 3. Check 2FA database
sudo ls -la /etc/wireshield/2fa/auth.db

# Expected output:
# -rw------- 1 root root 12288 Jan 15 10:30 /etc/wireshield/2fa/auth.db

# 4. View service logs
sudo journalctl -u wireshield-2fa -n 20
```

### Run Integration Tests

```bash
# Execute the test suite
bash /etc/wireshield/2fa/test-integration.sh

# Expected output:
# [Test 1] Checking Python3...
# ✓ Python 3.9.13
# 
# [Test 2] Checking Python dependencies...
# ✓ All required packages installed
# 
# ... (more tests)
#
# ✓ 2FA integration test completed
```

## Usage

### Create a New VPN Client

```bash
# From any machine with SSH access to the server
ssh root@<server_ip>

# Run WireShield menu
/opt/wireshield/wireshield.sh

# Select: "Create Client"
# Enter client name: "alice"
# Follow prompts for IPs and expiration
```

### First-Time Client Connection

```bash
# On client machine, import the WireGuard config
# alice.conf was created on the server

# On Linux:
sudo wg-quick up ./alice.conf

# On macOS/Windows:
# Use WireGuard GUI app, import alice.conf

# First time: Browser opens (or go to https://127.0.0.1:8443/?client_id=alice)
```

### 2FA Setup Flow

1. **User sees web UI** with:
   - WireShield 2FA branding
   - Step-by-step instructions
   - "Download Authenticator" button

2. **User installs Google Authenticator** (or compatible app):
   - Google Authenticator (iOS/Android)
   - Authy (iOS/Android)
   - Microsoft Authenticator (iOS/Android)
   - Any TOTP-compatible app

3. **User clicks "Generate QR Code"**:
   - QR code appears on screen
   - Secret key shown as backup

4. **User scans QR code** with authenticator app:
   - App shows 6-digit code that changes every 30 seconds

5. **User enters code** and clicks "Verify & Connect":
   - Code validated server-side
   - Session token created
   - User can now connect to VPN
   - Browser auto-closes

### Reconnect After Session Expires

```bash
# Session valid for 24 hours by default (configurable)
# After timeout or disconnect:

sudo wg-quick up ./alice.conf

# Browser opens again to 2FA verification page
# User enters current 6-digit code from authenticator
# Connection established
```

## Management

### View Clients

```bash
# SSH into server
ssh root@<server_ip>

# List all clients
/opt/wireshield/wireshield.sh

# Select: "List Clients"
# Shows all active clients with creation/expiry dates
```

### Check Client 2FA Status

```bash
# Using helper script
/etc/wireshield/2fa/2fa-helper.sh status alice

# Expected output:
# Client: alice
# Status: ✓ Enabled
# Setup Date: 2024-01-15 10:30:45
```

### Disable 2FA for a Client

```bash
# Remove 2FA requirement (not recommended)
sudo /etc/wireshield/2fa/2fa-helper.sh disable alice

# Re-enable 2FA
sudo /etc/wireshield/2fa/2fa-helper.sh enable alice
```

### View Audit Logs

```bash
# Check authentication attempts
sudo sqlite3 /etc/wireshield/2fa/auth.db << 'EOF'
SELECT client_id, action, status, ip_address, timestamp 
FROM audit_log 
ORDER BY timestamp DESC 
LIMIT 20;
EOF

# Example output:
# alice|2FA_SETUP_VERIFY|success|192.168.1.100|2024-01-15 10:35:22
# alice|2FA_VERIFY|success|192.168.1.100|2024-01-15 14:10:15
# bob|2FA_SETUP_START|qr_generated|192.168.1.101|2024-01-15 11:05:33
```

### Clean Expired Sessions

```bash
# Manually remove expired sessions
/etc/wireshield/2fa/2fa-helper.sh cleanup-sessions

# Automatic cleanup happens every 24 hours via cron
```

## Security Best Practices

### SSL/TLS Certificates

**Current**: Self-signed certificates (safe for local connections)

**Production**: Use proper certificates

```bash
# Option 1: Let's Encrypt (Recommended for internet-facing)
sudo certbot certonly --standalone -d vpn.example.com

# Option 2: Your own CA
sudo openssl req -x509 -newkey rsa:4096 \
  -keyout /etc/wireshield/2fa/key.pem \
  -out /etc/wireshield/2fa/cert.pem \
  -days 3650 -nodes \
  -subj "/C=US/ST=State/L=City/O=Company/CN=vpn.example.com"

# Restart service
sudo systemctl restart wireshield-2fa
```

### Database Security

```bash
# Verify permissions (should be 700, readable only by root)
sudo ls -la /etc/wireshield/2fa/auth.db

# Expected:
# -rw------- 1 root root 12288 ... auth.db

# Encrypt sensitive data
sudo chattr +i /etc/wireshield/2fa/auth.db  # Make immutable
```

### Firewall Rules

```bash
# Verify only localhost can access 2FA service
sudo ss -tlnp | grep 8443

# Expected output:
# LISTEN  0  128  127.0.0.1:8443  0.0.0.0:*  users:(("python3",pid=1234,...))

# Should NOT show 0.0.0.0:8443
```

### Rate Limiting (Optional)

```bash
# Install fail2ban to prevent brute-force attacks
sudo apt-get install fail2ban

# Create /etc/fail2ban/jail.local
[2fa-auth]
enabled = true
port = 8443
filter = 2fa-auth
logpath = /var/log/wireshield-2fa.log
maxretry = 5
findtime = 600
bantime = 3600
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u wireshield-2fa -n 50

# Common causes:
# 1. Port 8443 already in use
sudo netstat -tlnp | grep 8443

# 2. Missing Python dependencies
pip3 install -r /etc/wireshield/2fa/requirements.txt

# 3. Database locked
sudo pkill -f "sqlite3.*auth.db"
sudo systemctl restart wireshield-2fa
```

### QR Code Not Appearing

```bash
# Verify qrcode library installed
python3 -c "import qrcode; print('qrcode OK')"

# If missing
pip3 install qrcode pillow

# Restart service
sudo systemctl restart wireshield-2fa
```

### Browser Doesn't Open on Connection

```bash
# Verify firewall allows port 8443
sudo ufw allow 8443
# or
sudo firewall-cmd --add-port=8443/tcp --permanent
sudo firewall-cmd --reload

# Check if service is listening
sudo netstat -tlnp | grep 8443

# Manually access UI
# From server: curl -k https://127.0.0.1:8443/?client_id=alice
```

### Session Token Invalid

```bash
# Delete all sessions (users must re-verify on next connect)
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "DELETE FROM sessions;"

# Or delete specific client's sessions
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "DELETE FROM sessions WHERE client_id='alice';"

systemctl restart wireshield-2fa
```

### Database Corruption

```bash
# Check integrity
sudo sqlite3 /etc/wireshield/2fa/auth.db "PRAGMA integrity_check;"

# Expected: "ok"

# If corrupted, backup and reset
sudo cp /etc/wireshield/2fa/auth.db /etc/wireshield/2fa/auth.db.bak
sudo rm /etc/wireshield/2fa/auth.db
sudo systemctl restart wireshield-2fa
```

## Performance Tuning

### Increase Session Timeout

```bash
# Default: 24 hours

# Edit systemd service
sudo systemctl edit wireshield-2fa

# Add:
# [Service]
# Environment="2FA_SESSION_TIMEOUT=2880"  # 48 hours

sudo systemctl daemon-reload
sudo systemctl restart wireshield-2fa
```

### Change Service Port

```bash
# Edit systemd service
sudo systemctl edit wireshield-2fa

# Change:
# Environment="2FA_PORT=9443"

# Also update firewall
sudo ufw allow 9443
sudo systemctl restart wireshield-2fa
```

### Enable Verbose Logging

```bash
# Edit systemd service
sudo systemctl edit wireshield-2fa

# Change:
# Environment="2FA_LOG_LEVEL=DEBUG"

# View logs
sudo journalctl -u wireshield-2fa -f
```

## Integration with Firewall

### iptables Configuration

The 2FA service integrates with firewall rules to:

1. Block all unauthorized connections initially
2. Allow traffic from authenticated users
3. Clear rules on disconnect/timeout

```bash
# View active firewall rules
sudo iptables -L -n | grep -A 5 "FORWARD"

# Rules are managed automatically by WireShield
```

### Dynamic Firewall Rules (Future)

```bash
# The following will be implemented in next release:
# 1. After successful 2FA, add user's IP to whitelist
# 2. On session expiry, remove from whitelist
# 3. Requires cgroup integration for per-user traffic control
```

## Monitoring

### Health Check Endpoint

```bash
# Check service status
curl -k https://127.0.0.1:8443/health

# Expected:
# {"status":"ok","service":"wireshield-2fa"}
```

### Prometheus Metrics (Future)

```bash
# Will expose metrics like:
# - 2fa_setup_attempts_total
# - 2fa_verification_success_total
# - 2fa_session_duration_seconds
# - database_query_duration_ms
```

## Uninstallation

### Remove 2FA Service

```bash
# Stop service
sudo systemctl stop wireshield-2fa
sudo systemctl disable wireshield-2fa

# Remove systemd unit
sudo rm /etc/systemd/system/wireshield-2fa.service
sudo systemctl daemon-reload

# Remove files
sudo rm -rf /etc/wireshield/2fa

# Uninstall Python packages
sudo pip3 uninstall -y fastapi uvicorn pyotp qrcode sqlalchemy pydantic cryptography

# Verify
sudo systemctl list-units | grep 2fa  # Should be empty
```

### Keep WireGuard

```bash
# WireGuard continues to work without 2FA
# All VPN clients can connect immediately without TOTP verification
# Perfect for internal/trusted networks
```

## Support & Documentation

- **Main Repository**: https://github.com/technonext/wireshield
- **2FA Docs**: [2fa-auth/README.md](./2fa-auth/README.md)
- **Issues**: https://github.com/technonext/wireshield/issues

---

**Last Updated**: January 2024  
**WireShield Version**: 2.2.0+2FA
