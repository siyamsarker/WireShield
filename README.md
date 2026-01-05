<p align="center">
  <img src="assets/logo.svg" alt="WireShield Logo" width="120" height="132">
</p>
<div align="center">

# WireShield

**Secure WireGuard VPN with pre-connection 2FA authentication**

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![WireGuard](https://img.shields.io/badge/WireGuard-Compatible-88171a.svg)](https://www.wireguard.com/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

---
</div>

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [User Guide](#user-guide)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

---

## Overview

WireShield is an automated WireGuard VPN deployment tool with integrated two-factor authentication. It enforces pre-connection 2FA using TOTP (Time-based One-Time Password), ensuring that only authenticated users can access the VPN tunnel.

**How it works:**

1. Client connects to WireGuard VPN
2. Firewall gates all traffic except DNS and the 2FA portal
3. Browser redirects to captive portal for authentication
4. User verifies with Google Authenticator or compatible TOTP app
5. Upon successful verification, client IP is added to ipset allowlist
6. Full internet access is granted through the VPN tunnel

**Session Management Rules:**

1. **Absolute Timeout (24 Hours):**
   - Every authenticated session is valid for a maximum of 24 hours.
   - After 24 hours, you *must* re-authenticate with 2FA, regardless of activity.

2. **Inactivity/Disconnect (1 Hour Grace Period):**
   - If you disconnect the VPN or your device sleeps, your session remains active for **1 Hour**.
   - **Reconnecting < 1 Hour:** No 2FA required. Instant access.
   - **Reconnecting > 1 Hour:** Session expired. 2FA required.

3. **Strict Revocation:**
   - Once a session expires (either due to the 24h limit or >1h inactivity), it is immediately revoked.
   - The firewall blocks all internet access until 2FA is verified again.

---

## Features

### Security
- ✅ **Pre-connection 2FA** using TOTP (Google Authenticator, Authy, etc.)
- ✅ **TLS/SSL encryption** with Let's Encrypt or self-signed certificates
- ✅ **Rate limiting** (30 requests per 60 seconds per IP/endpoint)
- ✅ **Audit logging** for all authentication events
- ✅ **Session monitoring** with WireGuard handshake-aware revocation
- ✅ **ipset-based allowlisting** for verified clients
- ✅ **User activity logging** with configurable retention


### Deployment
- ✅ **One-command installation** via interactive CLI
- ✅ **Cross-platform support** for 9+ Linux distributions
- ✅ **Automatic firewall configuration** (iptables/ip6tables)
- ✅ **Let's Encrypt integration** with auto-renewal
- ✅ **Systemd service** with hardened configuration

### User Experience
- ✅ **QR code setup** for easy authenticator enrollment
- ✅ **Responsive web UI** for authentication
- ✅ **Automatic captive portal** redirection
- ✅ **Client configuration generation** with WireGuard QR codes

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/siyamsarker/WireShield.git
cd WireShield

# Run installer (requires root)
sudo ./wireshield.sh

# Follow interactive prompts for:
# - Public IP or domain
# - WireGuard port (UDP)
# - DNS servers
# - SSL/TLS configuration

# Installation creates first client automatically
# Client config: ~/<client_name>.conf
```

**Time to deploy:** ~5 minutes

---

## System Requirements

### Server Requirements
- **OS:** Linux with systemd
- **Kernel:** Linux 5.6+ (WireGuard built-in) or compatible kernel module
- **Architecture:** x86_64, ARM64
- **RAM:** 512 MB minimum
- **Root access:** Required for installation
- **Network:** Public IP or domain name, open UDP port

### Supported Distributions

| Distribution | Minimum Version | Status |
|--------------|----------------|--------|
| Ubuntu | 18.04 (Bionic) | ✅ Tested |
| Debian | 10 (Buster) | ✅ Tested |
| Fedora | 32 | ✅ Tested |
| CentOS Stream | 8 | ✅ Tested |
| AlmaLinux | 8 | ✅ Tested |
| Rocky Linux | 8 | ✅ Tested |
| Oracle Linux | 8+ | ✅ Supported |
| Arch Linux | Rolling | ✅ Supported |
| Alpine Linux | 3.14+ | ✅ Supported |

### Client Requirements
- WireGuard client (Windows, macOS, Linux, iOS, Android)
- TOTP authenticator app (Google Authenticator, Authy, Microsoft Authenticator, etc.)
- Web browser for 2FA verification

---

## Installation

### Step 1: Install WireShield

```bash
# Clone repository
git clone https://github.com/siyamsarker/WireShield.git
cd WireShield

# Make installer executable
chmod +x wireshield.sh

# Run installer
sudo ./wireshield.sh
```

### Step 2: Interactive Configuration

The installer will prompt for:

1. **Public IP or domain:** Auto-detected or manually specified
2. **WireGuard interface name:** Default `wg0`
3. **WireGuard IPv4/IPv6:** Default `10.66.66.1/24`, `fd42:42:42::1/64`
4. **UDP port:** Random port 49152-65535 or custom
5. **DNS servers:** Default `1.1.1.1`, `1.0.0.1`
6. **SSL/TLS configuration:**
   - Let's Encrypt (requires domain, port 80/443 accessible)
   - Self-signed certificate (for IP addresses)
   - No SSL (development only)

### Step 3: Verify Installation

```bash
# Check WireGuard status
sudo wg show

# Check 2FA service
sudo systemctl status wireshield-2fa.service

# View logs
sudo journalctl -u wireshield-2fa.service -f
```

### Installation Layout

```
/etc/wireguard/
├── wg0.conf              # WireGuard server configuration
└── params                # Installation parameters

/etc/wireshield/2fa/
├── app.py                # FastAPI 2FA service
├── requirements.txt      # Python dependencies
├── auth.db               # SQLite database (users, sessions, audit logs)
├── config.env            # Environment configuration
├── cert.pem              # SSL certificate
├── key.pem               # SSL private key
├── .venv/                # Python virtual environment
├── tests/                # Test suite
└── 2fa-helper.sh         # Management helper script

/etc/systemd/system/
├── wireshield-2fa.service       # 2FA service
└── wireshield-2fa-renew.timer   # Let's Encrypt renewal timer (if applicable)
```

---

## Architecture

### Network Flow

```
┌─────────────┐
│   Client    │
│ (WireGuard) │
└──────┬──────┘
       │ Connect
       ▼
┌─────────────────────────────────────────────┐
│         WireGuard Server (wg0)              │
│  ┌───────────────────────────────────────┐  │
│  │   iptables/ip6tables Firewall         │  │
│  │                                        │  │
│  │   1. Check ipset allowlist             │  │
│  │      ws_2fa_allowed_v4/v6              │  │
│  │                                        │  │
│  │   2. If NOT in allowlist:              │  │
│  │      └─> Jump to WS_2FA_PORTAL chain   │  │
│  │          ├─ Allow DNS (53/tcp,udp)     │  │
│  │          ├─ Allow portal (80,443/tcp)  │  │
│  │          └─ DROP all else              │  │
│  │                                        │  │
│  │   3. If in allowlist:                  │  │
│  │      └─> ACCEPT & MASQUERADE           │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────┐
│      2FA Service (FastAPI + Python)         │
│  ┌───────────────────────────────────────┐  │
│  │  Captive Portal (HTTPS)                │  │
│  │  ├─ QR code generation                 │  │
│  │  ├─ TOTP verification                  │  │
│  │  └─ Session management                 │  │
│  └───────────────────────────────────────┘  │
│  ┌───────────────────────────────────────┐  │
│  │  Background Monitors                   │  │
│  │  ├─ WireGuard handshake monitor        │  │
│  │  ├─ ipset sync daemon                  │  │
│  │  └─ HTTP→HTTPS redirector              │  │
│  └───────────────────────────────────────┘  │
│  ┌───────────────────────────────────────┐  │
│  │  SQLite Database                       │  │
│  │  ├─ users (client_id, TOTP secrets)    │  │
│  │  ├─ sessions (tokens, expiry)          │  │
│  │  └─ audit_log (security events)        │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

### Firewall Rules

**IPv4 chains:**
```bash
# ipset allowlists
ipset create ws_2fa_allowed_v4 hash:ip family inet

# Portal chain (before verification)
iptables -N WS_2FA_PORTAL
iptables -A WS_2FA_PORTAL -p tcp --dport 53 -j ACCEPT
iptables -A WS_2FA_PORTAL -p udp --dport 53 -j ACCEPT
iptables -A WS_2FA_PORTAL -d <portal_ip> -p tcp --dport 443 -j ACCEPT
iptables -A WS_2FA_PORTAL -d <portal_ip> -p tcp --dport 80 -j ACCEPT
iptables -A WS_2FA_PORTAL -j DROP

# Forward chain (order matters!)
iptables -A FORWARD -i wg0 -m set --match-set ws_2fa_allowed_v4 src -j ACCEPT
iptables -A FORWARD -i wg0 -j WS_2FA_PORTAL
```

**IPv6 chains:** Identical structure with `ip6tables` and `ws_2fa_allowed_v6`

### Session Monitor

The background monitor polls WireGuard handshakes every 3 seconds:

1. Reads `wg show <interface> dump` to get handshake timestamps
2. Calculates age for each client IP
3. Applies dual-threshold logic:
   - **Idle threshold (3600s):** Client active if any handshake ≤ 3600s
   - **Disconnect grace (3600s):** Client expired if all handshakes > 3600s
4. Removes stale sessions from database
5. Syncs ipset allowlists (removes IPs without active sessions)

---

## Configuration

### Primary Config File

**Location:** `/etc/wireshield/2fa/config.env`

**Core settings:**

```bash
# Database
WS_2FA_DB_PATH=/etc/wireshield/2fa/auth.db

# Network
WS_2FA_HOST=0.0.0.0
WS_2FA_PORT=443
WS_2FA_HTTP_PORT=80

# Logging
WS_2FA_LOG_LEVEL=INFO

# Rate Limiting
WS_2FA_RATE_LIMIT_MAX_REQUESTS=30
WS_2FA_RATE_LIMIT_WINDOW=60

# Session Management
WS_2FA_SESSION_TIMEOUT=1440                    # 24 hours (in minutes)
WS_2FA_SESSION_IDLE_TIMEOUT=3600               # 1 hour (in seconds)
WS_2FA_DISCONNECT_GRACE_SECONDS=3600           # 1 hour (in seconds)

# SSL/TLS
WS_2FA_SSL_ENABLED=true
WS_2FA_SSL_TYPE=letsencrypt                    # or 'self-signed'
WS_2FA_DOMAIN=vpn.example.com                  # for Let's Encrypt
WS_HOSTNAME_2FA=127.0.0.1                      # for self-signed

# WireGuard
WS_WG_INTERFACE=wg0
WS_WIREGUARD_PARAMS=/etc/wireguard/params

# Security (must be set for production)
WS_2FA_SECRET_KEY=<generate-random-key>
```

### Environment Variables

All `config.env` settings can be overridden via environment variables. The service uses a priority system:

1. `WS_2FA_*` prefixed variables
2. `2FA_*` prefixed variables (legacy)
3. Default values

### Tuning Session Behavior

**Scenario 1: Increase idle tolerance to 2 hours**
```bash
# Edit /etc/wireshield/2fa/config.env
WS_2FA_SESSION_IDLE_TIMEOUT=7200

# Restart service
sudo systemctl restart wireshield-2fa.service
```

**Scenario 2: Faster disconnect detection (10 seconds)**
```bash
WS_2FA_DISCONNECT_GRACE_SECONDS=10
sudo systemctl restart wireshield-2fa.service
```

**Scenario 3: Extend session validity to 7 days**
```bash
WS_2FA_SESSION_TIMEOUT=10080  # 7 days in minutes
sudo systemctl restart wireshield-2fa.service
```

---

## User Guide

### For VPN Users

#### Initial Setup

1. **Receive your WireGuard configuration**
   - Download `<your-name>.conf` from admin
   - Import into WireGuard client (desktop/mobile)

2. **Connect to VPN**
   - Click "Connect" or "Activate" in WireGuard app
   - Wait for tunnel to establish

3. **Complete 2FA enrollment**
   - Browser automatically opens to `https://<vpn-domain>/?client_id=<your-name>`
   - Click "Setup Authenticator"
   - Scan QR code with Google Authenticator, Authy, or compatible app
   - Enter 6-digit verification code
   - Save backup codes (if provided)

4. **Verification success**
   - You'll see "Verification Successful" page
   - Full internet access is now active through VPN
   - Session valid for 24 hours

#### Reconnecting

1. **After disconnection or session expiry:**
   - Connect VPN again
   - Browser opens to 2FA page
   - Enter current 6-digit code from authenticator app
   - No need to re-scan QR code

2. **Authenticator apps:**
   - Google Authenticator (iOS/Android)
   - Authy (iOS/Android/Desktop)
   - Microsoft Authenticator (iOS/Android)
   - 1Password, Bitwarden, LastPass Authenticator
   - Any TOTP-compatible app

#### Troubleshooting

**"Cannot reach 2FA portal"**
- Ensure VPN is connected (check WireGuard status)
- Verify DNS is working: `nslookup google.com`
- Try accessing portal manually: `https://<vpn-ip-or-domain>`

**"Invalid code" error**
- Ensure device clock is synchronized (TOTP relies on time)
- Wait for next code rotation (codes change every 30 seconds)
- Verify you're using the correct authenticator entry

**"Session expired immediately"**
- Contact admin to check `WS_2FA_SESSION_IDLE_TIMEOUT` setting
- Ensure WireGuard `PersistentKeepalive` is set (usually 25 seconds)

---

## Operations

### Service Management

```bash
# Start/stop/restart 2FA service
sudo systemctl start wireshield-2fa.service
sudo systemctl stop wireshield-2fa.service
sudo systemctl restart wireshield-2fa.service

# Enable/disable auto-start
sudo systemctl enable wireshield-2fa.service
sudo systemctl disable wireshield-2fa.service

# Check status
sudo systemctl status wireshield-2fa.service

# View logs (real-time)
sudo journalctl -u wireshield-2fa.service -f

# View logs (last 100 lines)
sudo journalctl -u wireshield-2fa.service -n 100
```

### WireGuard Management

```bash
# Start/stop WireGuard
sudo systemctl start wg-quick@wg0
sudo systemctl stop wg-quick@wg0

# View active peers
sudo wg show

# View peer handshakes and traffic
sudo wg show wg0 dump

# Reload configuration
sudo systemctl restart wg-quick@wg0
```

### Client Management

#### Add New Client

```bash
# Via interactive menu
sudo ./wireshield.sh
# Select option: "Add a new client"
# Enter client name: alice
# Config saved to ~/alice.conf

# Send alice.conf to user securely
```

#### List Clients

```bash
# Via interactive menu
sudo ./wireshield.sh
# Select option: "List existing clients"

# Or manually check WireGuard config
sudo grep -A 3 "Peer" /etc/wireguard/wg0.conf
```

#### Revoke Client

```bash
# Via interactive menu
sudo ./wireshield.sh
# Select option: "Revoke an existing client"
# Enter client name to remove

# This removes:
# - WireGuard peer configuration
# - 2FA database entries
# - Active sessions
# - ipset allowlist entries
```

### 2FA Management

#### View All Users

```bash
# Via SQLite
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT client_id, enabled, created_at, wg_ipv4, wg_ipv6 FROM users;"
```

#### View Active Sessions

```bash
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT s.client_id, s.device_ip, s.expires_at, s.created_at 
   FROM sessions s 
   WHERE s.expires_at > datetime('now') 
   ORDER BY s.created_at DESC;"
```

#### View Audit Logs

```bash
# Last 20 authentication events
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT timestamp, client_id, action, status, ip_address 
   FROM audit_log 
   ORDER BY timestamp DESC 
   LIMIT 20;"

# Failed authentication attempts
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT * FROM audit_log 
   WHERE status LIKE '%invalid%' OR status LIKE '%failed%' 
   ORDER BY timestamp DESC 
   LIMIT 50;"
```

#### Manually Revoke Session

```bash
# Remove specific client from allowlist
sudo ipset del ws_2fa_allowed_v4 10.66.66.2
sudo ipset del ws_2fa_allowed_v6 fd42:42:42::2

# Delete session from database
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "DELETE FROM sessions WHERE client_id='alice';"
```

### User Activity Logging

WireShield includes a built-in activity logger that tracks connection history for auditing purposes.

#### Enable/Disable Logging

```bash
# Via interactive menu
sudo ./wireshield.sh
# Select option: "User Activity Logs" -> "Enable/Disable Activity Logging"
```
When enabled, the system logs every **NEW** connection made by authenticated clients from the WireGuard interface.

#### View Activity Logs

```bash
# Via interactive menu
sudo ./wireshield.sh
# Select option: "User Activity Logs" -> "View User Logs"
```
The unified log viewer combines:
- Real-time logs from the system journal
- Archived historical logs

**Output format:**
```text
TIMESTAMP                 | USER            | SOURCE          -> DESTINATION (PROTO)
2023-12-30T10:00:00+0000 | alice           | 10.66.66.2      -> 8.8.8.8:53 (UDP)
```

#### Configure Retention

By default, logs are kept for **15 days**. You can adjust this period:

```bash
# Via interactive menu
sudo ./wireshield.sh
# Select option: "User Activity Logs" -> "Configure Retention Period"
```

A daily cron job (`/usr/local/bin/wireshield-archive-logs`) automatically:
1. Archives yesterday's logs to `/var/log/wireshield/archives/`
2. Deletes archives older than the configured retention period


### SSL/TLS Management

#### Let's Encrypt

```bash
# Check renewal timer status
sudo systemctl status wireshield-2fa-renew.timer

# Check renewal service logs
sudo journalctl -u wireshield-2fa-renew.service

# Manually renew certificates
sudo certbot renew --quiet --post-hook "systemctl reload wireshield-2fa"

# Test renewal (dry run)
sudo certbot renew --dry-run

# View certificate details
sudo certbot certificates
```

#### Self-Signed Certificates

```bash
# Check certificate expiry
sudo openssl x509 -in /etc/wireshield/2fa/cert.pem -noout -dates

# Regenerate certificate (365-day validity)
sudo openssl req -x509 -newkey rsa:4096 \
  -keyout /etc/wireshield/2fa/key.pem \
  -out /etc/wireshield/2fa/cert.pem \
  -days 365 -nodes \
  -subj "/CN=<your-ip-or-hostname>"

# Restart service
sudo systemctl restart wireshield-2fa.service
```

### Firewall Inspection

```bash
# View ipset allowlists
sudo ipset list ws_2fa_allowed_v4
sudo ipset list ws_2fa_allowed_v6

# View iptables rules (IPv4)
sudo iptables -L WS_2FA_PORTAL -v -n
sudo iptables -L FORWARD -v -n | grep -A 2 wg0
sudo iptables -t nat -L PREROUTING -v -n

# View ip6tables rules (IPv6)
sudo ip6tables -L WS_2FA_PORTAL6 -v -n
sudo ip6tables -L FORWARD -v -n | grep -A 2 wg0
```

### Monitoring

```bash
# Real-time 2FA service logs
sudo journalctl -u wireshield-2fa.service -f

# Monitor WireGuard handshakes
watch -n 2 'sudo wg show'

# Monitor ipset changes
watch -n 5 'sudo ipset list ws_2fa_allowed_v4 | grep -v "^Name:"'

# Check service resource usage
sudo systemctl status wireshield-2fa.service | grep -E "Memory|CPU"
```

---

## Troubleshooting

### Common Issues

#### 1. No Internet After 2FA Verification

**Symptoms:**
- 2FA verification succeeds
- Browser shows "Verification Successful"
- Cannot browse websites or ping external IPs

**Diagnosis:**
```bash
# Check if client IP is in allowlist
sudo ipset list ws_2fa_allowed_v4 | grep <client-wg-ip>

# Check WireGuard handshakes
sudo wg show | grep -A 5 <client-public-key>

# Check recent 2FA logs
sudo journalctl -u wireshield-2fa.service -n 50 | grep -i session
```

**Solutions:**

1. **Verify firewall rule order:**
   ```bash
   # Allowlist rule MUST come before portal rule
   sudo iptables -L FORWARD -n --line-numbers | grep wg0
   # Line with "match-set ws_2fa_allowed_v4" should be BEFORE "WS_2FA_PORTAL"
   ```

2. **Manually add to allowlist (temporary fix):**
   ```bash
   sudo ipset add ws_2fa_allowed_v4 <client-wg-ip> -exist
   ```

3. **Check NAT/masquerading:**
   ```bash
   sudo iptables -t nat -L POSTROUTING -n -v
   # Should see MASQUERADE rule for public interface
   ```

#### 2. Portal Not Reachable

**Symptoms:**
- Browser cannot load `https://<vpn-domain>`
- Connection timeout or "server not responding"

**Diagnosis:**
```bash
# Check 2FA service status
sudo systemctl status wireshield-2fa.service

# Check if ports are listening
sudo ss -tlnp | grep -E ':80|:443'

# Check firewall INPUT rules
sudo iptables -L INPUT -n | grep -E '80|443'
```

**Solutions:**

1. **Restart 2FA service:**
   ```bash
   sudo systemctl restart wireshield-2fa.service
   ```

2. **Verify SSL certificate exists:**
   ```bash
   sudo ls -lh /etc/wireshield/2fa/cert.pem /etc/wireshield/2fa/key.pem
   ```

3. **Check DNAT rules (for clients behind VPN):**
   ```bash
   sudo iptables -t nat -L PREROUTING -n -v | grep -E '80|443'
   ```

#### 3. Sessions Expiring Too Quickly

**Symptoms:**
- Need to re-verify 2FA every few minutes
- Session expires despite active connection

**Diagnosis:**
```bash
# Check current timeout settings
grep -E "IDLE_TIMEOUT|DISCONNECT_GRACE" /etc/wireshield/2fa/config.env

# Check monitor logs
sudo journalctl -u wireshield-2fa.service | grep "SESSION_MONITOR"

# Check WireGuard handshake frequency
sudo wg show wg0 | grep "latest handshake"
```

**Solutions:**

1. **Increase idle timeout:**
   ```bash
   sudo nano /etc/wireshield/2fa/config.env
   # Change: WS_2FA_SESSION_IDLE_TIMEOUT=7200  # 2 hours
   sudo systemctl restart wireshield-2fa.service
   ```

2. **Enable PersistentKeepalive on client:**
   ```conf
   # In client .conf file
   [Peer]
   PersistentKeepalive = 25
   ```

3. **Adjust disconnect grace period:**
   ```bash
   # In /etc/wireshield/2fa/config.env
   WS_2FA_DISCONNECT_GRACE_SECONDS=60  # More lenient
   sudo systemctl restart wireshield-2fa.service
   ```

#### 4. Let's Encrypt Renewal Failures

**Symptoms:**
- Certificate expiring soon (< 30 days)
- Renewal timer shows failed status

**Diagnosis:**
```bash
# Check renewal service logs
sudo journalctl -u wireshield-2fa-renew.service

# Test renewal
sudo certbot renew --dry-run
```

**Solutions:**

1. **Ensure ports 80/443 are accessible:**
   ```bash
   # Temporarily stop 2FA service
   sudo systemctl stop wireshield-2fa.service
   
   # Test renewal
   sudo certbot renew --force-renewal
   
   # Restart service
   sudo systemctl start wireshield-2fa.service
   ```

2. **Check DNS resolution:**
   ```bash
   nslookup <your-domain>
   # Should resolve to your server IP
   ```

3. **Manual renewal:**
   ```bash
   sudo certbot certonly --standalone -d <your-domain> --force-renewal
   sudo systemctl restart wireshield-2fa.service
   ```

#### 5. Database Corruption

**Symptoms:**
- 2FA service won't start
- Errors mentioning SQLite in logs

**Diagnosis:**
```bash
# Check database integrity
sudo sqlite3 /etc/wireshield/2fa/auth.db "PRAGMA integrity_check;"
```

**Solutions:**

1. **Backup and recreate database:**
   ```bash
   # Backup
   sudo cp /etc/wireshield/2fa/auth.db /etc/wireshield/2fa/auth.db.backup
   
   # Restart service (will recreate tables)
   sudo systemctl restart wireshield-2fa.service
   ```

2. **Restore from backup (if exists):**
   ```bash
   sudo systemctl stop wireshield-2fa.service
   sudo cp /etc/wireshield/2fa/auth.db.backup /etc/wireshield/2fa/auth.db
   sudo systemctl start wireshield-2fa.service
   ```

### Performance Tuning

#### High Connection Count (100+ clients)

```bash
# Increase file descriptor limits
sudo nano /etc/systemd/system/wireshield-2fa.service

# Add under [Service]:
LimitNOFILE=65535

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart wireshield-2fa.service
```

#### Reduce Monitor CPU Usage

```bash
# Increase polling interval (edit app.py)
# Change poll_interval from 3 to 5 or 10 seconds
# Trade-off: slower disconnect detection
```

---

## Development

### Local Development Setup

```bash
# Clone repository
git clone https://github.com/siyamsarker/WireShield.git
cd WireShield/2fa-auth

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run development server
python app.py

# Service runs on localhost:443 (requires SSL cert/key or disable SSL in code)
```

### Running Tests

```bash
cd 2fa-auth
source .venv/bin/activate
pytest -v
```

### Project Structure

```
WireShield/
├── wireshield.sh           # Main installer and manager CLI
├── LICENSE                 # GPLv3 license
├── README.md               # This file
└── 2fa-auth/
    ├── app.py              # FastAPI 2FA service
    ├── requirements.txt    # Python dependencies
    ├── generate-certs.sh   # Certificate generation helper
    ├── 2fa-helper.sh       # Management helper scripts
    └── tests/
        ├── test_rate_limit.py       # Rate limiter tests
        └── test-integration.sh      # Integration test suite
```

### Key Components

**wireshield.sh**
- Interactive installation wizard
- WireGuard configuration generator
- Firewall rules setup (iptables/ip6tables)
- Client management (add/list/revoke)
- SSL/TLS provisioning (Let's Encrypt or self-signed)

**app.py**
- FastAPI web service (HTTPS server)
- TOTP verification endpoints
- Session management and token generation
- SQLite database operations
- WireGuard handshake monitor (background thread)
- ipset synchronization daemon
- HTTP→HTTPS redirector for captive portal

### API Endpoints

**UI Routes:**
- `GET /` - Main 2FA setup/verification page
- `GET /success` - Post-verification success page
- `GET /health` - Health check endpoint

**API Routes:**
- `POST /api/setup-start` - Generate TOTP secret and QR code
- `POST /api/setup-verify` - Verify initial TOTP code during setup
- `POST /api/verify` - Verify TOTP code for existing users
- `POST /api/validate-session` - Check session token validity

### Database Schema

**users table:**
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT UNIQUE NOT NULL,
    totp_secret TEXT,
    backup_codes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    enabled BOOLEAN DEFAULT 1,
    wg_ipv4 TEXT,
    wg_ipv6 TEXT
);
```

**sessions table:**
```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    device_ip TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES users(client_id)
);
```

**audit_log table:**
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT,
    action TEXT NOT NULL,
    status TEXT,
    ip_address TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Development guidelines:**
- Follow existing code style
- Add tests for new features
- Update documentation as needed
- Test on multiple distributions before submitting

---

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3).

See [LICENSE](LICENSE) file for full terms.

**Key permissions:**
- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Private use

**Conditions:**
- Source code must be disclosed
- Modified versions must use same license
- Changes must be documented

---

## Credits

**Author:** Siyam Sarker  
**Repository:** [https://github.com/siyamsarker/WireShield](https://github.com/siyamsarker/WireShield)  
**License:** GPLv3

**Built with:**
- [WireGuard](https://www.wireguard.com/) - Fast, modern VPN protocol
- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework for Python
- [pyotp](https://github.com/pyauth/pyotp) - TOTP implementation
- [qrcode](https://github.com/lincolnloop/python-qrcode) - QR code generation
- [SQLite](https://www.sqlite.org/) - Embedded database

---

## Support

For issues, questions, or contributions:

- **GitHub Issues:** [https://github.com/siyamsarker/WireShield/issues](https://github.com/siyamsarker/WireShield/issues)
- **Documentation:** This README
- **Security Issues:** Please report privately via GitHub Security Advisories

---

**Last Updated:** December 2025
