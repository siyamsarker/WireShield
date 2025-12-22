<div align="center">

# WireShield

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![WireGuard](https://img.shields.io/badge/WireGuard-Compatible-88171a.svg)](https://www.wireguard.com/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://www.kernel.org/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

**Secure, production-ready WireGuard VPN manager with pre-connection 2FA and SSL/TLS support**

</div>

> *Deploy a complete VPN infrastructure with Google Authenticator authentication in minutes — CLI-driven, battle-tested, zero manual configuration*

---

## 📑 Quick Navigation

| Section | Purpose | Time |
|---------|---------|------|
| **[🚀 Getting Started](#-getting-started)** | Fresh installation guide | 5 min |
| **[👥 User Guide](#-user-guide)** | How to connect & use VPN | 10 min |
| **[🔧 DevOps Guide](#-devops-guide)** | Deploy, configure, manage | 20 min |
| **[💻 Contributor Guide](#-contributor-guide)** | Architecture & development | 15 min |
| **[❓ FAQ & Troubleshooting](#-faq--troubleshooting)** | Common questions & fixes | - |

---

**⚡ Quick Start (60 seconds):**
```bash
git clone https://github.com/siyamsarker/WireShield.git
cd WireShield
sudo ./wireshield.sh
# Follow prompts → Done!
```

---

## ✨ Overview

WireShield is a **production-grade WireGuard VPN manager** combining simplicity with enterprise-grade security:

<table>
<tr>
  <td width="50%">
    <h3>🔐 Security Features</h3>
    • Pre-connection 2FA<br/>
    • Rate limiting<br/>
    • Audit logging<br/>
    • TLS/SSL encryption
  </td>
  <td width="50%">
    <h3>🚀 Easy Deployment</h3>
    • One-command setup<br/>
    • Auto-configuration<br/>
    • Multi-distro support<br/>
    • Zero manual config
  </td>
</tr>
<tr>
  <td width="50%">
    <h3>📱 User-Friendly</h3>
    • QR code setup<br/>
    • Responsive UI<br/>
    • Clear audit trails<br/>
    • 24h sessions
  </td>
  <td width="50%">
    <h3>🔄 Auto-Renewal</h3>
    • Let's Encrypt support<br/>
    • Self-signed certs<br/>
    • Automatic updates<br/>
    • Systemd hardened
  </td>
</tr>
</table>

### Key Statistics

| Metric | Value | Status |
|--------|-------|--------|
| **Total Code** | 7,129 lines | ✅ Production |
| **Python (FastAPI)** | 1,500+ lines | ✅ Tested |
| **Bash (CLI)** | 1,733 lines | ✅ Stable |
| **Supported Distros** | 9+ distributions | ✅ Verified |
| **API Endpoints** | 5 core endpoints | ✅ Documented |
| **Database Tables** | 3 (users, sessions, audit_log) | ✅ Optimized |
| **Setup Time** | ~5 minutes | ⚡ Fast |
| **2FA Verification** | <1 second | ⚡ Quick |
| **Rate Limiting** | Per-IP/endpoint | ✅ Built-in |
| **Auto-Renewal** | Let's Encrypt support | ✅ Active |

---

## 🚀 Getting Started

### Prerequisites

- **Linux server** with systemd (Ubuntu 18.04+, Debian 10+, Fedora 32+, CentOS Stream 8+, etc.)
- **Root access** (via `sudo` or direct root login)
- **Internet connection** for package installation
- **Public IP or domain** (for VPN endpoint)
- **UDP port** open in firewall (1-65535, auto-selected if needed)

### Supported Distributions

| Distribution | Min Version | Status |
|---|---|---|
| 🐧 Ubuntu | 18.04 (Bionic) | ✅ Full support |
| 🍥 Debian | 10 (Buster) | ✅ Full support |
| 🎩 Fedora | 32 | ✅ Full support |
| 🌊 CentOS Stream | 8 | ✅ Full support |
| 🐴 AlmaLinux | 8 | ✅ Full support |
| ⛰️ Rocky Linux | 8 | ✅ Full support |
| 🔴 Oracle Linux | Latest | ✅ Full support |
| 🎯 Arch Linux | Latest | ✅ Full support |
| 🏔️ Alpine Linux | Latest | ✅ Full support |

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/siyamsarker/WireShield.git
cd WireShield

# 2. Run the installer
sudo ./wireshield.sh

# 3. Follow interactive prompts:
#    • Public IP or domain
#    • UDP port (optional, auto-generated if skipped)
#    • DNS servers (default: Google + Cloudflare)
#    • SSL configuration (Let's Encrypt, self-signed, or none)
#
# 4. System auto-installs:
#    ✓ WireGuard
#    ✓ 2FA service (Python + FastAPI)
#    ✓ SSL certificates
#    ✓ Firewall rules
#    ✓ First client with 2FA enabled

echo "✅ Installation complete! Check /etc/wireguard/ for configs"
```

### What Gets Installed

```
/etc/wireguard/
├── wg0.conf                        # Server configuration
└── params                          # Installation parameters

/etc/wireshield/2fa/
├── auth.db                         # SQLite database (users, sessions, audit)
├── config.env                      # SSL/TLS and rate limiting configuration
├── .venv/                          # Isolated Python environment with pinned dependencies
├── certs/
│   ├── cert.pem                    # SSL certificate
│   ├── key.pem                     # SSL private key
│   └── fullchain.pem               # Full chain (Let's Encrypt only)
├── app.py                          # FastAPI 2FA server with rate limiting
├── requirements.txt                # Pinned Python dependencies
├── tests/                          # Test suite (rate limiting, etc.)
├── 2fa-helper.sh                   # Management CLI
└── wireshield-2fa.service          # Systemd service

/etc/systemd/system/
├── wireshield-2fa.service          # 2FA service
└── wireshield-2fa-renewal.timer    # Auto-renewal timer (LE only)

~/<client_name>.conf                # Client configurations (generated)
```

Firewall constructs (iptables path)
```
ws_2fa_allowed_v4   # ipset allowlist for IPv4 client WG IPs
ws_2fa_allowed_v6   # ipset allowlist for IPv6 client WG IPs
WS_2FA_FILTER       # iptables chain: default DROP for WG src unless in allowlist
WS_2FA_FILTER6      # ip6tables chain: default DROP for WG src unless in allowlist
```

---

## 👥 User Guide

### How 2FA Works

When a user connects to your VPN:

```
1. User loads WireGuard client config
2. User clicks "Connect" in WireGuard app
3. VPN connection initiates
4. Firewall intercepts → redirects browser to:
   https://your-domain:8443/?client_id=user123
5. User sees QR code
   └─ Scans with Google Authenticator app
   └─ Gets 6-digit code
6. User enters code in web UI
7. Session token issued (valid 24 hours)
8. ✅ VPN access granted
9. After 24 hours (session expires):
   └─ User must re-verify with 2FA to reconnect
```

### Getting Your First Client

Your system automatically creates the first client during installation. Download config from server:

```bash
# On the VPN server
cd ~
ls -la *.conf                       # Shows your first client config

# On your local machine
# Download the .conf file
# Add to WireGuard app
# Connect → follow 2FA web UI
```

### Managing Your Authenticator App

**Compatible apps:**
- ✅ **Google Authenticator** (iOS/Android) — Recommended
- ✅ **Authy** (iOS/Android) — Backup codes included
- ✅ **Microsoft Authenticator** (iOS/Android)
- ✅ **LastPass Authenticator**
- ✅ Any TOTP-compatible app (Bitwarden, 1Password, etc.)

**Setup flow:**
1. Connect to VPN → browser redirects to https://your-domain:8443/?client_id=X
2. Click "Setup Authenticator"
3. Scan QR code with your app (or copy-paste secret manually)
4. Enter 6-digit code to verify
5. Save backup secret code (required for recovery)

### Reconnecting After Session Expires

Your 24-hour session token automatically expires. To reconnect:

```
1. Disconnect from VPN
2. Reconnect (WireGuard initiates new connection)
3. Browser redirects to 2FA UI again
4. Enter new 6-digit code from your authenticator app
5. ✅ Re-connected with new session
```

**No need to:**
- ❌ Re-scan QR code
- ❌ Reset authenticator app
- ❌ Remember passwords
- ✅ Just grab the latest 6-digit code

---

## 🔧 DevOps Guide

### Deployment

#### Option 1: Fresh Installation (Recommended)

```bash
# SSH to your Linux server
ssh root@your-server.com

# Clone and run
git clone https://github.com/siyamsarker/WireShield.git
cd WireShield
sudo ./wireshield.sh

# Follow prompts → done!
```

#### Option 2: Interactive Configuration

During `sudo ./wireshield.sh`, you'll be asked:

```
=== WireShield Installation ===

1. Public IP address? [auto-detected] 1.2.3.4
2. UDP port for VPN? [random] 51820
3. DNS servers? [8.8.8.8, 1.1.1.1] → press enter
4. Configure SSL/TLS? (y/n) y

=== SSL/TLS Configuration ===
Choose certificate type:
  1) Let's Encrypt (domain, auto-renewal, trusted)
  2) Self-signed (IP address, manual renewal)
  3) None (development/localhost only)
  
Enter choice (1 or 2): 1
Enter domain name: vpn.example.com
[Auto-setup with certbot...]

✅ Installation complete!
```

### SSL/TLS Configuration

Three options available:

#### 1. Let's Encrypt (Production Recommended ⭐)

```bash
# Best for: Production with domain name
# Setup: sudo ./wireshield.sh → Choose option 1
# Features:
#   ✓ Trusted certificates (no browser warnings)
#   ✓ Auto-renewal via systemd timer (daily checks)
#   ✓ 90-day certificate validity
#   ✓ Works on Ubuntu, Debian, Fedora, etc.
# Requirements:
#   • Valid domain name (e.g., vpn.example.com)
#   • DNS pointing to server IP
#   • Port 80/443 accessible for validation

# Check renewal status
sudo systemctl status wireshield-2fa-renewal.timer
sudo journalctl -u wireshield-2fa-renewal.service -f
```

#### 2. Self-Signed (For IPs)

```bash
# Best for: IP addresses, internal networks
# Setup: sudo ./wireshield.sh → Choose option 2
# Features:
#   ✓ Works with any IP address
#   ✓ Works with any hostname
#   ✓ No DNS required
#   ✓ 365-day certificate validity
# Tradeoff:
#   • Browser shows security warning (expected)
#   • Manual renewal required after 1 year

# Check certificate
sudo openssl x509 -in /etc/wireshield/2fa/certs/cert.pem -text -noout
```

#### 3. No SSL (Development Only)

```bash
# Best for: Development/testing on localhost
# Not recommended for production
# Browser accesses over HTTP (not HTTPS)
```

### Client Management

#### Create New Client

```bash
# Add new client
sudo ./wireshield.sh
# Follow menu → Option 2 (Add Client)
# Enter client name: alice
# 2FA automatically enabled for new clients

# Client config created at: ~/alice.conf
```

#### Enable/Disable 2FA

```bash
# Enable 2FA for client
sudo /etc/wireshield/2fa/2fa-helper.sh enable alice

# Disable 2FA (not recommended)
sudo /etc/wireshield/2fa/2fa-helper.sh disable alice

# Check 2FA status
sudo /etc/wireshield/2fa/2fa-helper.sh status alice
```

#### View All Users

```bash
# List all users in database
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT username, enabled, created_at FROM users;"

# View authentication audit log
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 20;"
```

### Audit Logs Management

WireShield maintains comprehensive audit logs for security and compliance. View logs through the CLI menu or directly via the 2FA helper script.

#### View Audit Logs via CLI Menu

**Interactive menu option (easiest):**
```bash
sudo ./wireshield.sh
# Select Option 8: View Audit Logs
# Then choose:
#   1) View all audit logs (last 100)
#   2) View logs for specific user
#   3) View audit statistics
#   4) Export audit logs to CSV
```

#### View Audit Logs via Helper Script

**View all audit logs (last 100 entries):**
```bash
sudo /etc/wireshield/2fa/2fa-helper.sh audit-logs
```

Output example:
```
=== WireShield Audit Logs (All Users) ===

Timestamp            Client         Action               Status          IP Address
========================================================================================
2024-01-20 14:32:10  alice          2FA_SETUP_START      qr_generated    192.168.1.100
2024-01-20 14:32:25  alice          2FA_SETUP_VERIFY     success         192.168.1.100
2024-01-20 15:10:45  bob            2FA_VERIFY           success         192.168.1.101
2024-01-20 15:11:02  bob            SESSION_VALIDATE     valid           192.168.1.101
2024-01-20 15:15:30  alice          2FA_VERIFY           invalid_code    192.168.1.100
2024-01-20 15:15:45  alice          2FA_VERIFY           success         192.168.1.100

Total logs shown: 6
```

**View audit logs for a specific user:**
```bash
sudo /etc/wireshield/2fa/2fa-helper.sh audit-logs-user alice
```

Output example:
```
=== WireShield Audit Logs for User: alice ===

Timestamp            Action               Status          IP Address
====================================================================
2024-01-20 14:32:10  2FA_SETUP_START      qr_generated    192.168.1.100
2024-01-20 14:32:25  2FA_SETUP_VERIFY     success         192.168.1.100
2024-01-20 15:15:30  2FA_VERIFY           invalid_code    192.168.1.100
2024-01-20 15:15:45  2FA_VERIFY           success         192.168.1.100

Total logs for alice: 4
```

**View audit statistics:**
```bash
sudo /etc/wireshield/2fa/2fa-helper.sh audit-stats
```

Output example:
```
=== Audit Log Statistics ===

Total Audit Logs: 150
Unique Clients: 12
Successful 2FA Verifications: 142
Failed Attempts: 8

Actions Summary:
  2FA_VERIFY: 95
  UI_ACCESS: 35
  2FA_SETUP_START: 12
  2FA_SETUP_VERIFY: 8
```

**Export audit logs to CSV:**
```bash
# Export to default location
sudo /etc/wireshield/2fa/2fa-helper.sh export-audit

# Export to custom location
sudo /etc/wireshield/2fa/2fa-helper.sh export-audit /tmp/audit-$(date +%Y%m%d).csv

# Import CSV to spreadsheet or analysis tool
scp user@server:/tmp/audit-*.csv ./
# Open in Excel, Google Sheets, or your analysis tool
```

CSV format example:
```
Timestamp,Client ID,Action,Status,IP Address
2024-01-20 14:32:10,alice,2FA_SETUP_START,qr_generated,192.168.1.100
2024-01-20 14:32:25,alice,2FA_SETUP_VERIFY,success,192.168.1.100
2024-01-20 15:15:30,alice,2FA_VERIFY,invalid_code,192.168.1.100
2024-01-20 15:15:45,alice,2FA_VERIFY,success,192.168.1.100
```

#### Audit Log Actions Reference

| Action | When It Occurs | Common Status Values |
|--------|---|---|
| `UI_ACCESS` | User loads 2FA web page | `page_loaded` |
| `2FA_SETUP_START` | User starts 2FA setup | `qr_generated`, `error_*` |
| `2FA_SETUP_VERIFY` | User enters setup code | `success`, `invalid_code`, `user_not_found` |
| `2FA_VERIFY` | User enters authentication code | `success`, `invalid_code`, `user_not_initialized` |
| `SESSION_VALIDATE` | System validates session token | `valid`, `invalid_or_expired` |

#### Monitoring & Analysis

**Monitor failed authentication attempts:**
```bash
# Failed attempts in last 24 hours
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT timestamp, client_id, action, status FROM audit_log \
   WHERE status LIKE '%fail%' OR status = 'invalid_code' \
   AND timestamp > datetime('now', '-1 day');"

# Count failed attempts per user
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT client_id, COUNT(*) as failed_attempts FROM audit_log \
   WHERE status = 'invalid_code' \
   GROUP BY client_id ORDER BY failed_attempts DESC;"
```

**Detect suspicious activity:**
```bash
# Multiple failed attempts from same IP (potential brute force)
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT ip_address, COUNT(*) as attempts FROM audit_log \
   WHERE status = 'invalid_code' \
   AND timestamp > datetime('now', '-1 hour') \
   GROUP BY ip_address HAVING attempts > 3;"

# User activity timeline
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT timestamp, action, status FROM audit_log \
   WHERE client_id = 'alice' ORDER BY timestamp DESC;"
```

**Cleanup old audit logs (optional):**
```bash
# Delete logs older than 90 days (saves space)
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "DELETE FROM audit_log WHERE timestamp < datetime('now', '-90 days');"

# Check database size before/after
du -sh /etc/wireshield/2fa/auth.db
```

#### Audit Log Best Practices

1. **Regular Monitoring** — Check logs weekly for failed attempts
2. **Backups** — Export audit logs monthly to external storage
3. **Cleanup** — Remove logs older than 90 days to save space
4. **Alerts** — Set up alerts for suspicious patterns (e.g., >5 failed attempts/user/day)
5. **Retention** — Keep 12 months of audit logs for compliance
6. **Access Control** — Only admins should access audit logs
7. **Analysis** — Use CSV export for detailed analysis in spreadsheets/SIEM tools

### Rate Limiting & Abuse Prevention

WireShield includes built-in rate limiting to prevent brute-force attacks and API abuse.

#### How Rate Limiting Works

- **Per-endpoint, per-IP tracking** — Each client IP is limited separately for each API endpoint
- **Sliding window algorithm** — Requests are tracked in a time window (default: 60 seconds)
- **Automatic blocking** — Exceeding the limit returns HTTP 429 (Too Many Requests)
- **In-memory tracking** — No database overhead, fast response

#### Default Configuration

```bash
# Current settings (in /etc/wireshield/2fa/config.env)
2FA_RATE_LIMIT_MAX_REQUESTS=30    # Max requests per window
2FA_RATE_LIMIT_WINDOW=60          # Window in seconds

# This means:
# • 30 requests allowed per IP per endpoint
# • Within a 60-second sliding window
# • Example: /api/verify limited to 30 attempts/minute per IP
```

#### Adjust Rate Limits

**For stricter security (lower limits):**
```bash
sudo nano /etc/wireshield/2fa/config.env

# Change to:
2FA_RATE_LIMIT_MAX_REQUESTS=10
2FA_RATE_LIMIT_WINDOW=60

# Restart service
sudo systemctl restart wireshield-2fa
```

**For high-traffic environments (higher limits):**
```bash
sudo nano /etc/wireshield/2fa/config.env

# Change to:
2FA_RATE_LIMIT_MAX_REQUESTS=100
2FA_RATE_LIMIT_WINDOW=60

# Restart service
sudo systemctl restart wireshield-2fa
```

#### Monitor Rate Limit Events

```bash
# View recent rate limit blocks (HTTP 429 responses)
sudo journalctl -u wireshield-2fa | grep "429"

# Count rate limit hits today
sudo journalctl -u wireshield-2fa --since today | grep -c "Too many requests"

# See which IPs are being rate limited
sudo journalctl -u wireshield-2fa --since today | grep "Too many requests" | awk '{print $NF}'
```

#### Rate Limiting Best Practices

1. **Monitor logs** — Watch for legitimate users hitting limits
2. **Adjust for your use case** — Lower for sensitive deployments, higher for large teams
3. **Document limits** — Inform users about retry delays
4. **Layer defenses** — Combine with firewall rules (fail2ban) for IP-level blocking
5. **Test changes** — Use `curl` or test scripts to verify limits work as expected

#### Testing Rate Limits

```bash
# Test rate limiting with curl (run on client machine)
for i in {1..35}; do
  curl -X POST https://your-domain:8443/api/verify \
    -d "client_id=test&code=123456" \
    -w "\nStatus: %{http_code}\n"
  sleep 0.5
done

# Expected output:
# First 30 requests: 401 (Unauthorized - invalid code)
# Requests 31-35: 429 (Too Many Requests)
```

### Captive Portal & Auto-Redirect (v2.4.0+)

WireShield implements a **captive portal** that automatically redirects users to the 2FA setup page when they first connect to the VPN:

#### How it works

**Connection Flow:**
1. User connects to VPN → WireGuard assigns IP (e.g., `10.66.66.2`)
2. Firewall blocks all traffic except DNS (port 53) and 2FA service (port 8443)
3. User tries to access any HTTP website → iptables redirects to HTTPS 2FA page
4. Browser automatically attempts captive portal detection and shows 2FA page
5. User completes 2FA → firewall automatically allows full internet access
6. Session valid for 24 hours (default)

#### What the firewall rules do

**Before 2FA verification:**
```
ALLOW:  Port 53 (DNS) - needed for domain resolution
ALLOW:  Port 8443 (HTTPS) - the 2FA service
ALLOW:  Port 80 → redirect to 8443 (HTTP capture)
DROP:   Everything else
```

**After 2FA verification:**
```
ALLOW:  All traffic (firewall whitelist activated)
```

**On disconnect or session expiry:**
- Client IP removed from allowlist
- Next connection requires 2FA again

#### Firewall constructs created

The installer automatically creates:
- `ws_2fa_allowed_v4` - IPv4 allowlist (ipset)
- `ws_2fa_allowed_v6` - IPv6 allowlist (ipset)
- `WS_2FA_PORTAL` - IPv4 captive portal chain
- `WS_2FA_PORTAL6` - IPv6 captive portal chain
- `WS_2FA_REDIRECT` - IPv4 HTTP→HTTPS redirect (iptables NAT)
- `WS_2FA_REDIRECT6` - IPv6 HTTP→HTTPS redirect (iptables NAT)

#### Client auto-discovery

The 2FA service auto-detects clients based on their WireGuard IP. No need to pass `?client_id=` manually:
- Direct access: `https://vpn.example.com:8443/?client_id=alice`
- Auto-discovery: `https://vpn.example.com:8443/` (discovers from IP)

#### Verify captive portal status

```bash
# Check if allowlists exist and have entries
sudo ipset list ws_2fa_allowed_v4
sudo ipset list ws_2fa_allowed_v6

# Verify DNAT redirect rules
sudo iptables -t nat -S | grep WS_2FA_REDIRECT
sudo ip6tables -t nat -S | grep WS_2FA_REDIRECT6

# Check firewall chains
sudo iptables -S WS_2FA_PORTAL
sudo ip6tables -S WS_2FA_PORTAL6
```

#### Troubleshooting

**Q: Browser doesn't show captive portal page automatically?**
- Some networks/devices don't trigger captive portal detection automatically
- Workaround: Manually open `https://vpn-server:8443/` in your browser

**Q: I can't access the 2FA page even on first connection?**
- Check if port 8443 is reachable: `telnet vpn-server 8443`
- Verify firewall rules: `sudo iptables -S WS_2FA_PORTAL | grep 8443`
- Check service is running: `sudo systemctl status wireshield-2fa`

**Q: After 2FA, still no internet?**
- Wait 5-10 seconds for the service to update allowlist
- Check if you're in the allowlist: `sudo ipset list ws_2fa_allowed_v4`
- Verify sessions table: `sqlite3 /etc/wireshield/2fa/auth.db "SELECT * FROM sessions WHERE client_id = '<YOUR_ID>';"`

### 2FA Enforcement (Firewall Gating)

WireShield enforces 2FA at the firewall for the iptables path. By default, traffic sourced from the WireGuard interface is dropped unless the client’s WG IP is present in an allowlist.

#### How it works

- On 2FA success (`/api/setup-verify` or `/api/verify`), the 2FA service adds the client’s WG IPv4/IPv6 addresses to `ws_2fa_allowed_v4/ws_2fa_allowed_v6`.
- The installer creates `WS_2FA_FILTER/WS_2FA_FILTER6` chains attached to `FORWARD` on the WG interface with default DROP.
- As long as any active session exists for a client, their WG IP remains in the allowlist.
- A background worker prunes allowlist entries for clients that have no active sessions (runs every 60 seconds).

#### Verify gating status

```bash
sudo ipset list ws_2fa_allowed_v4
sudo ipset list ws_2fa_allowed_v6
sudo iptables -S WS_2FA_FILTER
sudo ip6tables -S WS_2FA_FILTER6
```

#### Health check

```bash
curl -sk https://127.0.0.1:8443/health
# Expected: {"status":"ok","service":"wireshield-2fa"}
```

#### Notes

- Gating is applied in the iptables path (common on Ubuntu/Debian). If your host uses firewalld exclusively, the standard rich rules are configured; equivalent ipset-based gating for firewalld can be added in a future release.
- Multiple sessions per client are supported; gating persists while any session is valid.
- Default pruning interval is 60s. This can be tuned in code if you need tighter revocation.

### Service Management

#### Check Service Status

```bash
# 2FA service status
sudo systemctl status wireshield-2fa

# View live logs
sudo journalctl -u wireshield-2fa -f

# View last 50 lines
sudo journalctl -u wireshield-2fa -n 50
```

#### Restart Services

```bash
# Restart 2FA service
sudo systemctl restart wireshield-2fa

# Restart WireGuard
sudo systemctl restart wg-quick@wg0

# Full restart
sudo systemctl restart wg-quick@wg0 wireshield-2fa
```

#### Enable/Disable Auto-Start

```bash
# Enable 2FA service on boot
sudo systemctl enable wireshield-2fa

# Disable auto-start
sudo systemctl disable wireshield-2fa

# Verify auto-start
sudo systemctl is-enabled wireshield-2fa
```

### Monitoring & Logging

#### Monitor in Real-Time

```bash
# Watch all 2FA events
watch -n 1 'sudo journalctl -u wireshield-2fa -n 20'

# Monitor port 8443 (2FA web UI)
sudo lsof -i :8443

# Monitor database operations
sqlite3 /etc/wireshield/2fa/auth.db .tables
sqlite3 /etc/wireshield/2fa/auth.db "SELECT COUNT(*) FROM users;"
```

#### Environment configuration

The 2FA service reads environment from `/etc/wireshield/2fa/config.env`.

- Primary keys: `WS_2FA_*` (bash-safe, preferred in systemd unit)
- Legacy keys: `2FA_*` (still supported for compatibility)

Examples:

```
WS_2FA_PORT=8443
WS_2FA_SSL_ENABLED=true
WS_2FA_DOMAIN=vpn.example.com
WS_2FA_RATE_LIMIT_MAX_REQUESTS=30
WS_2FA_RATE_LIMIT_WINDOW=60
```

#### Certificate Renewal Monitoring

**How Let's Encrypt Automatic Renewal Works:**

WireShield uses systemd timers for automated certificate renewal. The renewal process:

1. **Daily Timer Check** - Runs daily at midnight (configurable)
2. **Certbot Renewal** - Checks if certificates need renewal (LE only renews within 30 days of expiry)
3. **Service Reload** - On successful renewal, reloads the 2FA service
4. **Logging** - All renewal attempts are logged

**Monitor Renewal Status:**

```bash
# Check renewal timer status
sudo systemctl status wireshield-2fa-renew.timer

# See next renewal check
sudo systemctl list-timers wireshield-2fa-renew.timer

# View renewal logs (today)
sudo journalctl -u wireshield-2fa-renew.service --since today

# View renewal logs (last 7 days)
sudo journalctl -u wireshield-2fa-renew.service --since "7 days ago"

# View detailed renewal history
sudo journalctl -u wireshield-2fa-renew.service -n 100

# Check certificate expiry date
sudo openssl x509 -in /etc/wireshield/2fa/cert.pem -noout -dates

# Days until expiry
sudo echo "Expires in: $((($( date -d "$(openssl x509 -in /etc/wireshield/2fa/cert.pem -noout -enddate | cut -d= -f2)" +%s) - $(date +%s) )/86400)) days"
```

**Manual Certificate Renewal:**

```bash
# Force immediate renewal (even if not due)
sudo certbot renew --force-renewal

# Renew and reload service immediately
sudo certbot renew --quiet --post-hook "sudo systemctl reload wireshield-2fa"

# Dry run (test without actually renewing)
sudo certbot renew --dry-run

# Check renewal configuration
sudo ls -la /etc/letsencrypt/renewal/

# View Certbot configuration
sudo cat /etc/letsencrypt/renewal/youromain.com.conf
```

**Renewal Troubleshooting:**

```bash
# Check if certbot can reach Let's Encrypt
sudo certbot renew --dry-run

# Check systemd timer is enabled
sudo systemctl is-enabled wireshield-2fa-renew.timer

# If timer not running, enable it
sudo systemctl enable wireshield-2fa-renew.timer
sudo systemctl start wireshield-2fa-renew.timer

# View systemd timer logs
sudo journalctl -u systemd-timer-monitor -n 50

# Check firewall allows port 80/443 for renewal
sudo ufw status                    # UFW
sudo firewall-cmd --list-all       # Firewalld

# Manual trigger (for testing)
sudo systemctl start wireshield-2fa-renew.service
sudo journalctl -u wireshield-2fa-renew.service -f
```

**Certificate Renewal Alerts:**

```bash
# Email alert on renewal failure (optional cron)
# Add to crontab:
# 0 1 * * * sudo /usr/bin/certbot renew --quiet || mail -s "Certificate renewal failed" admin@example.com

# Check certificate expiry in 30 days or less
EXPIRY=$(sudo openssl x509 -in /etc/wireshield/2fa/cert.pem -noout -enddate | cut -d= -f2)
DAYS_LEFT=$(( ($( date -d "$EXPIRY" +%s) - $(date +%s) )/86400 ))
if [ $DAYS_LEFT -le 30 ]; then
  echo "Alert: Certificate expires in $DAYS_LEFT days!"
fi
```

**Let's Encrypt Renewal Best Practices:**

1. ✅ **Always use port 80/443** - Let's Encrypt needs these for validation
2. ✅ **Keep certbot updated** - Run `sudo apt update && sudo apt upgrade certbot`
3. ✅ **Monitor logs regularly** - Check renewal success: `sudo journalctl -u wireshield-2fa-renew.service`
4. ✅ **Plan renewal timing** - Timer runs at midnight; avoid high-traffic times if possible
5. ✅ **Test before critical deployment** - Use `--dry-run` first
6. ✅ **Backup certificates** - Keep `/etc/letsencrypt/` backed up
7. ✅ **Set up monitoring** - Alert if renewal fails 3 days before expiry

#### Security Audit

```bash
# View all authentication attempts
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT username, success, timestamp FROM audit_log ORDER BY timestamp DESC;"

# Failed attempts only
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT username, attempts, timestamp FROM audit_log WHERE success = 0;"
```

### Backup & Recovery

#### Backup Configurations

```bash
# Backup everything
sudo tar -czf wireshield-backup-$(date +%Y%m%d).tar.gz \
  /etc/wireguard/ \
  /etc/wireshield/ \
  ~/

# Store securely
scp wireshield-backup-*.tar.gz user@backup-server:/backups/

# For menu option
sudo ./wireshield.sh    # Choose Option 9 (Backup)
```

#### Restore from Backup

```bash
# Extract backup
sudo tar -xzf wireshield-backup-20240101.tar.gz -C /

# Restart services
sudo systemctl restart wg-quick@wg0 wireshield-2fa

# Verify
sudo systemctl status wireshield-2fa
```

### Troubleshooting

#### 2FA Service Won't Start

```bash
# Check logs
sudo journalctl -u wireshield-2fa -n 50

# Check Python installation
python3 --version
pip3 list | grep fastapi

# Check port 8443
sudo lsof -i :8443

# Restart
sudo systemctl restart wireshield-2fa
```

#### Let's Encrypt Renewal Failing

```bash
# Check timer
sudo systemctl status wireshield-2fa-renewal.timer

# Manual renewal test
sudo certbot renew --dry-run

# View renewal logs
sudo journalctl -u wireshield-2fa-renewal.service -n 100

# Manual renewal if needed
sudo certbot renew --force-renewal
```

#### SSL Certificate Issues

```bash
# Check certificate info
sudo openssl x509 -in /etc/wireshield/2fa/certs/cert.pem -text -noout

# Check expiry date
sudo openssl x509 -in /etc/wireshield/2fa/certs/cert.pem -noout -dates

# View certificate chain
sudo openssl x509 -in /etc/wireshield/2fa/certs/fullchain.pem -text

# Verify certificate matches key
diff <(sudo openssl x509 -noout -modulus -in /etc/wireshield/2fa/certs/cert.pem) \
     <(sudo openssl rsa -noout -modulus -in /etc/wireshield/2fa/certs/key.pem)
```

#### User Can't Verify 2FA

```bash
# Reset user's TOTP secret (must re-scan QR)
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "DELETE FROM users WHERE username='alice';"

# Clear user's sessions
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "DELETE FROM sessions WHERE username='alice';"

# Verify user is re-created on next login
```

---

## 💻 Contributor Guide

### Project Structure

```
WireShield/
├── wireshield.sh                      Main CLI (1733 lines)
│   ├── _ws_system_check()             Validates OS/kernel
│   ├── _ws_install_wireguard()        WireGuard setup
│   ├── _ws_configure_2fa()            2FA installation
│   ├── _ws_configure_2fa_ssl()        SSL/TLS setup
│   ├── _ws_manage_clients()           Client CRUD operations
│   └── installWireGuard()             Main installation flow
│
├── 2fa-auth/                          2FA Service Directory
│   ├── app.py                         FastAPI server (1500+ lines)
│   │   ├── DatabaseManager            SQLite ORM wrapper
│   │   ├── TOTPManager                TOTP/QR code generation
│   │   ├── SessionManager             Session token management
│   │   ├── RateLimiter                Per-IP+endpoint throttling
│   │   └── Endpoints (5 total)        REST API endpoints
│   │
│   ├── requirements.txt               Pinned Python dependencies
│   ├── .venv/                         Isolated virtual environment
│   ├── wireshield-2fa.service         Systemd unit file
│   ├── generate-certs.sh              SSL cert generator
│   ├── 2fa-helper.sh                  Management CLI
│   └── tests/                         Test suite
│       ├── test_rate_limit.py         Rate limiting tests (pytest)
│       └── test-integration.sh        Integration tests (bash)
│
├── README.md                          This file (comprehensive guide)
└── LICENSE                            GPLv3 license
```

### Architecture

**Component Overview:**

```
User Device (Client)          Linux Server Infrastructure
     │                                  │
  ┌──┴──┐                        ┌─────┴──────┐
  │ WG  │ UDP Encrypted Tunnel  │  WireGuard  │
  │ App │◄──────────────────────►│  (wg0)     │
  └─────┘  Port 51820 (Default)  │  51820/UDP │
                                 └─────┬──────┘
                                       │
                  ┌────────────────────┼────────────────────┐
                  │                    │                    │
            ┌─────▼─────┐      ┌──────▼───────┐     ┌──────▼──────┐
            │ Firewall  │      │ 2FA Service  │     │  Systemd   │
            │ (iptables)│      │ (FastAPI)    │     │ Management │
            │ Port 51820│      │ Port 8443    │     │ • Services │
            │ NAT Rules │      │ SSL/TLS      │     │ • Timers   │
            └───────────┘      │ • Setup QR   │     └────────────┘
                               │ • Verify 2FA │
                               │ • Sessions   │
                               └──────┬───────┘
                                      │
                              ┌───────▼────────┐
                              │  SQLite DB     │
                              │ • users        │
                              │ • sessions     │
                              │ • audit_log    │
                              └────────────────┘
```

**Data Flow:**

1. User connects WireGuard app → UDP Port 51820
2. Firewall intercepts → Redirects to HTTPS 2FA UI
3. User scans QR code → Stores secret in app
4. User enters TOTP code → FastAPI validates
5. Session token issued → Access granted
6. After 24h → Must re-verify with new code

### Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **CLI** | Bash | 4.x+ | Main orchestrator, installer |
| **VPN** | WireGuard | Latest | Kernel VPN module |
| **2FA Server** | FastAPI | 0.100+ | REST API, web UI |
| **Web Framework** | Uvicorn | 0.23+ | ASGI server |
| **2FA Algorithm** | PyOTP | 2.8+ | TOTP generation |
| **QR Codes** | qrcode | 7.4+ | QR code generation |
| **Database** | SQLite | 3.x | Persistent storage |
| **ORM** | SQLAlchemy | 2.0+ | Database abstraction |
| **Crypto** | cryptography | 41.0+ | TLS/SSL support |
| **SSL Certs** | OpenSSL | 1.1+ | Certificate generation |
| **Auto-Renewal** | Certbot | 1.x+ | Let's Encrypt automation |
| **Service** | Systemd | Modern | Process management |
| **Firewall** | iptables/firewalld | Latest | Access control |

### Code Quality Standards

#### Bash (wireshield.sh)
- ✅ POSIX-compliant where possible
- ✅ Shellcheck clean (no warnings)
- ✅ Error handling with meaningful messages
- ✅ Colored output for readability
- ✅ Function-based modular design
- ✅ Comprehensive comments

#### Python (app.py)
- ✅ Python 3.8+ compatible
- ✅ Type hints throughout
- ✅ Comprehensive error handling
- ✅ Async/await for performance
- ✅ Security-first defaults
- ✅ Extensive logging

#### Documentation
- ✅ Every function documented
- ✅ Complex logic explained
- ✅ Security implications noted
- ✅ Examples provided

### Contributing

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Implement** your changes (follow code standards above)
4. **Test** thoroughly: `bash wireshield.sh` (interactive testing)
5. **Validate** syntax:
   ```bash
   bash -n wireshield.sh           # Bash syntax
   python3 -m py_compile 2fa-auth/app.py  # Python syntax
   ```
6. **Commit** with clear message: `git commit -m "feat: add amazing feature"`
7. **Push** to your fork: `git push origin feature/amazing-feature`
8. **Create** a Pull Request with description

### Development Setup

```bash
# Clone for development
git clone https://github.com/YOUR_FORK/WireShield.git
cd WireShield

# Review code
cat wireshield.sh           # Bash implementation
cat 2fa-auth/app.py         # Python implementation

# Test locally (non-destructive)
bash -n wireshield.sh       # Bash syntax check
python3 -m py_compile 2fa-auth/app.py

# For actual testing, use test VM
```

### API Reference

The 2FA service exposes these endpoints:

```
GET /health
  Response: {"status": "healthy"}
  
GET /?client_id=<client_id>
  Returns: HTML web UI for 2FA setup
  
POST /api/setup-start
  Request: {"client_id": "alice"}
  Response: {"qr_code": "data:image/png;base64,...", "secret": "..."}
  
POST /api/setup-verify
  Request: {"client_id": "alice", "code": "123456"}
  Response: {"success": true, "session_token": "...", "expires_in": 86400}
  
POST /api/verify
  Request: {"client_id": "alice", "code": "123456"}
  Response: {"success": true, "session_token": "...", "expires_in": 86400}
  
POST /api/validate-session
  Request: {"client_id": "alice", "session_token": "..."}
  Response: {"valid": true, "expires_in": 82345}
```

### Database Schema

```sql
-- Users table
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  secret TEXT NOT NULL,           -- Encrypted TOTP secret
  enabled BOOLEAN DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  session_token TEXT UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  FOREIGN KEY (username) REFERENCES users(username)
);

-- Audit log table
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  action TEXT NOT NULL,           -- 'setup', 'verify', 'failed_attempt'
  success BOOLEAN NOT NULL,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## ❓ FAQ & Troubleshooting

### General Questions

**Q: How does the auto-redirect to 2FA work?**
A: When you connect to the VPN for the first time, the firewall blocks internet access. Any HTTP traffic is automatically redirected to the 2FA setup page (HTTPS). Your browser's captive portal detection may automatically open it. If not, manually open `https://vpn-server:8443/` in your browser. Once you complete 2FA, the firewall automatically whitelists your IP and grants full internet access.

**Q: What happens when I disconnect and reconnect?**
A: Each disconnect expires your session. When you reconnect, the firewall blocks you again until you re-verify with 2FA (unless your 24-hour session is still active). If your session is still valid within the 24-hour window, you stay whitelisted across disconnect/reconnect cycles.

**Q: What if I lose my authenticator phone?**
A: You saved your backup secret code during setup. Use it to re-add 2FA to a new phone. Administrators can also reset your account via `2fa-helper.sh disable <username>` to set up again.

**Q: Can I use multiple authenticator apps?**
A: Not with the current setup—one secret per user. For multi-device setup, save the backup secret code to a secure location and restore on other devices.

**Q: What happens during the 24-hour session window?**
A: After 2FA verification, your session token is valid for 24 hours. You can disconnect/reconnect without re-verifying. After 24 hours, you must 2FA again. Sessions are tracked per-device/IP, so multiple devices need separate 2FA verifications.

**Q: Is there a way to bypass 2FA?**
A: No. 2FA is enforced at the firewall level before VPN access. Only admins can disable it per user via `2fa-helper.sh disable <username>`.

**Q: Can I use this for on-premise/private networks?**
A: Yes! Choose self-signed certificates with an internal IP or hostname. No internet access required after installation.

### Installation Issues

**Q: "Permission denied" during installation?**
A: Run with `sudo`: `sudo ./wireshield.sh`

**Q: "System not supported" error?**
A: Your OS/kernel isn't supported. Minimum: Ubuntu 18.04, Debian 10, Fedora 32, CentOS 8, etc. Check with: `uname -r`

**Q: Port already in use?**
A: The installation will suggest an alternative UDP port. Or manually edit `/etc/wireguard/params` and restart.

### 2FA Issues

**Q: "TOTP verification failed" repeatedly?**
A: 
1. Check server and phone times are synchronized
2. Ensure authenticator app is up-to-date
3. Try entering the code immediately after it changes
4. Reset: `sudo /etc/wireshield/2fa/2fa-helper.sh disable <username>`

**Q: 2FA service not running?**
A: Check: `sudo systemctl status wireshield-2fa`
Logs: `sudo journalctl -u wireshield-2fa -n 50`

**Q: WireGuard service fails with "protocol family of set ws_2fa_allowed_v6 is IPv4"?**
A: This was fixed in commit 9444bc6. Update your installation:
```bash
cd WireShield
git pull
sudo ./wireshield.sh  # Re-run installer
```
Or manually fix existing `/etc/wireguard/wg0.conf`:
```bash
sudo wg-quick down wg0
# Edit PostUp lines to include 'family inet' and 'family inet6':
# PostUp = ipset create ws_2fa_allowed_v4 hash:ip family inet -exist
# PostUp = ipset create ws_2fa_allowed_v6 hash:ip family inet6 -exist
sudo wg-quick up wg0
```

**Q: Can't access https://vpn.example.com:8443?**
A: 
1. Check port 8443 is open: `sudo lsof -i :8443`
2. Check SSL certificate: `sudo openssl x509 -in /etc/wireshield/2fa/certs/cert.pem -text`
3. Check service: `sudo systemctl status wireshield-2fa`

### SSL/Certificate Issues

**Q: Browser shows certificate warning for self-signed certs?**
A: This is expected and normal. Click "Advanced" → "Proceed" in your browser. Self-signed certs aren't trusted by default.

**Q: Let's Encrypt certificate won't renew?**
A: Check:
```bash
sudo systemctl status wireshield-2fa-renewal.timer
sudo journalctl -u wireshield-2fa-renewal.service -n 50
```
Manually renew: `sudo certbot renew --force-renewal`

**Q: How to switch from self-signed to Let's Encrypt?**
A: Reinstall 2FA:
```bash
sudo systemctl stop wireshield-2fa
sudo rm -rf /etc/wireshield/2fa/
sudo ./wireshield.sh  # Choose 2FA installation
```

### Performance & Monitoring

**Q: How many concurrent users can WireShield handle?**
A: Depends on server specs, but typical VPS (2 CPU, 4GB RAM) handles 50-100 concurrent users. 2FA itself is lightweight (<1ms per verification).

**Q: How to monitor 2FA in production?**
A: 
```bash
# Real-time logs
sudo journalctl -u wireshield-2fa -f

# Database size
du -sh /etc/wireshield/2fa/auth.db

# Active sessions
sqlite3 /etc/wireshield/2fa/auth.db "SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now');"

# Failed auth attempts (last 24h)
sqlite3 /etc/wireshield/2fa/auth.db "SELECT COUNT(*) FROM audit_log WHERE success=0 AND timestamp > datetime('now', '-1 day');"
```

**Q: Should I clean up old audit logs?**
A: Optional, but recommended for large databases:
```bash
# Delete audit logs older than 90 days
sqlite3 /etc/wireshield/2fa/auth.db \
  "DELETE FROM audit_log WHERE timestamp < datetime('now', '-90 days');"
```

### Security Questions

**Q: Is 2FA stored encrypted?**
A: Yes. TOTP secrets are encrypted using the `cryptography` library. Session tokens are SHA256 hashed. Never stored in plaintext.

**Q: What about TOTP time skew?**
A: The system accepts TOTP codes with ±1 time window tolerance (±30 seconds), which is industry standard and accounts for clock drift.

**Q: Can 2FA be bypassed using firewall rules?**
A: No. 2FA is enforced at the firewall level (iptables/firewalld). Every connection attempt is redirected to the 2FA web UI until verified.

**Q: Are audit logs encrypted?**
A: No, audit logs are plaintext in the SQLite database. Secure your server filesystem and restrict `/etc/wireshield/2fa/` to root-only access (default: 0700).

### Uninstallation

**Q: How to uninstall WireShield completely?**
A: The uninstall process removes everything (WireGuard, 2FA service, certificates, etc.):

**Method 1: Interactive Uninstall (Recommended)**
```bash
# Run the main menu
sudo ./wireshield.sh

# Choose Option 9 (Uninstall)
# Confirms removal of all configs, services, and data
# 
# This removes:
#   ✓ WireGuard kernel module and tools
#   ✓ WireGuard configuration (/etc/wireguard)
#   ✓ 2FA service (FastAPI, Uvicorn)
#   ✓ 2FA database (/etc/wireshield/2fa/auth.db)
#   ✓ SSL certificates (Let's Encrypt symlinks, self-signed certs)
#   ✓ Auto-renewal timers and services
#   ✓ All systemd service files
#   ✓ Client configuration files
#   ✓ Cron jobs for client expiration
#   ✓ Firewall rules and sysctl settings
```

**Method 2: Manual Uninstall**
```bash
# Stop and disable services
sudo systemctl stop wireshield-2fa wg-quick@wg0
sudo systemctl stop wireshield-2fa-renew.timer wireshield-2fa-renew.service
sudo systemctl disable wireshield-2fa wg-quick@wg0
sudo systemctl disable wireshield-2fa-renew.timer wireshield-2fa-renew.service

# Remove configuration directories
sudo rm -rf /etc/wireguard/           # WireGuard configs
sudo rm -rf /etc/wireshield/          # 2FA service, database, certs
sudo rm -f /etc/sysctl.d/wg.conf      # Kernel settings

# Remove systemd services and timers
sudo rm -f /etc/systemd/system/wireshield-2fa.service
sudo rm -f /etc/systemd/system/wireshield-2fa-renew.timer
sudo rm -f /etc/systemd/system/wireshield-2fa-renew.service
sudo systemctl daemon-reload

# Remove helper scripts
sudo rm -f /usr/local/bin/wireshield-check-expired
sudo rm -f /usr/local/bin/wireshield-renew-cert

# Remove client configs from home directories
rm -f ~/*.conf                        # From root home
sudo find /home -maxdepth 2 -name "*.conf" -delete

# Remove Let's Encrypt symlinks (if applicable)
sudo rm -f /etc/wireshield/2fa/certs/*.pem

# Remove crontab entries
sudo crontab -l 2>/dev/null | grep -v "wireshield" | sudo crontab -

# Reload sysctl
sudo sysctl --system

# Remove 2FA gating (iptables path)
sudo iptables -D FORWARD -j WS_2FA_FILTER 2>/dev/null || true
sudo iptables -F WS_2FA_FILTER 2>/dev/null || true
sudo iptables -X WS_2FA_FILTER 2>/dev/null || true
sudo ip6tables -D FORWARD -j WS_2FA_FILTER6 2>/dev/null || true
sudo ip6tables -F WS_2FA_FILTER6 2>/dev/null || true
sudo ip6tables -X WS_2FA_FILTER6 2>/dev/null || true
sudo ipset destroy ws_2fa_allowed_v4 2>/dev/null || true
sudo ipset destroy ws_2fa_allowed_v6 2>/dev/null || true
```

**Q: What gets removed during uninstall?**
A:
| Component | Location | Removed | Notes |
|-----------|----------|---------|-------|
| WireGuard | `/etc/wireguard/` | ✅ Yes | All configs and parameters |
| 2FA Service | `/etc/wireshield/2fa/` | ✅ Yes | Database, certs, configs |
| 2FA Systemd Service | `/etc/systemd/system/wireshield-2fa.service` | ✅ Yes | Service file |
| Let's Encrypt Auto-Renewal | `/etc/systemd/system/wireshield-2fa-renew.*` | ✅ Yes | Timer and service |
| SSL Certificates | `/etc/letsencrypt/live/` | ❌ No | (Let's Encrypt keeps original) |
| Client Configs | `/root/*.conf` `/home/*/*.conf` | ✅ Yes | All client configs |
| Firewall Rules | iptables/firewalld | ✅ Yes | Cleared during service stop |
| Cron Jobs | crontab | ✅ Yes | Expiration checker removed |
| Python Packages | System Python | ❌ No | (Safe to keep, may be used elsewhere) |

**Q: Can I reinstall after uninstalling?**
A: Yes! Just run `sudo ./wireshield.sh` again. The uninstall is clean and doesn't prevent reinstallation.

**Q: How to preserve Let's Encrypt certificates after uninstall?**
A: Let's Encrypt certificates are stored independently:
```bash
# They remain in /etc/letsencrypt/live/
# Make a backup before uninstall if needed
sudo cp -r /etc/letsencrypt ~/letsencrypt-backup

# After uninstall, they're still available for other services
sudo ls -la /etc/letsencrypt/live/
```

---

## 📊 Architecture & Security

### System Architecture

**Network Topology:**

```
                        ┌──────────────┐
                        │   Internet   │
                        └──────┬───────┘
                               │
                        UDP Port 51820
                               │
                               ▼
                  ┌────────────────────────────┐
                  │   Linux Server             │
                  │  (Firewall Layer)          │
                  │ • Port 51820 (UDP)         │
                  │ • Port 8443 (HTTPS)        │
                  │ • Port 80/443 (LE renewal) │
                  └──┬───┬──────────┬───────────┘
                     │   │          │
          ┌──────────┘   │          └──────────┐
          │              │                     │
      ┌───▼────┐   ┌─────▼──────┐    ┌────────▼──────┐
      │WireGuard│   │ FastAPI    │    │ Systemd      │
      │ Module  │   │ 2FA Server │    │ Management   │
      │ (wg0)   │   │ Port 8443  │    │              │
      │         │   │ HTTPS/TLS  │    │ • wg-quick   │
      │ UDP Port│   │            │    │ • timers     │
      │ 51820   │   │ Endpoints: │    │ • cert renew │
      │         │   │ /health    │    └──────────────┘
      └────┬────┘   │ /api/setup │
           │        │ /api/verify│
           │        │ /validate  │
           │        └─────┬──────┘
           │              │
           └──────┬───────┘
                  │
           ┌──────▼──────────┐
           │  SQLite DB      │
           │  /etc/wieshield/│
           │  • users        │
           │  • sessions     │
           │  • audit_log    │
           └─────────────────┘
```

**Security Layers:**

| Layer | Component | Purpose |
|-------|-----------|----------|
| Network | Firewall (iptables) | Port filtering, NAT masquerading |
| Application | FastAPI Server | 2FA authentication, session management |
| Storage | SQLite Database | User data, session tokens, audit logs |
| Crypto | OpenSSL/Certbot | TLS certificates, auto-renewal |
| Process | Systemd | Service orchestration, auto-recovery |

### Security Features

| Feature | Implementation | Status |
|---------|---|---|
| TOTP Generation | PyOTP with ±1 time window | ✅ |
| Secret Storage | Encrypted in SQLite | ✅ |
| Session Tokens | 32-byte random, SHA256 hashed | ✅ |
| Session TTL | 24 hours (configurable) | ✅ |
| HTTPS Transport | TLS 1.2+ (Let's Encrypt or self-signed) | ✅ |
| Database Encryption | At-rest (via filesystem permissions) | ✅ |
| Firewall Integration | Per-user iptables rules | ✅ |
| Audit Logging | Every auth attempt logged | ✅ |
| Rate Limiting | Per-IP+endpoint sliding window (30 req/60s default) | ✅ |
| Key Rotation | Supported via manual reset | ✅ |

### Hardening

- ✅ Systemd service: `PrivateTmp`, `NoNewPrivileges`, `RestrictAddressFamilies`
- ✅ File permissions: `/etc/wireshield/2fa/` owned by root with `0700` mode
- ✅ Database: SQLite with WAL mode for consistency
- ✅ Network: Firewall rules restrict access to authorized ports only
- ✅ Secrets: Never logged, never cached, never transmitted without encryption

---

## 📝 License

WireShield is released under the **GNU General Public License v3.0 (GPLv3)**. See [LICENSE](LICENSE) for the full text.

### Why GPLv3?

GPLv3 is the ideal license for WireShield because:

**✅ It's Right for This Project:**
- **Open Source Heritage** — Based on WireGuard (MIT) and open-source tools (FastAPI, PyOTP, Certbot)
- **Community-Driven** — Encourages community contributions and improvements
- **Freedom & Copyleft** — Ensures the software remains free for all users
- **Derivative Works** — If you modify WireShield, you must share improvements back
- **No Patent Threats** — Explicit patent grant protects users

**✅ It Aligns With Project Goals:**
- **Security-First** — Open source allows security auditing by the community
- **Transparency** — Source code visible and verifiable
- **Professional Use** — Companies can use it commercially, must contribute back
- **Long-Term Viability** — Community can fork and maintain if needed

### What You Can Do (GPLv3 Permissions)

✅ **Use commercially** — Deploy in production for profit
✅ **Modify** — Change the code for your needs
✅ **Distribute** — Share with others (including commercially)
✅ **Private use** — Modify for internal use without sharing

### What You Must Do (GPLv3 Obligations)

📋 **Include license** — Provide copy of GPLv3 license
📋 **State changes** — Document modifications to the code
📋 **Disclose source** — If distributing (modified or not), provide source code
📋 **Same license** — Derivatives must also use GPLv3

### Common Scenarios

**Scenario 1: Using WireShield as-is in production**
```
✅ ALLOWED
• Deploy as your VPN solution
• Use commercially
• No obligation to share (unless distributing)
```

**Scenario 2: Modifying WireShield internally**
```
✅ ALLOWED (private use)
• Modify code for internal needs
• Not required to share modifications
• Can't distribute modified version without source
```

**Scenario 3: Creating a derivative product**
```
⚠️ REQUIRED ACTIONS
• If you distribute (modified or unmodified): provide source code
• Release under GPLv3 (or compatible license)
• Clearly mark your changes
• Include the original license
```

**Scenario 4: Forking on GitHub**
```
✅ ALLOWED & ENCOURAGED
• Create a fork for your improvements
• Contribute back via pull requests
• Or maintain your own version
• Must keep GPLv3 license
```

### Is GPLv3 Right for You?

**Use WireShield if:**
✅ You're building a VPN solution for your organization
✅ You want to contribute improvements back
✅ You need a security-auditable codebase
✅ You're OK with GPL terms for derivative works

**Don't use WireShield if:**
❌ You want to create proprietary closed-source software
❌ You can't comply with GPL obligations
❌ You need a permissive license (MIT, Apache 2.0)
→ Consider: alternatives like simple WireGuard managers (not GPL-based)

### Dependency Licenses

WireShield depends on software with compatible licenses:

| Dependency | License | Compatibility |
|-----------|---------|---|
| WireGuard | MIT | ✅ Compatible |
| FastAPI | MIT | ✅ Compatible |
| Python | PSF | ✅ Compatible |
| PyOTP | MIT | ✅ Compatible |
| SQLAlchemy | MIT | ✅ Compatible |
| Certbot | Apache 2.0 | ✅ Compatible |
| OpenSSL | Apache 2.0, SSLeay | ✅ Compatible |

All dependencies are compatible with GPLv3.

### Legal Disclaimer

This is not legal advice. For detailed license interpretation:
- Read the [LICENSE](LICENSE) file
- Visit [gnu.org](https://www.gnu.org/licenses/gpl-3.0.html)
- Consult a lawyer for your specific situation

---

## 🙏 Acknowledgments

- **WireGuard** team for the incredible VPN protocol (MIT License)
- **FastAPI** for the modern Python web framework (MIT License)
- **PyOTP** for TOTP implementation (MIT License)
- **Certbot/Let's Encrypt** for free SSL certificates (Apache 2.0)
- **Our community** for contributions and feedback

---

## 📞 Support & Issues

**Documentation:**
- This README (complete guide)
- See specific sections above for your use case

**Troubleshooting:**
- Check the [FAQ & Troubleshooting](#faq--troubleshooting) section above
- Review logs: `sudo journalctl -u wireshield-2fa -f`

**Reporting Issues:**
- GitHub Issues: [github.com/siyamsarker/WireShield/issues](https://github.com/siyamsarker/WireShield/issues)
- Include: OS version, output of `wireshield.sh`, relevant logs

**Contributing:**
- See [Contributor Guide](#contributor-guide) above
- Pull requests welcome!

**License Questions:**
- See [License](#-license) section above
- All dependencies are GPLv3 compatible
- Commercial use is allowed (must provide source if distributed)

---

**Made with ❤️ for secure, simple VPN deployments**

[⭐ Star on GitHub](https://github.com/siyamsarker/WireShield) • [🔗 Report Issue](https://github.com/siyamsarker/WireShield/issues) • [💬 Discussions](https://github.com/siyamsarker/WireShield/discussions)
