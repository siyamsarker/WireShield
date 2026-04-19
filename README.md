<div align="center">

<img src="assets/logo.svg" alt="WireShield Logo" width="140" height="140">

# WireShield

**Zero-trust WireGuard VPN with pre-connection two-factor authentication**

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![WireGuard](https://img.shields.io/badge/WireGuard-Compatible-88171a.svg)](https://www.wireguard.com/)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776ab.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688.svg)](https://fastapi.tiangolo.com/)

WireShield deploys a WireGuard VPN with mandatory TOTP-based two-factor authentication at the connection layer. Every client must verify through a captive portal before any traffic is allowed through the tunnel.

[Quick Start](#quick-start) &bull; [How It Works](#how-it-works) &bull; [Features](#features) &bull; [Installation](#installation) &bull; [Usage](#usage) &bull; [Contributing](#contributing)

</div>

---

## Quick Start

```bash
git clone https://github.com/siyamsarker/WireShield.git
cd WireShield
sudo ./wireshield.sh
```

The interactive installer handles everything: WireGuard setup, firewall rules, SSL certificates, 2FA service, and your first client configuration. Takes about 5 minutes.

---

## How It Works

```
┌──────────────────┐
│  Client Device   │
│  (WireGuard)     │
└────────┬─────────┘
         │  Connect VPN tunnel
         ▼
┌──────────────────────────────────────────────────┐
│                 WireGuard Server                 │
│  ┌────────────────────────────────────────────┐  │
│  │       iptables / ipset Firewall            │  │
│  │                                            │  │
│  │   Client IP in allowlist?                  │  │
│  │     ├── YES ──► ACCEPT (full access)       │  │
│  │     └── NO  ──► WS_2FA_PORTAL chain        │  │
│  │                   ├── Allow DNS (port 53)  │  │
│  │                   ├── Allow portal (80/443)│  │
│  │                   └── DROP everything else │  │
│  └────────────────────────────────────────────┘  │
│                      │                           │
│                      ▼                           │
│  ┌────────────────────────────────────────────┐  │
│  │       2FA Captive Portal (HTTPS)           │  │
│  │                                            │  │
│  │   1. User opens browser                    │  │
│  │   2. Redirected to portal                  │  │
│  │   3. Enter TOTP code from authenticator    │  │
│  │   4. Client IP added to ipset allowlist    │  │
│  │   5. Full internet access granted          │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

### Session Rules

| Rule | Behavior |
|------|----------|
| **Absolute timeout** | Sessions expire after 24 hours regardless of activity |
| **Disconnect grace** | If the VPN disconnects, the session survives for 1 hour |
| **Reconnect < 1h** | Instant access, no re-authentication required |
| **Reconnect > 1h** | Session revoked, 2FA required again |
| **Strict revocation** | Expired sessions immediately block all traffic |

### Split Tunnel

By default, when a client connects with `AllowedIPs = 0.0.0.0/0`, **all traffic** goes through the VPN tunnel — including traffic to local resources like `192.168.169.121:8000`. If the VPN server is cloud-hosted (e.g. AWS), it cannot reach those private IPs, so the connection fails.

The **Split Tunnel** page (under *Network* in the console) solves this by letting admins define **Tunnel Bypass Rules**: IPs or subnets that should **bypass the VPN** and go directly to the client's local network. The system calculates updated WireGuard `AllowedIPs` that exclude the rule targets and provides a ready-to-use config for the client.

| Target Type | Example | Effect |
|-------------|---------|--------|
| IP | `192.168.169.121` | Traffic to this host bypasses VPN |
| CIDR | `192.168.169.0/24` | Traffic to entire subnet bypasses VPN |
| Domain | `internal.example.com` | Resolved to IP at creation time, then excluded |

#### How it works

1. Admin clicks **Add Rule** in the console: client `uloop`, target `192.168.169.0/24`
2. The system computes `AllowedIPs` = `0.0.0.0/0` minus `192.168.169.0/24` (result: 24 complementary CIDRs)
3. Admin opens **Configure Split Tunnel** and shares the updated config with the client
4. Client imports the new config (or scans the QR code) and reconnects
5. Traffic to `192.168.169.x` now goes directly to the local network; everything else still goes through VPN

#### Applying the config

After creating or modifying rules, click **Configure Split Tunnel** in the console. A step-by-step modal opens with three ways to apply the updated config — pick the one that best matches the client device:

| Tab | Best for | How it works |
|-----|----------|-------------|
| **Download** | Desktop clients (Windows, macOS, Linux) | One-click download of a ready-to-import `.conf` file. Delete the old tunnel in the WireGuard app and import this file as a new tunnel. |
| **QR Code** | Mobile clients (iOS, Android) | Generate a QR code and scan it with the WireGuard app (`+` → **Create from QR code**) to import the tunnel in one tap. |
| **Manual** | Advanced users / troubleshooting | Copy the calculated `AllowedIPs` line (and optionally the full config) to paste into an existing config manually. |

> **Why prefer Download / QR over Manual:** the split-tunnel `AllowedIPs` is a long comma-separated list (often 20–40 CIDRs). Manual editing is error-prone — a single missing comma or a browser line break will silently break routing. The Download and QR paths give the client a clean, valid config that cannot be mis-pasted.

After applying the config, the client must **reconnect** the tunnel (WireGuard reads `AllowedIPs` only at connection time) for the split tunneling to take effect.

---

## Features

### Security
- **Pre-connection 2FA** with TOTP (RFC 6238 compatible)
- **TLS/SSL** with Let's Encrypt auto-renewal or self-signed certificates
- **Rate limiting** at 30 requests per 60 seconds per IP/endpoint
- **ipset-based firewall** for O(1) allowlist lookups (IPv4 + IPv6)
- **Per-client split-tunnel policies** for excluding local IPs, CIDRs, or domains from the VPN tunnel
- **WireGuard handshake monitoring** with 3-second polling for real-time session tracking
- **Comprehensive audit logging** for all authentication events

### Admin Console
- **Dashboard** with real-time statistics, charts, and active session monitoring
- **User management** with pagination, search, and per-client access control
- **Split Tunnel** page with per-client Tunnel Bypass Rules and a config generator (download `.conf`, QR code, or copyable AllowedIPs)
- **Traffic activity** logs with DNS resolution and protocol analysis
- **Bandwidth insights** with per-client daily upload/download tracking
- **Audit trail** for all security events (2FA setup, verification, failures)

### Operations
- **One-command installation** with interactive CLI wizard
- **9+ Linux distributions** supported (Ubuntu, Debian, Fedora, CentOS, Alma, Rocky, Oracle, Arch, Alpine)
- **Systemd integration** with hardened service configuration
- **Client management** via CLI (add, list, revoke, reset 2FA)
- **Configurable log retention** with automatic cleanup
- **Activity logging** with iptables-based traffic capture and DNS enrichment
- **Self-healing watchdog** that detects WireGuard interface flaps, re-asserts portal firewall rules, and auto-restarts the DNS/TLS sniffer
- **Diagnostic `/health` endpoint** exposing WireGuard state, iptables rules, database stats, and watchdog history for monitoring

---

## System Requirements

### Server
- **OS:** Linux with systemd (kernel 5.6+ for built-in WireGuard, or compatible module)
- **Architecture:** x86_64, ARM64
- **RAM:** 512 MB minimum
- **Access:** Root privileges, public IP or domain, open UDP port

### Supported Distributions

| Distribution | Minimum Version |
|--------------|----------------|
| Ubuntu | 18.04 (Bionic) |
| Debian | 10 (Buster) |
| Fedora | 32 |
| CentOS Stream | 8 |
| AlmaLinux | 8 |
| Rocky Linux | 8 |
| Oracle Linux | 8 |
| Arch Linux | Rolling |
| Alpine Linux | 3.14 |

### Client
- Any WireGuard client (Windows, macOS, Linux, iOS, Android)
- A TOTP authenticator app (Google Authenticator, Authy, Microsoft Authenticator, 1Password, Bitwarden)
- A web browser for 2FA verification

---

## Installation

```bash
git clone https://github.com/siyamsarker/WireShield.git
cd WireShield
chmod +x wireshield.sh
sudo ./wireshield.sh
```

The interactive wizard walks you through configuration in clear sections:

| Section | Prompts |
|---------|---------|
| **Network** | Public IP/hostname (auto-detected), public interface |
| **WireGuard** | Interface name, server IPv4/IPv6, UDP port |
| **Client DNS** | Primary and secondary resolvers (default: Cloudflare) |
| **Routing** | AllowedIPs for client traffic routing |
| **SSL/TLS** | Let's Encrypt, self-signed, or disabled |

A review summary is shown before installation begins. All prompts have sensible defaults — press Enter to accept.

### Verify

```bash
sudo wg show                              # WireGuard status
sudo systemctl status wireshield.service   # 2FA service
sudo journalctl -u wireshield.service -f   # Live logs
```

### File Layout

```
/etc/wireguard/
├── wg0.conf                  # WireGuard server configuration
└── params                    # Installation parameters

/etc/wireshield/2fa/
├── config.env                # Service configuration
├── auth.db                   # SQLite database
├── cert.pem                  # SSL certificate
├── key.pem                   # SSL private key
├── app/                      # FastAPI application
├── templates/                # Jinja2 HTML templates
├── static/                   # CSS, JS, fonts
└── .venv/                    # Python virtual environment

/etc/systemd/system/
├── wireshield.service        # 2FA service unit
└── wireshield-2fa-renew.timer  # Let's Encrypt renewal (if applicable)
```

---

## Configuration

Edit `/etc/wireshield/2fa/config.env` and restart the service:

```bash
sudo systemctl restart wireshield.service
```

### Key Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `WS_2FA_SESSION_TIMEOUT` | `1440` | Session lifetime in minutes (24h) |
| `WS_2FA_SESSION_IDLE_TIMEOUT` | `3600` | Handshake freshness threshold in seconds (1h) |
| `WS_2FA_DISCONNECT_GRACE_SECONDS` | `3600` | Grace period after disconnect in seconds (1h) |
| `WS_2FA_RATE_LIMIT_MAX_REQUESTS` | `30` | Max requests per rate limit window |
| `WS_2FA_RATE_LIMIT_WINDOW` | `60` | Rate limit window in seconds |
| `WS_2FA_ACTIVITY_LOG_RETENTION_DAYS` | `30` | Days to retain activity logs |
| `WS_2FA_LOG_LEVEL` | `INFO` | Logging verbosity |
| `WS_2FA_SSL_TYPE` | `self-signed` | `letsencrypt`, `self-signed`, or `disabled` |
| `WS_2FA_DOMAIN` | | Domain name for Let's Encrypt |

### Tuning Examples

```bash
# Extend session to 7 days
WS_2FA_SESSION_TIMEOUT=10080

# More lenient disconnect detection (2 hours)
WS_2FA_SESSION_IDLE_TIMEOUT=7200

# Tighter disconnect detection (10 seconds)
WS_2FA_DISCONNECT_GRACE_SECONDS=10

# Keep activity logs for 90 days
WS_2FA_ACTIVITY_LOG_RETENTION_DAYS=90
```

---

## Usage

### Client Management

All client operations are available through the interactive menu:

```bash
sudo ./wireshield.sh
```

The menu is organized into categories: **Client Management**, **Server Operations**, **Security & Logging**, and **System**. Enter a number to select or `q` to exit.

| # | Option | Description |
|---|--------|-------------|
| 1 | Create Client | Generate WireGuard config and QR code |
| 2 | List Clients | Show all registered VPN clients |
| 3 | Display Client QR | Render config as terminal QR code |
| 4 | Revoke Client | Remove client, sessions, and firewall entries |
| 5 | Clean Up Expired | Remove expired clients automatically |
| 6 | View Status | WireGuard runtime info |
| 7 | Restart VPN | Restart the WireGuard service |
| 8 | Backup Config | Archive /etc/wireguard |
| 9 | Audit Logs | View 2FA authentication events |
| 10 | Remove Client 2FA | Reset 2FA for lost authenticator devices |
| 11 | Activity Logs | Enable/disable logging, set retention, view traffic |
| 12 | Console Access | Toggle admin console access per client |
| 13 | Uninstall | Remove WireShield completely |

### For VPN Users

1. Import the `.conf` file into your WireGuard client and connect
2. Your browser opens the captive portal automatically
3. First time: scan the QR code with your authenticator app, then enter the 6-digit code
4. Returning: enter the current 6-digit code from your authenticator app
5. Access granted. Session valid for 24 hours

### Admin Console

Access the web console at `https://<server-ip>/console` (requires `console_access` permission).

The console provides:
- **Overview** with active users, sessions, bandwidth, and event charts
- **Bandwidth Insights** with per-client upload/download data
- **User Management** with status, IPs, and access control
- **Audit Trail** for security events
- **Traffic Activity** with connection logs, DNS resolution, and filtering
- **Split Tunnel** with Tunnel Bypass Rules — define which local IPs or subnets bypass the VPN for each client, then generate an updated WireGuard config (download `.conf`, QR code, or copyable AllowedIPs)

---

## Architecture

### Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Installer & CLI | Bash | Server setup, client management, firewall config |
| 2FA Service | Python, FastAPI | Captive portal, TOTP, session management |
| Database | SQLite | Users, sessions, audit logs, activity, bandwidth |
| Firewall | iptables, ipset | Zero-trust access control |
| VPN | WireGuard | Encrypted tunnel |
| DNS Sniffer | scapy | IP-to-domain resolution for activity logs |
| Monitors | Background threads | Handshake tracking, ipset sync, HTTP redirect |

### Background Services

| Monitor | Interval | Function |
|---------|----------|----------|
| WireGuard session monitor | 3s | Polls handshakes, tracks bandwidth, revokes stale sessions |
| ipset sync daemon | 60s | Removes clients without active sessions from firewall |
| HTTP redirector | Continuous | Redirects port 80 to HTTPS captive portal |
| Activity log ingestion | 5s | Parses kernel logs into queryable database records |
| Log retention cleanup | Daily | Purges activity logs older than retention period |
| Interface watchdog | 30s | Tracks WireGuard interface state; logs flaps; re-inserts missing `INPUT ACCEPT` rules for ports 80/443 |
| DNS + TLS SNI sniffer | Continuous | Auto-recovering sniffer; waits for `wg0` to come back up before resuming after interface drops |

### API Endpoints

**Authentication:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | 2FA setup or verification page |
| `GET` | `/success` | Post-verification success page |
| `POST` | `/api/setup-start` | Generate TOTP secret and QR code |
| `POST` | `/api/setup-verify` | Verify initial TOTP code during setup |
| `POST` | `/api/verify` | Verify TOTP code for existing users |
| `POST` | `/api/validate-session` | Check session token validity |
| `GET` | `/health` | Diagnostic snapshot: database, WireGuard interface, iptables rules, watchdog state |

**Admin Console:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/console` | Admin dashboard |
| `GET` | `/api/console/users` | User list with pagination and search |
| `GET` | `/api/console/audit-logs` | Audit events with filtering |
| `GET` | `/api/console/activity-logs` | Traffic logs with DNS resolution |
| `GET` | `/api/console/bandwidth-usage` | Per-client bandwidth data |
| `GET` | `/api/console/dashboard-stats` | Dashboard metrics |
| `GET` | `/api/console/dashboard-charts` | Chart visualization data |
| `GET` | `/api/console/policies` | List tunnel bypass rules (optional `?client_filter=<id>`) |
| `POST` | `/api/console/policies` | Create a new tunnel bypass rule (JSON body) |
| `DELETE` | `/api/console/policies/{id}` | Delete a tunnel bypass rule |
| `PATCH` | `/api/console/policies/{id}/toggle` | Enable or disable a tunnel bypass rule |
| `GET` | `/api/console/policies/split-config/{client}` | Get split-tunnel AllowedIPs and config (JSON) for a client |
| `GET` | `/api/console/policies/split-config/{client}/download` | Download the split-tunnel `.conf` file (attachment) |
| `GET` | `/api/console/policies/split-config/{client}/qrcode` | Return a base64 PNG QR code of the split-tunnel config |

---

## SSL/TLS

### Let's Encrypt

Auto-renewal is configured via systemd timer during installation.

```bash
sudo systemctl status wireshield-2fa-renew.timer  # Check timer
sudo certbot renew --dry-run                       # Test renewal
sudo certbot certificates                          # View cert details
```

### Self-Signed

```bash
# Check expiry
sudo openssl x509 -in /etc/wireshield/2fa/cert.pem -noout -dates

# Regenerate (365 days)
sudo openssl req -x509 -newkey rsa:4096 \
  -keyout /etc/wireshield/2fa/key.pem \
  -out /etc/wireshield/2fa/cert.pem \
  -days 365 -nodes -subj "/CN=<your-ip>"
sudo systemctl restart wireshield.service
```

---

## Troubleshooting

### Start here: the `/health` endpoint

Before digging into logs, hit the diagnostic endpoint — it reports the state of every subsystem the portal depends on:

```bash
curl -sk https://<your-server>/health | jq
```

Example response:
```json
{
  "status": "ok",
  "timestamp": "2026-04-19T10:12:34.567Z",
  "database": { "status": "ok", "users": 5, "active_sessions": 2 },
  "wireguard": { "status": "up", "interface": "wg0", "operstate": "up" },
  "iptables_portal": { "80": "present", "443": "present" },
  "watchdog": {
    "iface_state": "up",
    "last_transition": { "from": "down", "to": "up", "at": "..." },
    "portal_rule_fixes": 0
  }
}
```

What each field tells you:

| Field | `"ok"` / `"present"` means | Problem if not |
|-------|----------------------------|----------------|
| `status` | All subsystems healthy | `"degraded"` = at least one check below failed |
| `database` | SQLite reachable, schema intact | Service won't be able to verify codes or track sessions |
| `wireguard.status` | Kernel reports `wg0` as up | VPN clients cannot connect or reach captive portal |
| `iptables_portal.80/443` | INPUT ACCEPT rule exists | Portal is firewall-blocked even though uvicorn is listening |
| `watchdog.portal_rule_fixes` | `0` means stable | Non-zero = the watchdog had to re-add stripped firewall rules (wg-quick flaps) |
| `watchdog.last_transition` | `null` means no flaps | Shows the most recent wg0 up/down transition for outage correlation |

### 1. No Internet After 2FA Verification

**Symptoms:** 2FA verification succeeds, browser shows success page, but no internet access.

**Diagnose:**
```bash
# Check if client IP is in the allowlist
sudo ipset list ws_2fa_allowed_v4 | grep <client-ip>

# Verify firewall rule order (allowlist MUST come before portal chain)
sudo iptables -L FORWARD -n --line-numbers | grep wg0

# Check NAT/masquerading is active
sudo iptables -t nat -L POSTROUTING -n -v

# Check WireGuard handshake for this client
sudo wg show | grep -A 5 <client-public-key>

# Check recent session logs
sudo journalctl -u wireshield.service -n 50 | grep -i session
```

**Solutions:**
- If client IP is missing from ipset, manually add: `sudo ipset add ws_2fa_allowed_v4 <client-ip> -exist`
- If firewall rule order is wrong, the allowlist rule must appear before the portal chain. Restart the service: `sudo systemctl restart wireshield.service`
- If MASQUERADE rule is missing, check WireGuard PostUp/PostDown in `/etc/wireguard/wg0.conf`

### 2. Captive Portal Not Reachable

**Symptoms:** Browser cannot load `https://<vpn-domain>`, connection timeout or refused.

**Diagnose:**
```bash
# Check service status
sudo systemctl status wireshield.service

# Check if ports are listening
sudo ss -tlnp | grep -E ':80|:443'

# Check SSL certificate exists
ls -lh /etc/wireshield/2fa/cert.pem /etc/wireshield/2fa/key.pem

# Check firewall INPUT rules for portal ports
sudo iptables -L INPUT -n | grep -E '80|443'

# Check DNAT rules (for clients behind VPN)
sudo iptables -t nat -L PREROUTING -n -v | grep -E '80|443'
```

**Solutions:**
- Restart the 2FA service: `sudo systemctl restart wireshield.service`
- If SSL cert is missing, regenerate: `sudo /etc/wireshield/2fa/generate-certs.sh`
- Check service logs for startup errors: `sudo journalctl -u wireshield.service -n 100`

### 3. Sessions Expiring Too Quickly

**Symptoms:** Need to re-verify 2FA every few minutes despite active connection.

**Diagnose:**
```bash
# Check current timeout settings
grep -E "IDLE_TIMEOUT|DISCONNECT_GRACE" /etc/wireshield/2fa/config.env

# Check WireGuard handshake frequency
sudo wg show wg0 | grep "latest handshake"

# Check monitor logs
sudo journalctl -u wireshield.service | grep -i "stale\|expired\|revok"
```

**Solutions:**
- Increase idle timeout in `/etc/wireshield/2fa/config.env`:
  ```bash
  WS_2FA_SESSION_IDLE_TIMEOUT=7200  # 2 hours
  sudo systemctl restart wireshield.service
  ```
- Enable PersistentKeepalive in the client `.conf` file to prevent handshake staleness:
  ```ini
  [Peer]
  PersistentKeepalive = 25
  ```
- Increase disconnect grace period:
  ```bash
  WS_2FA_DISCONNECT_GRACE_SECONDS=7200  # 2 hours
  sudo systemctl restart wireshield.service
  ```

### 4. TOTP Codes Not Working

**Symptoms:** 6-digit code is always rejected as invalid.

**Diagnose:**
- Verify device clock is synchronized (TOTP relies on accurate UTC time)
- Wait for the next 30-second code rotation and try the new code
- Confirm you're using the correct authenticator entry for this VPN

**Solutions:**
- Sync device time: on Android/iOS, enable automatic date & time in settings
- If authenticator entry is lost, admin can reset 2FA:
  ```bash
  sudo ./wireshield.sh
  # Select: "Remove Client 2FA"
  # User will be prompted to re-enroll on next connection
  ```

### 5. Let's Encrypt Renewal Failures

**Symptoms:** Certificate expiring soon, renewal timer shows failed status.

**Diagnose:**
```bash
# Check renewal service logs
sudo journalctl -u wireshield-2fa-renew.service

# Test renewal (dry run)
sudo certbot renew --dry-run

# Check DNS resolves to this server
nslookup <your-domain>
```

**Solutions:**
- Ensure ports 80/443 are accessible from the internet
- Force renewal:
  ```bash
  sudo systemctl stop wireshield.service
  sudo certbot renew --force-renewal
  sudo systemctl start wireshield.service
  ```

### 6. Local Network Unreachable While on VPN

**Symptoms:** Client is connected to the VPN but cannot reach local resources like `192.168.169.121:8000`.

**Cause:** With `AllowedIPs = 0.0.0.0/0`, all traffic goes through the VPN tunnel — including traffic to local IPs. If the VPN server is cloud-hosted (e.g. AWS), it has no route to your private office network, so the traffic is silently dropped.

**Solution — Split tunneling via Tunnel Bypass Rules:**
1. Open the WireShield console → **Split Tunnel** (under *Network* in the sidebar)
2. Click **Add Rule** → set Client to the affected user, Target to the local subnet (e.g. `192.168.169.0/24`)
3. Click **Configure Split Tunnel** → pick the most reliable apply method for the client device:
   - **Download** — click *Download .conf file*, then in the WireGuard app delete the old tunnel and import the downloaded file as a new one.
   - **QR Code** — click *Generate QR Code*, then on mobile tap **+ → Create from QR code** and scan it.
   - **Manual** (not recommended for long exclusions — use only if Download/QR aren't possible): copy the `AllowedIPs` line and replace it in the existing config.
4. Reconnect the VPN so WireGuard picks up the new `AllowedIPs`

**Verify the config is correct:**
```bash
# The client's WireGuard config should NOT contain 0.0.0.0/0
# Instead it should have multiple CIDRs that exclude the local subnet:
grep AllowedIPs /path/to/your/wireguard.conf
# Expected: AllowedIPs = 0.0.0.0/1,128.0.0.0/2,...  (NOT 0.0.0.0/0)
```

**Diagnose if it's still not working:**
```bash
# On the client machine, verify the WireGuard route table excludes the target
# The local IP should NOT appear in the WireGuard routing table
wg show
ip route get 192.168.169.121
# Expected: "192.168.169.121 via <local-gateway>" (NOT "dev wg0")
```

**Common mistakes:**
- **Forgot to reconnect** after updating AllowedIPs — WireGuard applies AllowedIPs at connection time
- **Wrong target** — if you excluded `192.168.169.121/32` but the service is on `192.168.169.122`, that IP still goes through VPN
- **Using a CIDR is safer** — `192.168.169.0/24` covers the whole subnet instead of individual hosts

### 7. Database Issues

**Symptoms:** Service won't start, SQLite errors in logs.

**Diagnose:**
```bash
# Check database integrity
sudo sqlite3 /etc/wireshield/2fa/auth.db "PRAGMA integrity_check;"

# Check database file permissions
ls -la /etc/wireshield/2fa/auth.db
```

**Solutions:**
- If corrupted, backup and restart (tables are auto-recreated):
  ```bash
  sudo cp /etc/wireshield/2fa/auth.db /etc/wireshield/2fa/auth.db.backup
  sudo rm /etc/wireshield/2fa/auth.db
  sudo systemctl restart wireshield.service
  ```
- If permission issue: `sudo chown root:root /etc/wireshield/2fa/auth.db`

### General Diagnostics

```bash
# Real-time service logs
sudo journalctl -u wireshield.service -f

# Monitor WireGuard handshakes
watch -n 2 'sudo wg show'

# Monitor ipset changes
watch -n 5 'sudo ipset list ws_2fa_allowed_v4'

# View active sessions in database
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT client_id, device_ip, expires_at FROM sessions WHERE expires_at > datetime('now');"

# View recent audit events
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT timestamp, client_id, action, status FROM audit_log ORDER BY timestamp DESC LIMIT 20;"
```

---

## Development

### Setup

```bash
cd WireShield/console-server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

### Tests

```bash
cd console-server
pytest -v
```

### Project Structure

```
WireShield/
├── wireshield.sh                 # Installer and management CLI
├── LICENSE
├── README.md
├── assets/
│   └── logo.svg
├── tests/
│   ├── test_rate_limit.py
│   ├── test_activity_logs_api.py
│   ├── test_bandwidth_usage_api.py
│   ├── test-2fa-access.sh
│   └── test-integration.sh
└── console-server/
    ├── run.py                    # Service entry point
    ├── requirements.txt
    ├── wireshield.service        # Systemd unit file
    ├── 2fa-helper.sh
    ├── generate-certs.sh
    ├── app/
    │   ├── main.py               # FastAPI application
    │   ├── templates.py          # Template rendering
    │   ├── core/
    │   │   ├── config.py         # Environment configuration
    │   │   ├── database.py       # SQLite schema and migrations
    │   │   ├── security.py       # Auth, rate limiting, ipset
    │   │   ├── policies.py       # Split-tunnel rules: AllowedIPs calculator + config generator
    │   │   ├── tasks.py          # Background monitors
    │   │   └── sniffer.py        # DNS packet capture
    │   └── routers/
    │       ├── auth.py           # 2FA endpoints
    │       ├── console.py        # Admin console endpoints
    │       └── health.py         # Health check
    ├── templates/                # Jinja2 HTML templates
    │   ├── base.html
    │   ├── console.html
    │   ├── 2fa_setup.html
    │   ├── 2fa_verify.html
    │   ├── success.html
    │   └── access_denied.html
    └── static/
        ├── css/                  # Console stylesheets
        ├── js/                   # Dashboard, tables, charts
        └── fonts/                # Inter font family
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| VPN | WireGuard |
| Backend | Python 3.8+, FastAPI 0.104, Uvicorn |
| Database | SQLite |
| Frontend | Jinja2, vanilla JavaScript, Chart.js |
| Auth | pyotp (TOTP), pyqrcode |
| Firewall | iptables, ip6tables, ipset |
| DNS | scapy, tldextract |
| Service | systemd |
| SSL | Let's Encrypt (certbot), OpenSSL |

---

## Contributing

Contributions are welcome. To get started:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

### Guidelines

- Follow the existing code style and conventions
- Add tests for new features
- Test on at least one supported distribution before submitting
- Keep PRs focused on a single change

### Reporting Issues

- **Bugs:** Open an issue at [github.com/siyamsarker/WireShield/issues](https://github.com/siyamsarker/WireShield/issues)
- **Security vulnerabilities:** Report privately via [GitHub Security Advisories](https://github.com/siyamsarker/WireShield/security/advisories)

---

## License

WireShield is licensed under the [GNU General Public License v3.0](LICENSE).

You are free to use, modify, and distribute this software. Modified versions must be released under the same license with source code disclosed.

