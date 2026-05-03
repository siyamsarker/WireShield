<div align="center">

<img src="assets/logo.svg" alt="WireShield Logo" width="140" height="140">

# WireShield

**Zero-trust WireGuard VPN with pre-connection two-factor authentication**

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![WireGuard](https://img.shields.io/badge/WireGuard-Compatible-88171a.svg)](https://www.wireguard.com/)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776ab.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688.svg)](https://fastapi.tiangolo.com/)

WireShield deploys a WireGuard VPN with mandatory TOTP-based two-factor authentication at the connection layer. Every client must verify through a captive portal before any traffic is allowed through the tunnel. A built-in agent system lets remote Linux servers register as WireGuard peers — authenticated VPN clients can then route traffic to private LANs on those servers with no extra client-side configuration.

[Quick Start](#quick-start) &bull; [How It Works](#how-it-works) &bull; [Features](#features) &bull; [Installation](#installation) &bull; [Configuration](#configuration) &bull; [Usage](#usage) &bull; [Agents](#agents) &bull; [Troubleshooting](#troubleshooting) &bull; [Contributing](#contributing)

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

### VPN + 2FA Flow

Every VPN client must pass a TOTP challenge through the captive portal before any traffic is forwarded through the tunnel.

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
│  │   5. Full internet + agent LAN access      │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

### Agent Network Extension

Agents are Go daemons deployed on remote Linux servers. Each agent dials outbound into the WireShield VPN as a WireGuard peer and advertises its local LAN CIDRs. The server adds those CIDRs to the agent's `AllowedIPs`, so any authenticated VPN client can reach them without any client-side changes.

```
┌──────────────────────┐       ┌────────────────────────────────────────────┐
│     VPN Client       │       │           WireShield Server                │
│     (WireGuard)      │◄─────►│                  (wg0)                     │
└──────────────────────┘  WG   │                                            │
                        tunnel │  wg0 peer table:                           │
                               │  ┌──────────────────────────────────────┐  │
                               │  │ VPN Client   AllowedIPs 10.8.0.2/32  │  │
                               │  │ Agent        AllowedIPs 10.8.0.200/32│  │
                               │  │              + 10.50.0.0/24          │  │
                               │  │              (advertised LAN CIDRs)  │  │
                               │  └──────────────────────────────────────┘  │
                               └──────────────────────┬─────────────────────┘
                                                      │
                                          outbound WireGuard tunnel
                                                 (wg-agent0)
                                                      │
                                                      ▼
                               ┌────────────────────────────────────────────┐
                               │          Remote Linux Server               │
                               │                                            │
                               │   wireshield-agent                         │
                               │   · dials outbound, no open inbound ports  │
                               │   · heartbeat to server every 30 s         │
                               │   · polls revocation every 60 s            │
                               │   · token-enrolled, managed by systemd     │
                               │                                            │
                               │   Private LAN: 10.50.0.0/24                │
                               └────────────────────────────────────────────┘
```

Traffic from any authenticated VPN client destined for `10.50.0.0/24` is forwarded through the server's WireGuard peer for the agent, which NATs it into the remote LAN. No routes, no config changes, no restarts on the client side — the server applies `wg syncconf` live.

### Session Rules

| Rule | Behavior |
|------|----------|
| **Absolute timeout** | Sessions expire after 24 hours regardless of activity |
| **Disconnect grace** | If the VPN disconnects, the session survives for 1 hour |
| **Reconnect < 1h** | Instant access, no re-authentication required |
| **Reconnect > 1h** | Session revoked, 2FA required again |
| **Strict revocation** | Expired sessions immediately block all traffic |

---

## Features

### Security
- **Pre-connection 2FA** with TOTP (RFC 6238 compatible)
- **TLS/SSL** with Let's Encrypt auto-renewal or self-signed certificates
- **Rate limiting** at 30 requests per 60 seconds per IP/endpoint
- **ipset-based firewall** for O(1) allowlist lookups (IPv4 + IPv6)
- **Session-gated portal pages** — `/success`, `/console` and user APIs reject callers without a non-expired 2FA session
- **WireGuard handshake monitoring** with 3-second polling for real-time session tracking
- **Comprehensive audit logging** for all authentication events

### Admin Console
- **Dashboard** with real-time statistics, charts, and active session monitoring
- **User management** with pagination, search, in-browser **Create / Revoke** actions and per-user **Download `.conf`** — no SSH required
- **Per-client access control** (admin console permission, expiry dates)
- **Traffic activity** logs with DNS resolution and protocol analysis
- **Bandwidth insights** with per-client daily upload/download tracking
- **Audit trail** for all security events (2FA setup, verification, failures)

### Operational Features
- **One-command installation** with interactive CLI wizard
- **9+ Linux distributions** supported (Ubuntu, Debian, Fedora, CentOS, Alma, Rocky, Oracle, Arch, Alpine)
- **Systemd integration** with hardened service configuration
- **Client management** via CLI (add, list, revoke, reset 2FA)
- **Configurable log retention** with automatic cleanup
- **Activity logging** with iptables-based traffic capture and DNS enrichment
- **Self-healing watchdog** that detects WireGuard interface flaps, re-asserts portal firewall rules, and auto-restarts the DNS/TLS sniffer
- **Diagnostic `/health` endpoint** exposing WireGuard state, iptables rules, database stats, watchdog history, and agent fleet stats for monitoring
- **Agent fleet** — deploy WireShield agent daemons on remote Linux servers to let VPN clients reach private LANs behind those servers (reverse-connection, outbound-only, token-enrolled)

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

### Prerequisites

Before running the installer, ensure the following are in place:

| Requirement | Details |
|-------------|---------|
| **Operating system** | Linux with systemd — see [Supported Distributions](#supported-distributions) |
| **Privileges** | Root or `sudo` access during installation |
| **Inbound ports** | UDP `51820` (WireGuard, configurable) · TCP `80` and `443` (captive portal) |
| **Public address** | A static public IP or a domain name pointing to the server |
| **Domain name** | Required only for Let's Encrypt; a bare IP works fine with self-signed TLS |
| **Packages** | `git` and `curl` — pre-installed on most distributions |

### Step 1 — Clone and run the installer

```bash
git clone https://github.com/siyamsarker/WireShield.git
cd WireShield
chmod +x wireshield.sh
sudo ./wireshield.sh
```

Select **Install WireShield** from the main menu. The interactive wizard walks through each component in order:

| Section | What it configures |
|---------|--------------------|
| **Network** | Public IP/hostname (auto-detected), public interface |
| **WireGuard** | Interface name, server IPv4/IPv6 subnet, UDP listen port |
| **Client DNS** | Primary and secondary resolvers pushed to clients (default: Cloudflare) |
| **Routing** | `AllowedIPs` controlling what traffic routes through the tunnel |
| **SSL/TLS** | Let's Encrypt (certbot), self-signed certificate, or disabled |

A review summary is displayed before anything is written to disk. All prompts have sensible defaults — press Enter to accept them.

The installer sets up WireGuard, configures iptables/ipset firewall rules, generates SSL certificates, deploys the 2FA FastAPI service under systemd, and writes all configuration to `/etc/wireshield/`.

### Step 2 — Verify the installation

```bash
sudo wg show                                         # WireGuard interface + peers
sudo systemctl status wireshield.service             # 2FA portal service running?
sudo journalctl -u wireshield.service -f             # Live service logs
curl -sk https://localhost/health | jq .status       # Expect "ok"
```

The `/health` endpoint returns a JSON snapshot of every subsystem. If `status` is `"degraded"`, check the individual fields (`database`, `wireguard`, `iptables_portal`) to identify which component needs attention.

### Step 3 — Add your first VPN client

```bash
sudo ./wireshield.sh   # Select option 1 — Create Client
```

Enter a client ID when prompted (e.g. `alice`). The wizard generates a WireGuard `.conf` file and a QR code at:

```
/etc/wireshield/clients/alice.conf
```

Transfer it to the client device via `scp`, email, or by scanning the QR code printed directly in the terminal.

### Step 4 — Enable admin console access

By default no client has admin console access. Grant it to a specific client:

```bash
sudo ./wireshield.sh   # Select option 12 — Console Access
```

Enter the `client_id` (e.g. `alice`) when prompted. Once granted, that client can reach `https://<server-ip>/console` — but only while holding an active 2FA session (connect VPN → complete captive portal → browse to `/console`).

### Step 5 — Connect the VPN client

1. Import the `.conf` file into any WireGuard app (Windows, macOS, Linux, iOS, Android) or scan the QR code.
2. Toggle the VPN tunnel on.
3. Open a browser — you will be redirected to the captive portal automatically.
4. **First connection:** the portal shows a QR code; scan it with your authenticator app (Google Authenticator, Authy, etc.), then enter the 6-digit code.
5. **Subsequent connections:** enter the current 6-digit TOTP code directly.
6. Access granted. Session stays valid for 24 hours.

### File Layout

```
/etc/wireguard/
├── wg0.conf                  # WireGuard server configuration (VPN clients + agent peers)
└── params                    # Installation parameters

/etc/wireshield/2fa/
├── config.env                # Service configuration (WS_2FA_* and WS_AGENT_* variables)
├── auth.db                   # SQLite database (users, sessions, agents, heartbeats, audit)
├── cert.pem                  # SSL certificate
├── key.pem                   # SSL private key
├── app/                      # FastAPI application
├── templates/                # Jinja2 HTML templates
├── static/                   # CSS, JS, fonts
└── .venv/                    # Python virtual environment

/etc/wireshield/clients/       # Generated VPN client .conf files (mode 0700/0600)
└── <client>.conf             # Written by CLI (ws_add_client) and console "Create User"

/etc/wireshield/agent-binaries/  # Pre-built Go agent binaries served by the API
├── wireshield-agent_linux_amd64        # Static binary for x86_64
├── wireshield-agent_linux_amd64.sha256
├── wireshield-agent_linux_arm64        # Static binary for ARM64
├── wireshield-agent_linux_arm64.sha256
└── version.json                        # Auto-update manifest

/etc/systemd/system/
├── wireshield.service        # 2FA + admin console service unit
└── wireshield-2fa-renew.timer  # Let's Encrypt renewal timer (if applicable)
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
| `WS_AGENT_TOKEN_TTL_SECONDS` | `3600` | Enrollment token lifetime (1 hour) |
| `WS_AGENT_IP_START` | `200` | First WG IPv4 octet reserved for agents (inside the server subnet) |
| `WS_AGENT_IP_END` | `254` | Last WG IPv4 octet reserved for agents |
| `WS_AGENT_HEARTBEAT_RETENTION_HOURS` | `48` | Hours of `agent_heartbeats` rows to retain before housekeeping prunes them |
| `WS_AGENT_OFFLINE_AFTER_SECONDS` | `90` | Seconds without a heartbeat before an agent is reported as `online=false` in `/health` |
| `WS_AGENT_BINARY_DIR` | `/etc/wireshield/agent-binaries` | Server-side directory holding pre-built Go-agent binaries + SHA-256 sidecars, populated by `make -C agent install` |

### Tuning Examples

**Session and portal:**

```bash
# Extend session lifetime to 7 days
WS_2FA_SESSION_TIMEOUT=10080

# More lenient disconnect detection (2 hours grace)
WS_2FA_SESSION_IDLE_TIMEOUT=7200

# Tighter disconnect detection (10 seconds grace)
WS_2FA_DISCONNECT_GRACE_SECONDS=10

# Keep activity logs for 90 days instead of 30
WS_2FA_ACTIVITY_LOG_RETENTION_DAYS=90
```

**Agent fleet:**

```bash
# Shorten enrollment token TTL to 15 minutes for tighter security
WS_AGENT_TOKEN_TTL_SECONDS=900

# Mark agents offline faster — useful if heartbeat interval is tuned down
WS_AGENT_OFFLINE_AFTER_SECONDS=45

# Reserve a different IP range for agents (e.g. .150–.199 within the server subnet)
WS_AGENT_IP_START=150
WS_AGENT_IP_END=199

# Keep 7 days of heartbeat history for the metrics sparklines
WS_AGENT_HEARTBEAT_RETENTION_HOURS=168

# Serve agent binaries from a custom directory
WS_AGENT_BINARY_DIR=/opt/wireshield/agent-binaries
```

---

## SSL/TLS

The installer configures TLS during setup based on your choice (Let's Encrypt, self-signed, or disabled). Use the commands below for ongoing certificate operations.

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

### Using the Admin Console

Access the web console at `https://<server-ip>/console`. Two conditions must both hold:

1. The client must have `console_access = 1` in the users table.
2. The client must have an **active (non-expired) 2FA session**. Expired sessions are denied access even if `console_access = 1`, so an idle admin has to re-verify TOTP at the captive portal before they can reach the console again.

The console provides:
- **Overview** with active users, sessions, bandwidth, and event charts
- **Bandwidth Insights** with per-client upload/download data
- **User Management** with status, IPs, access control — plus in-browser **Create User**, per-row **Download Config** (`.conf` file) and **Revoke** buttons
- **Audit Trail** for security events
- **Traffic Activity** with connection logs, DNS resolution, and filtering

---

## Architecture

### System Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Installer & CLI | Bash | Server setup, client management, firewall config, agent binary build |
| 2FA Service | Python, FastAPI | Captive portal, TOTP, session management, admin console API |
| Admin Console | Vanilla JavaScript, Chart.js | Web UI for users, sessions, agents, bandwidth, activity logs |
| Database | SQLite | Users, sessions, audit logs, activity, bandwidth, agents, heartbeats, ACL grants |
| Firewall | iptables, ipset | Zero-trust access control + per-user agent allowlist enforcement |
| VPN | WireGuard | Encrypted tunnel for both VPN clients and agent peers |
| DNS Sniffer | scapy | IP-to-domain resolution for activity logs |
| Monitors | Background threads | Handshake tracking, ipset sync, HTTP redirect, agent ACL sync, watchdog |
| Agent daemon | Go (static binary) | Remote-LAN gateway: outbound WireGuard peer + heartbeat + self-update |

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
| Agent housekeeping | 1h | Purges expired/used enrollment tokens and prunes `agent_heartbeats` older than the retention window |
| Agent ACL iptables sync | 30s | Rebuilds the `WS_AGENT_ACL` iptables chain to match the current per-user allowlist for all restricted agents; also triggered immediately on every grant/revoke |

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
| `GET` | `/health` | Diagnostic snapshot: database, WireGuard interface, iptables rules, watchdog state, agent ACL chain |

**Admin Console:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/console` | Admin dashboard |
| `GET` | `/api/console/users` | User list with pagination and search |
| `POST` | `/api/console/users` | Create a new WireGuard client (JSON body: `client_id`, `expiry_days?`) |
| `GET` | `/api/console/users/{client}/config` | Download the client's `.conf` file |
| `GET` | `/api/console/users/{client}/qrcode` | Return a base64 PNG QR code of the client config |
| `DELETE` | `/api/console/users/{client}` | Revoke a client (remove peer, delete config, clear sessions) |
| `GET` | `/api/console/audit-logs` | Audit events with filtering |
| `GET` | `/api/console/activity-logs` | Traffic logs with DNS resolution |
| `GET` | `/api/console/bandwidth-usage` | Per-client bandwidth data |
| `GET` | `/api/console/dashboard-stats` | Dashboard metrics |
| `GET` | `/api/console/dashboard-charts` | Chart visualization data |
| `POST` | `/api/console/agents` | Register a new agent; returns a single-use enrollment token + install command |
| `GET` | `/api/console/agents` | List agents (add `?include_revoked=true` to include revoked rows) |
| `GET` | `/api/console/agents/{id}` | Agent detail (preshared key is redacted) |
| `PATCH` | `/api/console/agents/{id}` | Update advertised CIDRs or description |
| `DELETE` | `/api/console/agents/{id}` | Revoke an agent (removes its WG peer + marks DB row as revoked) |
| `POST` | `/api/console/agents/{id}/rotate-token` | Reissue an enrollment token for a `pending` agent |
| `GET` | `/api/console/agents/{id}/metrics` | Time-bucketed RX/TX deltas + uptime % from heartbeats |
| `GET` | `/api/console/agents/{id}/access` | Read `is_restricted` flag + per-user allowlist |
| `POST` | `/api/console/agents/{id}/access` | Grant a user (body: `{client_id}`) — triggers immediate iptables sync |
| `DELETE` | `/api/console/agents/{id}/access/{client_id}` | Remove a user from the allowlist |

**Agent Public API** (called by the agent daemon, not by humans):

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/agents/enroll` | Exchange a single-use token for a WG peer config (public/keyless endpoint, rate-limited) |
| `POST` | `/api/agents/heartbeat` | Periodic liveness + bandwidth report (auth: WG tunnel source IP) |
| `GET` | `/api/agents/revocation-check` | Agent polls this to self-disable when revoked (auth: bearer token) |
| `GET` | `/api/agents/install` | **Legacy** Bash installer (kept for backward compatibility) |
| `GET` | `/api/agents/install-go` | Bash bootstrap that downloads the Go binary |
| `GET` | `/api/agents/binary/{arch}` | Pre-built agent binary (`linux-amd64`, `linux-arm64`) |
| `GET` | `/api/agents/binary/{arch}.sha256` | Sidecar SHA-256 checksum for integrity verification |
| `GET` | `/api/agents/unit` | systemd unit file (`wireshield-agent.service`) |
| `GET` | `/api/agents/version` | Version manifest used by `--auto-update` agents |

---

## Agents

Agents are statically-linked Go daemons deployed on remote Linux servers. They connect **outbound** to the WireShield VPN and register themselves as a special WireGuard peer whose `AllowedIPs` include the LAN CIDRs they advertise. Any VPN client can then route traffic for those CIDRs through the agent, with the VPN server enforcing the same zero-trust policies. Agents are enrolled with single-use, IP-bound tokens (SHA-256 hashed at rest) and authenticated on every heartbeat by matching the decrypted tunnel's source IP to the allocated WG address.

### How traffic flows: User → WireShield → Agent → Local LAN

```
VPN Client (user laptop)          WireShield Server             Agent Host              Local LAN
192.168.1.x / 10.66.66.50         47.x.x.x (public)            10.66.66.200            192.168.169.0/24
        │                                │                            │                       │
        │  1. WireGuard tunnel           │                            │                       │
        │◄──────────────────────────────►│                            │                       │
        │                                │                            │                       │
        │  2. curl http://192.168.169.5  │                            │                       │
        │──────────────────────────────► │                            │                       │
        │                                │ wg0 peer AllowedIPs for    │                       │
        │                                │ agent includes             │                       │
        │                                │ 192.168.169.0/24 →         │                       │
        │                                │ kernel routes packet to    │                       │
        │                                │ agent peer (10.66.66.200)  │                       │
        │                                │──────────────────────────► │                       │
        │                                │  3. WireGuard tunnel       │                       │
        │                                │     (agent's wg-agent0)    │ ip_forward=1          │
        │                                │                            │ FORWARD ACCEPT        │
        │                                │                            │ MASQUERADE            │
        │                                │                            │──────────────────────►│
        │                                │                            │  4. Forwarded packet  │
        │                                │                            │     src: agent LAN IP │
        │◄─────────────────────────────────────────────────────────────────────────────────────
        │                   5. Response travels the same path in reverse
```

**What each component does:**

| Component | Role |
|---|---|
| **WireShield server** | Terminates the client tunnel. Routes packets destined for an agent's advertised CIDRs to that agent's WireGuard peer (via kernel routing — the agent's peer entry has `AllowedIPs = <wg-ip>/32, <LAN-CIDRs>`). |
| **Agent (wg-agent0)** | Maintains a persistent outbound WireGuard tunnel to the server. Accepts packets from the VPN subnet, forwards them to the LAN via `ip_forward=1`, and masquerades the source with iptables POSTROUTING so LAN hosts reply to the agent's LAN IP. |
| **VPN client** | Sends all traffic through the WireGuard tunnel (`AllowedIPs = 0.0.0.0/0`). No special routes or configuration needed — the server handles all routing decisions. |

**iptables rules on the agent host** (written to `/etc/wireguard/wg-agent0.conf` as `PostUp`/`PreDown`):

```
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg-agent0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg-agent0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE
PreDown = iptables -D FORWARD -i wg-agent0 -j ACCEPT
PreDown = iptables -D FORWARD -o wg-agent0 -j ACCEPT
PreDown = iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE
```

**CIDR auto-sync:** When an admin updates an agent's advertised CIDRs via the console, the change is applied server-side immediately (wg0.conf peer `AllowedIPs` updated + `wg syncconf`). On the next heartbeat (within 30 seconds), the agent daemon receives the new CIDRs, calls `iptables` to apply them live, and rewrites `/etc/wireguard/wg-agent0.conf` so they persist after a reboot — no manual intervention required.

**Advertised LAN CIDRs are required** when registering an agent. They cannot be left empty because without them the server has no CIDRs to route to the agent, the agent writes no iptables rules, and LAN access is silently broken.

### Step 1 — Publish agent binaries on the VPN server (one-time setup)

**Done automatically by `sudo ./wireshield.sh`.** The installer:

1. Detects whether Go 1.22+ is already on the server and uses it if so
2. Otherwise downloads the official Go 1.22 tarball from go.dev (or `apk add go` on Alpine)
3. Cross-compiles `wireshield-agent` for `linux-amd64` and `linux-arm64`
4. Publishes the binaries + SHA-256 sidecars to `/etc/wireshield/agent-binaries/`
5. Marks `/etc/wireshield/.go-installed-by-wireshield` so the uninstaller knows to clean Go up

The whole step adds ~30 seconds to a fresh install. **Skip to Step 2.**

To rebuild manually (e.g. after pulling new agent code):

```bash
cd WireShield
make -C agent dist
sudo make -C agent install AGENT_BINARY_DIR=/etc/wireshield/agent-binaries
```

To skip the agent build entirely during install (useful for headless environments without internet access to go.dev):

```bash
WS_SKIP_AGENT_BUILD=1 sudo ./wireshield.sh
```

This populates `/etc/wireshield/agent-binaries/` with:

```
wireshield-agent_linux_amd64
wireshield-agent_linux_amd64.sha256
wireshield-agent_linux_arm64
wireshield-agent_linux_arm64.sha256
version.json
```

> **No Go available?** Use the [legacy Bash installer](#legacy-installer-compatibility) instead — it requires no build step and works on any enrolled agent.

### Step 2 — Register the Agent in the Admin Console

1. Open `https://<server-ip>/console` in your browser and complete 2FA.
2. Click **Agents** in the left sidebar.
3. Click **Register Agent**.
4. Fill in the form:
   - **Name** — a short, unique identifier (e.g. `branch-office-01`)
   - **Description** — optional free text
   - **Advertised CIDRs** — the LAN subnets reachable through this agent, one per line (e.g. `10.50.0.0/24`)
5. Click **Register**.

The console displays a one-time install command. **Copy it immediately** — it will not be shown again. If it expires (1-hour TTL), use the **Reissue token** button on the pending agent row.

### Step 3 — Run the Install Command on the Remote Server

SSH into the remote Linux server as root and paste the install command from Step 2. It looks like:

```bash
curl -sSL https://<server-ip>/api/agents/install-go | \
  sudo TOKEN=<enrollment-token> WIRESHIELD_SERVER=https://<server-ip> bash
```

The bootstrap script automatically:

1. Detects the CPU architecture (`amd64` or `arm64`)
2. Installs WireGuard tools if missing (supports `apt`, `dnf`, `yum`, `pacman`, `apk`)
3. Downloads the `wireshield-agent` binary and verifies its SHA-256 checksum
4. Runs `wireshield-agent enroll` — generates a Curve25519 keypair, exchanges the enrollment token for a WireGuard peer config, and writes `/etc/wireguard/wg-agent0.conf`
5. Brings up the `wg-agent0` interface and enables `wireshield-agent.service` under systemd

The entire process takes under 60 seconds on a standard server.

### Step 4 — Verify the Connection

**On the remote agent host:**

```bash
# Check that the systemd service is running
sudo systemctl status wireshield-agent.service

# Print current enrollment state and WireGuard interface info
wireshield-agent status

# Confirm the tunnel is up and exchanging handshakes with the VPN server
sudo wg show wg-agent0
```

**In the admin console:**

The agent row in the **Agents** tab changes from **Pending** to **Enrolled** within 30 seconds of the first heartbeat. The online indicator turns green and the last-seen timestamp updates every 30 seconds.

**On the VPN server:**

```bash
# Confirm the agent peer appears with the advertised CIDRs in AllowedIPs
sudo wg show wg0
```

VPN clients can now route traffic to the advertised CIDRs through the agent. No configuration changes are needed on the client side — routing is enforced server-side via `wg syncconf`.

---

### Uninstalling an Agent

A full agent removal is a two-step process: local teardown on the agent host, then server-side revocation in the admin console.

**Step 1 — run `uninstall` on the agent host (as root):**

```bash
sudo wireshield-agent uninstall
```

This single command performs a complete local teardown in order:

| Step | What happens |
|------|--------------|
| 1 | Stops and disables `wireshield-agent.service` (the heartbeat daemon) |
| 2 | Stops and disables `wg-quick@wg-agent0` and removes `/etc/wireguard/wg-agent0.conf` |
| 3 | Deletes `/etc/wireshield-agent/` (config.json + private.key) |
| 4 | Removes `/etc/systemd/system/wireshield-agent.service` |
| 5 | Runs `systemctl daemon-reload` |
| 6 | Removes `/usr/local/bin/wireshield-agent` |

Every step is idempotent — running `uninstall` on an already-uninstalled host is safe.

To keep the binary on disk (e.g. for immediate re-enrollment):

```bash
sudo wireshield-agent uninstall --keep-binary
```

**Step 2 — revoke in the admin console:**

Open `/console` → **Agents** → click **Delete** on the agent row. This removes the WireGuard peer from `wg0.conf`, marks the DB row as revoked, and stops the server accepting heartbeats from that enrollment. Without this step the agent's WireGuard slot and IP remain reserved on the server.

> **Order matters:** run `uninstall` on the host *before* or *after* console revocation — both orders work. If you revoke from the console first, the agent daemon will detect the revocation on its next poll and shut down on its own. If you `uninstall` first, no heartbeats will arrive so the server simply sees the agent go offline; the console revocation then cleans up the server side.

---

### Managing Agents from the Console

The admin dashboard ships an **Agents** tab (sidebar, under "Users & Access") with a no-CLI-required workflow:

| Action | What happens |
|--------|--------------|
| **Register Agent** | Opens a modal with name, description, and advertised-CIDR fields. On submit the server allocates a token + builds the install command, which is shown **once** in a copy-to-clipboard block. |
| **Update CIDRs** (enrolled rows) | Inline textarea PATCHes the agent and live-applies via `wg syncconf` — no client disconnect. |
| **Manage Access** (enrolled rows) | Toggle per-agent restriction + maintain a per-user allowlist. Default OFF (every VPN user can reach). When ON, only allowlisted client IDs can route to the agent's CIDRs; enforced by an `iptables` chain rebuilt every 30 s and on every grant/revoke. |
| **Reissue token** (pending rows) | Generates a new single-use token and re-shows the install command. |
| **Revoke / Delete** | Removes the WG peer immediately and stops accepting heartbeats. The agent daemon self-disables on its next revocation-check poll. Also run `sudo wireshield-agent uninstall` on the agent host for a full local teardown. |
| **Details** | Read-only drawer with all 19 agent fields plus a 24-hour traffic sparkline (RX/TX deltas) and an uptime % derived from heartbeat coverage. |

The **Overview** tab shows an "Agents" stat card alongside Users/Sessions/Failed/Bandwidth: enrolled count + online indicator + pending count.

### Auto-Update Flow

Agents can self-upgrade against a server-published version manifest. Off by default — enable with `--auto-update` on the systemd unit:

```bash
ExecStart=/usr/local/bin/wireshield-agent run --auto-update --update-interval 6
```

How it works:

1. The operator runs `make -C agent dist` + `make install AGENT_BINARY_DIR=/etc/wireshield/agent-binaries` and drops a `version.json` next to the binaries:

   ```json
   {
     "current_version": "1.1.0",
     "released_at":     "2026-04-26T10:00:00Z",
     "min_version":     "1.0.0",
     "arches": {
       "linux-amd64": { "url": "/api/agents/binary/linux-amd64", "sha256": "<64hex>" },
       "linux-arm64": { "url": "/api/agents/binary/linux-arm64", "sha256": "<64hex>" }
     }
   }
   ```

   Per-arch SHA-256 is auto-backfilled from the sidecars `make dist` produces, so a hand-written manifest can omit them.

2. Each enrolled agent polls `GET /api/agents/version` on the configured cadence (default 6 hours).
3. When the published version is newer than the running version (or when `min_version` is set above the running version), the agent downloads the new binary, verifies the SHA-256 against the manifest, atomically replaces `/usr/local/bin/wireshield-agent`, and exits with code **75** (`sysexits EX_TEMPFAIL`).
4. The systemd unit's `Restart=on-failure` rule reloads the daemon onto the new binary. Code **2** (revocation) and code **0** (clean SIGTERM) both leave the unit stopped, so update vs. revocation never collide.

For a one-shot upgrade trigger:

```bash
wireshield-agent update           # check + apply if newer
wireshield-agent update --dry-run # check only, do not touch /usr/local/bin
```

A SHA-256 mismatch *never* replaces the binary — the daemon logs and continues with the old image.

### End-to-End cURL Walkthrough

Replace `VPN_HOST`, `COOKIE`, and the agent ID as appropriate. The admin requests require an active 2FA session cookie from `/console`.

**1. Admin registers a new agent**

```bash
curl -sS -X POST https://VPN_HOST/api/console/agents \
  -H "Cookie: session=$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "branch-office-01",
    "description": "Dhaka office LAN gateway",
    "advertised_cidrs": ["10.50.0.0/24"]
  }'
```

Response (token is returned **once**):

```json
{
  "agent": { "id": 1, "name": "branch-office-01", "status": "pending", ... },
  "enrollment_token": "RgV9...truncated...Ks",
  "expires_at": "2026-04-23T17:36:00Z",
  "install_command": "curl -sSL https://VPN_HOST/api/agents/install | TOKEN=RgV9...Ks WIRESHIELD_SERVER=https://VPN_HOST bash"
}
```

**2. Operator runs the install command on the remote Linux server (as root)**

The installer generates a WG keypair, enrolls the agent, writes `/etc/wireguard/wg-agent0.conf`, enables the `wg-quick@wg-agent0` unit, and installs a 30-second systemd heartbeat timer. No further manual steps are required.

**3. Agent heartbeat (runs automatically every 30s)**

```bash
curl -sS -X POST https://VPN_HOST/api/agents/heartbeat \
  -H "Content-Type: application/json" \
  -d '{"agent_version":"1.0.0","rx_bytes":1024,"tx_bytes":2048}'
```

Authentication is implicit: this call only succeeds through the WireGuard tunnel, where the source IP matches the agent's allocated WG address. The VPN server rejects callers whose source IP isn't an enrolled agent.

**4. Admin updates advertised CIDRs**

```bash
curl -sS -X PATCH https://VPN_HOST/api/console/agents/1 \
  -H "Cookie: session=$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"advertised_cidrs":["10.50.0.0/24","10.50.1.0/24"]}'
```

The server rewrites the peer's `AllowedIPs` in `wg0.conf` and live-reloads WireGuard via `wg syncconf` — no interface bounce, no client disconnection.

**5. Admin revokes an agent**

```bash
curl -sS -X DELETE https://VPN_HOST/api/console/agents/1 \
  -H "Cookie: session=$COOKIE"
```

The WG peer block is removed, the DB row is marked `revoked`, and the next `/api/agents/revocation-check` poll causes the agent to self-disable its local `wg-agent0` unit.

### Security Model

| Control | Mechanism |
|---------|-----------|
| Enrollment token | 32-byte `secrets.token_urlsafe`, SHA-256 hashed in DB, single-use (atomic `UPDATE ... WHERE used_at IS NULL`), 1-hour TTL, IP-bound |
| Heartbeat / revocation-check auth | Source IP must match the agent's allocated WG address — only reachable through the decrypted tunnel |
| CIDR escalation defence | Admin-pre-declared CIDRs take precedence over agent-declared CIDRs at enrollment |
| Replay / enumeration | Rate-limited public endpoints; generic `401 Invalid or expired enrollment token` for all token-related failures |
| Config hygiene | Atomic `wg0.conf` writes (`tmp + os.replace`); idempotent peer-add/remove; hourly purge of stale tokens + old heartbeats |

### Agent-Side Layout

| Path | Purpose |
|------|---------|
| `/usr/local/bin/wireshield-agent` | Statically-linked Go binary (subcommands: `enroll`, `run`, `status`, `revoke`, `update`, `version`) |
| `/etc/wireshield-agent/private.key` | Agent WG private key (mode 0600) |
| `/etc/wireshield-agent/config.json` | Agent identity: server URL, agent ID, WG address, advertised CIDRs (mode 0600) |
| `/etc/wireguard/wg-agent0.conf` | WG interface config with `PostUp` MASQUERADE for the advertised LAN (mode 0600) |
| `/etc/systemd/system/wireshield-agent.service` | systemd unit running the heartbeat daemon as a hardened long-lived process |

### Go Agent Build + Deployment

The agent is a single statically-linked Go binary. Build it on any host with Go 1.22+:

```bash
cd agent
make test        # run unit tests
make dist        # cross-compile static linux-amd64 + linux-arm64 + .sha256 sidecars
```

Artefacts land under `agent/dist/bin/` as flat files (`wireshield-agent_linux_amd64`, `wireshield-agent_linux_arm64`, and their `.sha256` sidecars). On the VPN server, publish them so the `install-go` endpoint can serve them:

```bash
# On the VPN server, after copying the agent/ tree over:
AGENT_BINARY_DIR=/etc/wireshield/agent-binaries make -C agent install
```

Then any remote Linux host can be onboarded with the one-liner the admin console prints:

```bash
curl -sSL https://VPN_HOST/api/agents/install-go | \
  sudo TOKEN=<enrollment-token> WIRESHIELD_SERVER=https://VPN_HOST bash
```

The installer detects architecture, downloads the binary (verifying its SHA-256 if published), drops the systemd unit, runs `wireshield-agent enroll`, and starts `wireshield-agent.service`. The daemon heartbeats every 30 s and polls revocation every 60 s; on server-confirmed revocation it exits with code 2 and systemd keeps it stopped (via `RestartPreventExitStatus=2`).

Operator subcommands on the agent host:

| Command | Action |
|---------|--------|
| `wireshield-agent status` | Print current enrollment + WG interface state |
| `wireshield-agent run` | Long-running heartbeat daemon (invoked by systemd; rarely run by hand) |
| `wireshield-agent revoke` | Local teardown: stop `wg-quick@wg-agent0`, remove config, delete keys |
| `wireshield-agent version` | Print the agent version |

### Legacy Installer Compatibility

`/api/agents/install` still serves the original Bash installer and its heartbeat-timer approach so existing one-liners keep working. New agents enrolled from the admin console get the Go-daemon flow automatically.

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
  "timestamp": "2026-04-27T05:23:55.528379Z",
  "database": { "status": "ok", "users": 1, "active_sessions": 0 },
  "wireguard": { "status": "up", "interface": "wg0", "operstate": "unknown" },
  "iptables_portal": { "80": "present", "443": "present" },
  "watchdog": {
    "iface": "wg0",
    "iface_state": "up",
    "last_transition": null,
    "portal_rule_fixes": 0,
    "last_check": "2026-04-27T05:23:42.854502"
  },
  "agents": {
    "enrolled": 0,
    "pending": 0,
    "revoked": 0,
    "total": 0,
    "online": 0
  },
  "agent_acl": {
    "last_sync_unix": 1777267422,
    "last_rule_count": 0,
    "last_error": null,
    "missing_iptables": false
  }
}
```

What each field tells you:

| Field | Healthy value | Problem if not |
|-------|---------------|----------------|
| `status` | `"ok"` | `"degraded"` = at least one subsystem check failed |
| `database.status` | `"ok"` | SQLite unreachable — service cannot verify codes or track sessions |
| `wireguard.status` | `"up"` | VPN clients cannot connect or reach captive portal |
| `wireguard.operstate` | `"up"` or `"unknown"` | WireGuard virtual interfaces always report `"unknown"` on Linux — this is normal, not an error |
| `iptables_portal.80/443` | `"present"` | Portal is firewall-blocked even though uvicorn is listening |
| `watchdog.portal_rule_fixes` | `0` | Non-zero = watchdog had to re-add stripped firewall rules (wg-quick flaps) |
| `watchdog.last_transition` | `null` | Non-null = shows the most recent wg0 up/down transition for outage correlation |
| `agents.online` | any integer | Shows how many enrolled agents sent a heartbeat within `WS_AGENT_OFFLINE_AFTER_SECONDS` |
| `agent_acl.last_error` | `null` | Non-null string = iptables command failed; restricted agents may have stale rules |
| `agent_acl.missing_iptables` | `false` | `true` = iptables not available on this host; agent ACL enforcement disabled |

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

### 6. Database Issues

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

### 7. Agent Issues

**Agent not connecting / stuck in `pending`:**

```bash
# On the agent host — check the daemon logs
sudo journalctl -u wireshield-agent.service -f

# Print current enrollment state and WG interface status
wireshield-agent status

# Verify the WireGuard tunnel is up
sudo wg show wg-agent0
```

**Agent ACL rules not applying:**

Check the `agent_acl` block in the `/health` response — a non-null `last_error` field means the last iptables sync failed:

```bash
curl -sk https://<your-server>/health | jq .agent_acl
```

To force an immediate sync, grant or revoke any access entry from the console — this triggers `trigger_agent_acl_sync()` in addition to the 30-second background timer.

**Agent not self-updating:**

```bash
# One-shot dry-run to see what would happen
wireshield-agent update --dry-run

# Check the version manifest the server is serving
curl -sk https://<your-server>/api/agents/version | jq
```

Ensure the operator has run `make -C agent dist && make -C agent install` and that `WS_AGENT_BINARY_DIR` points to the directory containing the built binaries.

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
├── agent/                        # Go agent daemon
│   ├── go.mod
│   ├── Makefile                  # build / test / dist / install targets
│   ├── cmd/
│   │   └── wireshield-agent/
│   │       ├── main.go           # Subcommand dispatch
│   │       ├── enroll.go         # Enrollment flow
│   │       ├── daemon.go         # Heartbeat daemon (run subcommand)
│   │       ├── update.go         # One-shot self-update (update subcommand)
│   │       ├── revoke.go         # Local teardown
│   │       └── status.go         # Enrollment state printer
│   ├── internal/
│   │   ├── client/client.go      # HTTP client for server API
│   │   ├── config/config.go      # config.json read/write (atomic)
│   │   ├── logx/logx.go          # Leveled stderr logger
│   │   ├── runner/runner.go      # Event-loop with heartbeat + revocation + auto-update timers
│   │   ├── updater/updater.go    # Semver compare, binary download + SHA-256 verify, atomic replace
│   │   └── wg/
│   │       ├── keys.go           # Curve25519 keypair generation
│   │       ├── config.go         # wg-agent0.conf builder (atomic write)
│   │       ├── lan.go            # Default-route LAN detection
│   │       ├── stats.go          # wg show transfer parser
│   │       └── systemd.go        # systemctl enable/disable --now wrappers
│   └── dist/
│       ├── wireshield-agent.service  # Hardened systemd unit
│       └── install.sh            # Bootstrap installer (arch-detect, binary download, enroll)
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
    │   │   ├── wireguard.py      # Client lifecycle: create/revoke/download .conf (Python mirror of ws_add_client)
    │   │   ├── tasks.py          # Background monitors + interface watchdog
    │   │   └── sniffer.py        # DNS + TLS SNI packet capture (auto-recovering)
    │   └── routers/
    │       ├── auth.py           # 2FA captive portal endpoints
    │       ├── console.py        # Admin console endpoints (users, agents, metrics, ACL)
    │       ├── agents.py         # Agent public API (enroll, heartbeat, binary, version)
    │       └── health.py         # Diagnostic /health endpoint
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
| Agent daemon | Go 1.22+ (single static binary, Curve25519 via `golang.org/x/crypto`) |
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

### Contribution Guidelines

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

