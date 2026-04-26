<div align="center">

<img src="assets/logo.svg" alt="WireShield Logo" width="140" height="140">

# WireShield

**Zero-trust WireGuard VPN with pre-connection two-factor authentication**

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![WireGuard](https://img.shields.io/badge/WireGuard-Compatible-88171a.svg)](https://www.wireguard.com/)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776ab.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688.svg)](https://fastapi.tiangolo.com/)

WireShield deploys a WireGuard VPN with mandatory TOTP-based two-factor authentication at the connection layer. Every client must verify through a captive portal before any traffic is allowed through the tunnel.

[Quick Start](#quick-start) &bull; [How It Works](#how-it-works) &bull; [Features](#features) &bull; [Installation](#installation) &bull; [Usage](#usage) &bull; [Agents](#agents) &bull; [Contributing](#contributing)

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

### Operations
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

/etc/wireshield/clients/       # Canonical location for generated client .conf files
└── <client>.conf             # Both the CLI (ws_add_client, newClient) and the
                              # console's "Create User" write here. Mode 0700/0600.

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
| `WS_AGENT_TOKEN_TTL_SECONDS` | `3600` | Enrollment token lifetime (1 hour) |
| `WS_AGENT_IP_START` | `200` | First WG IPv4 octet reserved for agents (inside the server subnet) |
| `WS_AGENT_IP_END` | `254` | Last WG IPv4 octet reserved for agents |
| `WS_AGENT_HEARTBEAT_RETENTION_HOURS` | `48` | Hours of `agent_heartbeats` rows to retain before housekeeping prunes them |
| `WS_AGENT_OFFLINE_AFTER_SECONDS` | `90` | Seconds without a heartbeat before an agent is reported as `online=false` in `/health` |
| `WS_AGENT_BINARY_DIR` | `/etc/wireshield/agent-binaries` | Server-side directory holding pre-built Go-agent binaries + SHA-256 sidecars, populated by `make -C agent install` |

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
| Agents | WireGuard peer + Bash daemon | Reverse-connection gateways that expose remote LANs to VPN clients |

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

**Agent Public API** (called by the agent daemon, not by humans):

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/agents/enroll` | Exchange a single-use token for a WG peer config (public/keyless endpoint, rate-limited) |
| `POST` | `/api/agents/heartbeat` | Periodic liveness + bandwidth report (auth: WG tunnel source IP) |
| `GET` | `/api/agents/revocation-check` | Agent polls this to self-disable when revoked (auth: WG tunnel source IP) |
| `GET` | `/api/agents/install` | **Legacy Phase-1** Bash installer (kept for backward compatibility) |
| `GET` | `/api/agents/install-go` | **Phase-2** Bash bootstrap that downloads the Go binary |
| `GET` | `/api/agents/binary/{arch}` | Pre-built agent binary (`linux-amd64`, `linux-arm64`) |
| `GET` | `/api/agents/binary/{arch}.sha256` | Sidecar SHA-256 checksum for integrity verification |
| `GET` | `/api/agents/unit` | systemd unit file (`wireshield-agent.service`) |

---

## Agents

Agents are statically-linked Go daemons deployed on remote Linux servers. They connect **outbound** to the WireShield VPN and register themselves as a special WireGuard peer whose `AllowedIPs` include the LAN CIDRs they advertise. Any VPN client can then route traffic for those CIDRs through the agent, with the VPN server enforcing the same zero-trust policies. Agents are enrolled with single-use, IP-bound tokens (SHA-256 hashed at rest) and authenticated on every heartbeat by matching the decrypted tunnel's source IP to the allocated WG address.

### Managing agents from the console

The admin dashboard ships an **Agents** tab (sidebar, under "Users & Access") with a no-CLI-required workflow:

| Action | What happens |
|--------|--------------|
| **Register Agent** | Opens a modal with name, description, and advertised-CIDR fields. On submit the server allocates a token + builds the install command, which is shown **once** in a copy-to-clipboard block. |
| **Update CIDRs** (enrolled rows) | Inline textarea PATCHes the agent and live-applies via `wg syncconf` — no client disconnect. |
| **Reissue token** (pending rows) | Generates a new single-use token and re-shows the install command. |
| **Revoke** | Removes the WG peer immediately and stops accepting heartbeats. The agent self-disables on its next revocation-check poll. |
| **Details** | Read-only drawer with all 19 agent fields (public key, hostname, last-seen IP, RX/TX byte totals, etc.). |

The **Overview** tab shows an "Agents" stat card alongside Users/Sessions/Failed/Bandwidth: enrolled count + online indicator + pending count.

### End-to-end cURL walkthrough

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

### Security model

| Control | Mechanism |
|---------|-----------|
| Enrollment token | 32-byte `secrets.token_urlsafe`, SHA-256 hashed in DB, single-use (atomic `UPDATE ... WHERE used_at IS NULL`), 1-hour TTL, IP-bound |
| Heartbeat / revocation-check auth | Source IP must match the agent's allocated WG address — only reachable through the decrypted tunnel |
| CIDR escalation defence | Admin-pre-declared CIDRs take precedence over agent-declared CIDRs at enrollment |
| Replay / enumeration | Rate-limited public endpoints; generic `401 Invalid or expired enrollment token` for all token-related failures |
| Config hygiene | Atomic `wg0.conf` writes (`tmp + os.replace`); idempotent peer-add/remove; hourly purge of stale tokens + old heartbeats |

### Agent-side layout (Phase 2, Go daemon)

| Path | Purpose |
|------|---------|
| `/usr/local/bin/wireshield-agent` | Statically-linked Go binary (subcommands: `enroll`, `run`, `status`, `revoke`, `version`) |
| `/etc/wireshield-agent/private.key` | Agent WG private key (mode 0600) |
| `/etc/wireshield-agent/config.json` | Agent identity: server URL, agent ID, WG address, advertised CIDRs (mode 0600) |
| `/etc/wireguard/wg-agent0.conf` | WG interface config with `PostUp` MASQUERADE for the advertised LAN (mode 0600) |
| `/etc/systemd/system/wireshield-agent.service` | systemd unit running the heartbeat daemon as a hardened long-lived process |

### Go agent build + deployment

The Phase-2 agent is a single statically-linked Go binary. Build it on any host with Go 1.22+:

```bash
cd agent
make test        # run unit tests
make dist        # cross-compile static linux-amd64 + linux-arm64 + .sha256 sidecars
```

Artefacts land under `agent/dist/bin/<arch>/`. On the VPN server, publish them so the `install-go` endpoint can serve them:

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

### Phase-1 compatibility

`/api/agents/install` still serves the original Bash installer and its heartbeat-timer approach so existing one-liners keep working. New agents enrolled from the admin console get the Phase-2 flow automatically.

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
    │   │   ├── wireguard.py      # Client lifecycle: create/revoke/download .conf (Python mirror of ws_add_client)
    │   │   ├── tasks.py          # Background monitors + interface watchdog
    │   │   └── sniffer.py        # DNS + TLS SNI packet capture (auto-recovering)
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

