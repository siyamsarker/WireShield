# WireShield 2FA Service Integration

This directory contains the 2FA authentication service for WireShield. It provides secure pre-connection 2FA verification using Google Authenticator (TOTP).

## Architecture

### How It Works

1. **User creates a VPN client** via CLI (`wireshield-dashboard new-client`)
2. **Client is marked for 2FA** - a unique client ID is stored in the 2FA database
3. **User attempts VPN connection** - traffic is initially blocked by firewall rules
4. **User is redirected to 2FA web UI** (running on `https://127.0.0.1:8443`)
5. **First-time setup**: User scans QR code with Google Authenticator and verifies the code
6. **Session is created** - valid for 24 hours by default
7. **VPN access is granted** - firewall rules updated to allow this user
8. **On disconnect/timeout**: Session expires, next connection requires re-verification

### Technology Stack

- **Language**: Python 3.8+
- **Web Framework**: FastAPI (async, lightweight, secure)
- **Server**: Uvicorn (ASGI)
- **Database**: SQLite (embedded, no external dependencies)
- **2FA**: PyOTP (TOTP implementation)
- **QR Codes**: QRCode (for enrollment)
- **Security**: TLS/HTTPS, secure cookies, rate limiting ready
- **Service Manager**: Systemd

## Installation

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y python3 python3-pip openssl curl jq

# RHEL/CentOS/Fedora
sudo dnf install -y python3 python3-pip openssl curl jq

# Alpine
sudo apk add python3 py3-pip openssl curl jq

# Arch
sudo pacman -S python pip openssl curl jq
```

### Automated Installation

The WireShield main CLI (`wireshield.sh`) will auto-install 2FA when you create your first client:

```bash
sudo ./wireshield.sh
# Select "Create Client"
# 2FA service will be auto-configured on first use
```

### Manual Installation

```bash
# Copy 2FA service to system
sudo mkdir -p /etc/wireshield/2fa
sudo cp -r . /etc/wireshield/2fa/

# Install Python dependencies
sudo pip3 install -r /etc/wireshield/2fa/requirements.txt

# Generate SSL certificates
sudo bash /etc/wireshield/2fa/generate-certs.sh 365

# Install systemd service
sudo cp /etc/wireshield/2fa/wireshield-2fa.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable wireshield-2fa
sudo systemctl start wireshield-2fa

# Verify
sudo systemctl status wireshield-2fa
```

## File Structure

```
2fa-auth/
├── app.py                    # Main FastAPI application
├── requirements.txt          # Python dependencies
├── wireshield-2fa.service    # Systemd service unit
├── generate-certs.sh         # SSL certificate generator
├── 2fa-helper.sh             # CLI integration helper
└── README.md                 # This file
```

## API Endpoints

### Health Check

```bash
curl https://127.0.0.1:8443/health -k
```

Response:
```json
{"status": "ok", "service": "wireshield-2fa"}
```

### Setup QR Code (First Time)

**Request:**
```bash
curl -k -X POST https://127.0.0.1:8443/api/setup-start \
  -d "client_id=my_vpn_client"
```

**Response:**
```json
{
  "success": true,
  "secret": "JBSWY3DPEBLW64TMMQ...",
  "qr_code": "data:image/png;base64,iVBORw0KG...",
  "uri": "otpauth://totp/..."
}
```

### Verify Code (Setup)

**Request:**
```bash
curl -k -X POST https://127.0.0.1:8443/api/setup-verify \
  -d "client_id=my_vpn_client&code=123456"
```

**Response:**
```json
{
  "success": true,
  "session_token": "s_...",
  "expires_at": "2024-01-15T14:30:00"
}
```

### Verify Code (Reconnect)

**Request:**
```bash
curl -k -X POST https://127.0.0.1:8443/api/verify \
  -d "client_id=my_vpn_client&code=654321"
```

**Response:**
```json
{
  "success": true,
  "session_token": "s_...",
  "expires_at": "2024-01-15T14:30:00"
}
```

### Validate Session

**Request:**
```bash
curl -k -X POST https://127.0.0.1:8443/api/validate-session \
  -d "client_id=my_vpn_client&session_token=s_..."
```

**Response:**
```json
{
  "valid": true,
  "expires_at": "2024-01-15T14:30:00"
}
```

## Web UI

Access the 2FA setup/verification interface:

```
https://127.0.0.1:8443/?client_id=YOUR_CLIENT_ID
```

The UI is:
- ✅ Mobile-responsive
- ✅ Dark mode compatible
- ✅ Accessible (WCAG 2.1 AA)
- ✅ Works offline (no external resources)
- ✅ Fast (no heavy frameworks)

## Management Commands

### Using the Helper Script

```bash
# Check service status
sudo /etc/wireshield/2fa/2fa-helper.sh service-status

# Enable 2FA for a specific client
sudo /etc/wireshield/2fa/2fa-helper.sh enable my_client

# Disable 2FA for a specific client
sudo /etc/wireshield/2fa/2fa-helper.sh disable my_client

# Show 2FA status for a client
sudo /etc/wireshield/2fa/2fa-helper.sh status my_client

# Clean up expired sessions
sudo /etc/wireshield/2fa/2fa-helper.sh cleanup-sessions

# Check service logs
sudo journalctl -u wireshield-2fa -f
```

### Database Access

```bash
# View all users
sudo sqlite3 /etc/wireshield/2fa/auth.db "SELECT * FROM users;"

# View active sessions
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT * FROM sessions WHERE expires_at > datetime('now');"

# View audit log
sudo sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 20;"
```

## Integration with CLI

### Adding a New Client with 2FA

```bash
sudo ./wireshield.sh
# Choose "Create Client" → "Alice"
# 2FA is automatically enabled for Alice
```

### Creating a WireGuard Config

When you export the config, 2FA is automatically enforced:

```bash
# User exports their config
sudo wg-quick up alice_vpn

# On first connection: Browser opens to 2FA setup
# User scans QR code with Google Authenticator
# User enters 6-digit code
# Session is created
# VPN connects successfully

# On disconnect and reconnect: Session has expired
# User must re-verify 2FA code
```

## Security Considerations

### SSL/TLS

- Service uses **self-signed certificates** by default (safe for localhost)
- For production remote access, use **Let's Encrypt** or proper CA certs
- Clients can bypass self-signed warnings (safe in private networks)

### Database

- TOTP secrets are **stored in plain text** (must be on secure filesystem)
- Sessions use **salted hashing** for token verification
- Audit log tracks all authentication attempts

### Rate Limiting

- Ready for rate limiting implementation (not currently enforced)
- Recommend: max 5 failed attempts per minute per IP

### Firewall Integration

- Initially, all non-2FA connections are blocked by firewall rules
- Session token must be valid to allow traffic
- Sessions auto-expire after 24 hours

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status wireshield-2fa

# View logs
sudo journalctl -u wireshield-2fa -n 50

# Check if port 8443 is already in use
sudo netstat -tlnp | grep 8443

# Verify permissions
sudo ls -la /etc/wireshield/2fa/
```

### QR Code Not Generating

```bash
# Ensure qrcode library is installed
sudo pip3 install -U qrcode pillow

# Restart service
sudo systemctl restart wireshield-2fa
```

### Database Locked Error

```bash
# Close any open connections
sudo pkill -f "sqlite3.*auth.db"

# Verify database integrity
sudo sqlite3 /etc/wireshield/2fa/auth.db "PRAGMA integrity_check;"

# If corrupted, backup and reset
sudo mv /etc/wireshield/2fa/auth.db /etc/wireshield/2fa/auth.db.bak
sudo systemctl restart wireshield-2fa
```

### HTTPS Connection Refused

```bash
# Check if SSL certs exist
ls -la /etc/wireshield/2fa/*.pem

# Regenerate if missing
sudo bash /etc/wireshield/2fa/generate-certs.sh 365

# Restart service
sudo systemctl restart wireshield-2fa
```

## Development & Testing

### Run Locally (Development)

```bash
# Install dev dependencies
pip3 install -r requirements.txt

# Generate test certs
bash generate-certs.sh 365

# Run server
python3 app.py
```

### Test Endpoints

```bash
# Health check
curl -k https://127.0.0.1:8443/health

# Setup QR (replace with test client ID)
curl -k -X POST https://127.0.0.1:8443/api/setup-start \
  -d "client_id=test_user"

# Get a valid TOTP code
python3 -c "import pyotp; print(pyotp.TOTP('JBSWY3DPEBLW64TMMQ...').now())"

# Verify setup
curl -k -X POST https://127.0.0.1:8443/api/setup-verify \
  -d "client_id=test_user&code=123456"
```

## Performance & Resource Usage

- **Memory**: ~50-100 MB at idle
- **CPU**: Minimal (event-driven)
- **Disk**: ~1-2 MB for SQLite database
- **Network**: TLS 1.3 with perfect forward secrecy

## License

Same as WireShield - see LICENSE file in the main repo

## Support

For issues, questions, or contributions:
- GitHub: https://github.com/technonext/wireshield
- Email: support@wireshield.local
