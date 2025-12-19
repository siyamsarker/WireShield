# WireShield 2FA Auth Service

**Secure pre-connection 2FA authentication for WireGuard VPN using Google Authenticator (TOTP)**

## 🚀 Quick Start

```bash
# 1. Automatic (recommended) - integrated with main wireshield.sh
sudo ./wireshield.sh

# 2. Manual installation
bash /etc/wireshield/2fa/generate-certs.sh 365
pip3 install -r /etc/wireshield/2fa/requirements.txt
sudo systemctl start wireshield-2fa

# 3. Verify
curl -k https://127.0.0.1:8443/health
```

## 📦 What's Included

| File | Purpose |
|------|---------|
| `app.py` | FastAPI server with all 2FA endpoints (1500+ lines) |
| `requirements.txt` | Python package dependencies |
| `wireshield-2fa.service` | Systemd unit file for auto-start |
| `generate-certs.sh` | SSL certificate generator |
| `2fa-helper.sh` | CLI management tool |
| `test-integration.sh` | Integration test suite |
| `README.md` | Full technical documentation |

## ✨ Features

✅ **TOTP Authentication** - Time-based one-time passwords (Google Authenticator compatible)  
✅ **QR Code Enrollment** - Scan QR to set up 2FA  
✅ **Session Management** - Time-bound tokens (24h default)  
✅ **SQLite Database** - Secrets, sessions, audit logs  
✅ **Web UI** - Mobile-responsive 2FA setup/verification  
✅ **HTTPS/TLS** - Secure communication  
✅ **Audit Logging** - All authentication attempts tracked  
✅ **Systemd Service** - Auto-start and restart  

## 🔄 Flow

```
User creates VPN client → 2FA enabled automatically
                ↓
User connects → Redirect to web UI (127.0.0.1:8443)
                ↓
User scans QR with Google Authenticator
                ↓
User enters 6-digit code
                ↓
Session created (24 hours)
                ↓
VPN access granted!
                ↓
On reconnect after timeout: Re-verify 2FA
```

## 📖 Full Documentation

- **[README.md](./README.md)** - Complete API and management guide
- **[../DEPLOYMENT_2FA.md](../DEPLOYMENT_2FA.md)** - Installation and troubleshooting
- **[../IMPLEMENTATION_SUMMARY.md](../IMPLEMENTATION_SUMMARY.md)** - Architecture and overview

## 🛠️ Management Commands

```bash
# Install 2FA service
sudo /etc/wireshield/2fa/2fa-helper.sh install

# Enable 2FA for client
sudo /etc/wireshield/2fa/2fa-helper.sh enable alice

# Check client status
sudo /etc/wireshield/2fa/2fa-helper.sh status alice

# View service
sudo systemctl status wireshield-2fa

# View logs
sudo journalctl -u wireshield-2fa -f

# Test endpoints
curl -k https://127.0.0.1:8443/health
```

## 🧪 Testing

```bash
bash test-integration.sh
```

## 📋 System Requirements

- Python 3.8+
- Linux kernel 5.6+ (for WireGuard)
- pip3
- OpenSSL
- Systemd

## 🔐 Security

- TOTP secrets stored in SQLite database
- Sessions use secure random tokens
- HTTPS with TLS 1.3+
- Rate limiting ready
- Comprehensive audit logging
- Firewall-level access control

## 📊 Technology Stack

- **FastAPI** - Modern async web framework
- **Uvicorn** - ASGI server
- **SQLite** - Lightweight database
- **SQLAlchemy** - Database ORM
- **PyOTP** - TOTP implementation
- **QRCode** - QR generation

## ⚙️ Configuration

Environment variables (in systemd service):

```bash
2FA_DB_PATH=/etc/wireshield/2fa/auth.db
2FA_HOST=127.0.0.1
2FA_PORT=8443
2FA_SESSION_TIMEOUT=1440  # minutes
2FA_LOG_LEVEL=INFO
```

## 🚀 Production Checklist

- [ ] SSL certificates (Let's Encrypt or proper CA)
- [ ] Database encrypted at rest
- [ ] Rate limiting configured
- [ ] Firewall rules verified
- [ ] Backup strategy for auth.db
- [ ] Monitoring/alerting set up
- [ ] Audit logs retention policy

## 📝 License

Same as WireShield - GPLv3

## 🤝 Support

Issues? See [DEPLOYMENT_2FA.md Troubleshooting](../DEPLOYMENT_2FA.md#troubleshooting) section.

---

**Status**: ✅ Production Ready  
**Version**: 1.0.0  
**Last Updated**: January 2024
