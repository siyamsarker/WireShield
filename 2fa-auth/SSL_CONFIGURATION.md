# SSL/TLS Configuration for WireShield 2FA

This document describes the SSL/TLS configuration options added to WireShield 2FA deployment.

## Overview

During WireShield installation, you will now be prompted to configure SSL/TLS for the 2FA service:

```
=== WireShield 2FA SSL/TLS Configuration ===

The 2FA web interface requires HTTPS for security.

Configure SSL/TLS for 2FA service? (y/n): 
```

## Configuration Options

### 1. No SSL/TLS (Not Recommended)
```
Configure SSL/TLS for 2FA service? (y/n): n
```

**Use case**: Development/testing on localhost only

**Behavior**:
- 2FA service runs on HTTP (port 8443 without encryption)
- Only safe if accessible from localhost only
- ⚠️ WARNING: Not suitable for production or remote access

### 2. Let's Encrypt (Recommended for Production)
```
Configure SSL/TLS for 2FA service? (y/n): y

Choose SSL certificate type:
  1) Let's Encrypt (Domain name required, auto-renewal)
  2) Self-signed (IP address or any hostname, no auto-renewal)

Enter choice (1 or 2): 1

Enter domain name for 2FA service (e.g., vpn.example.com): vpn.example.com
```

**Benefits**:
- ✅ Trusted certificate (no browser warnings)
- ✅ Automatic renewal (90-day auto-refresh)
- ✅ Works with all devices/apps
- ✅ Production-ready

**Requirements**:
- Valid domain name
- Port 80/443 accessibility from the internet
- certbot installation (auto-installed if needed)

**What happens**:
1. Certbot validates domain ownership
2. Certificate stored in `/etc/letsencrypt/live/domain/`
3. Symlinked to `/etc/wireshield/2fa/cert.pem` and `key.pem`
4. Systemd timer auto-renews certificate before expiry
5. Service automatically reloaded after renewal

### 3. Self-Signed Certificate (For IP Addresses)
```
Configure SSL/TLS for 2FA service? (y/n): y

Choose SSL certificate type:
  1) Let's Encrypt (Domain name required, auto-renewal)
  2) Self-signed (IP address or any hostname, no auto-renewal)

Enter choice (1 or 2): 2

Enter IP address or hostname (e.g., 127.0.0.1 or vpn.local): 192.168.1.100
```

**Use cases**:
- Private networks using IP addresses
- Hostnames without public DNS
- Testing environments
- Internal deployments

**What happens**:
1. OpenSSL generates self-signed certificate
2. Valid for specified IP/hostname for 365 days
3. Certificate stored at `/etc/wireshield/2fa/cert.pem`
4. Private key stored at `/etc/wireshield/2fa/key.pem`
5. Manual renewal required after 365 days

**Note**: Browsers will show security warnings (expected for self-signed certs)

---

## Configuration Files

### Main Configuration
**File**: `/etc/wireshield/2fa/config.env`

```bash
# Created during installation with your choices:
2FA_SSL_ENABLED=true
2FA_SSL_TYPE=letsencrypt        # or "self-signed"
2FA_DOMAIN=vpn.example.com      # if Let's Encrypt
2FA_HOSTNAME=192.168.1.100      # if Self-signed
```

### Systemd Service
**File**: `/etc/systemd/system/wireshield-2fa.service`

Configuration from `config.env` is injected as environment variables:

```ini
[Service]
Environment="2FA_SSL_ENABLED=true"
Environment="2FA_SSL_TYPE=letsencrypt"
Environment="2FA_DOMAIN=vpn.example.com"
Environment="2FA_HOSTNAME="
```

### Auto-Renewal Service (Let's Encrypt Only)
**File**: `/etc/systemd/system/wireshield-2fa-renew.timer`

Runs daily to check certificate expiry and renew if needed:

```ini
[Timer]
OnCalendar=daily
OnBootSec=5min
Persistent=true
```

---

## Certificate Files

### Let's Encrypt
```
Original: /etc/letsencrypt/live/vpn.example.com/
├── fullchain.pem  ← Certificate chain
└── privkey.pem    ← Private key

Symlinks: /etc/wireshield/2fa/
├── cert.pem → /etc/letsencrypt/live/vpn.example.com/fullchain.pem
└── key.pem → /etc/letsencrypt/live/vpn.example.com/privkey.pem
```

### Self-Signed
```
/etc/wireshield/2fa/
├── cert.pem        ← Self-signed certificate
└── key.pem         ← Private key
```

### File Permissions
```bash
-rw------- 1 root root cert.pem   # 600
-rw------- 1 root root key.pem    # 600
```

---

## Verification

### Check Configuration
```bash
# View current configuration
cat /etc/wireshield/2fa/config.env

# Check certificate validity
openssl x509 -in /etc/wireshield/2fa/cert.pem -text -noout

# Check service status
sudo systemctl status wireshield-2fa

# View SSL/TLS info in logs
sudo journalctl -u wireshield-2fa | grep -i ssl
```

### Verify Certificate Works
```bash
# Test HTTPS connection
curl -k https://127.0.0.1:8443/health

# Expected output:
# {"status":"ok","service":"wireshield-2fa"}
```

### Check Auto-Renewal (Let's Encrypt)
```bash
# Verify renewal timer is active
sudo systemctl status wireshield-2fa-renew.timer

# View renewal history
sudo grep "certbot" /var/log/syslog | tail -20

# Check next renewal date
sudo certbot certificates
```

---

## Common Scenarios

### Scenario 1: Production with Domain
```
Domain: vpn.example.com
Choice: Let's Encrypt
Result: Auto-renewed certificate, trusted by all browsers
```

### Scenario 2: Private Network with IP
```
IP: 192.168.1.100
Choice: Self-signed
Result: Works internally, browser warning (expected)
```

### Scenario 3: Testing on Localhost
```
Choice: No SSL
Note: Only use if accessing from same machine
```

---

## Troubleshooting

### Certificate Renewal Failed
```bash
# Check renewal errors
sudo systemctl status wireshield-2fa-renew.timer

# Manual renewal
sudo certbot renew --force-renewal

# Check logs
sudo journalctl -u wireshield-2fa-renew.service
```

### Browser Shows Certificate Warning
```
Self-signed certificate warnings are normal.

Firefox: Click "Advanced" → "Accept Risk"
Chrome: Click "Advanced" → "Proceed to localhost"
Safari: Click "Show Details" → "Visit Website"

To avoid: Use Let's Encrypt with valid domain
```

### Certificate Already Expired
```bash
# Check expiry
openssl x509 -in /etc/wireshield/2fa/cert.pem -noout -dates

# Regenerate self-signed (expires in 365 days)
sudo bash /etc/wireshield/2fa/generate-certs.sh 365
sudo systemctl restart wireshield-2fa

# OR renew Let's Encrypt
sudo certbot renew --force-renewal
```

### Can't Access 2FA UI
```bash
# Verify service is running
sudo systemctl status wireshield-2fa

# Check if listening on correct port
sudo netstat -tlnp | grep 8443

# View service logs
sudo journalctl -u wireshield-2fa -f

# Check firewall
sudo ufw status numbered  # or firewall-cmd
sudo ufw allow 8443      # or firewall-cmd --add-port 8443/tcp
```

---

## Switching SSL Configuration

### From Self-Signed to Let's Encrypt
```bash
# 1. Back up current config
sudo cp /etc/wireshield/2fa/config.env /etc/wireshield/2fa/config.env.bak

# 2. Re-run configuration wizard
# Edit the config file manually or re-run installer
sudo vim /etc/wireshield/2fa/config.env

# 3. Update to Let's Encrypt
sudo certbot certonly --standalone -d vpn.example.com

# 4. Create symlinks
sudo ln -sf /etc/letsencrypt/live/vpn.example.com/fullchain.pem /etc/wireshield/2fa/cert.pem
sudo ln -sf /etc/letsencrypt/live/vpn.example.com/privkey.pem /etc/wireshield/2fa/key.pem

# 5. Update config
sudo sed -i 's/2FA_SSL_TYPE=.*/2FA_SSL_TYPE=letsencrypt/' /etc/wireshield/2fa/config.env
sudo sed -i 's/2FA_DOMAIN=.*/2FA_DOMAIN=vpn.example.com/' /etc/wireshield/2fa/config.env

# 6. Restart service
sudo systemctl restart wireshield-2fa
```

### From Let's Encrypt to Self-Signed
```bash
# 1. Remove symlinks
sudo rm /etc/wireshield/2fa/cert.pem /etc/wireshield/2fa/key.pem

# 2. Generate self-signed
sudo bash /etc/wireshield/2fa/generate-certs.sh 365

# 3. Update config
sudo sed -i 's/2FA_SSL_TYPE=.*/2FA_SSL_TYPE=self-signed/' /etc/wireshield/2fa/config.env

# 4. Restart service
sudo systemctl restart wireshield-2fa
```

---

## Environment Variables

The 2FA service reads these environment variables from systemd:

```bash
2FA_SSL_ENABLED      # "true" or "false"
2FA_SSL_TYPE         # "self-signed", "letsencrypt", or "none"
2FA_DOMAIN           # Domain name for Let's Encrypt
2FA_HOSTNAME         # IP or hostname for self-signed
2FA_HOST             # Bind address (0.0.0.0)
2FA_PORT             # Port (8443)
2FA_DB_PATH          # Database location
2FA_LOG_LEVEL        # Logging level
2FA_SESSION_TIMEOUT  # Session duration in minutes
```

---

## Security Best Practices

1. **Always use HTTPS** (Let's Encrypt or self-signed)
   - Protects TOTP secrets in transit
   - Encrypts session tokens

2. **Use Let's Encrypt for Production**
   - Trusted certificates
   - Automatic renewal
   - No manual management

3. **Firewall the 2FA Service**
   - Only allow from trusted networks
   - Use IP whitelisting if possible
   - Block direct internet access if internal-only

4. **Keep Certificates Updated**
   - Monitor renewal status
   - Set up alerts for failures
   - Test renewal process regularly

5. **Backup Configuration**
   - Save `/etc/wireshield/2fa/config.env`
   - Keep Let's Encrypt certificates backed up
   - Document your settings

---

## Support

For issues:
- Check systemd logs: `sudo journalctl -u wireshield-2fa`
- Check renewal logs: `sudo journalctl -u wireshield-2fa-renew`
- Review certbot logs: `sudo certbot logs`
- Test certificate: `openssl s_client -connect localhost:8443`

---

**Last Updated**: December 2024  
**WireShield Version**: 2.2.0+2FA  
**Status**: Production Ready
