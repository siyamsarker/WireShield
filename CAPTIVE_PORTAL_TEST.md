# Captive Portal Testing Guide

## Overview
This document describes how to test the new captive portal functionality in WireShield v2.4.0+.

## Architecture

### Firewall Flow

**Before 2FA Verification:**
```
WireGuard Client → Port Check → WS_2FA_PORTAL Chain
                                    ├─ Port 53 (DNS) → ALLOW
                                    ├─ Port 8443 (HTTPS) → ALLOW
                                    ├─ Port 80 (HTTP) → DNAT to 127.0.0.1:8443
                                    └─ All other ports → DROP
```

**After 2FA Verification:**
```
WireGuard Client → Added to ipset allowlist → Full internet access
```

### Key Components

1. **WS_2FA_PORTAL / WS_2FA_PORTAL6** (iptables chains)
   - Attached to FORWARD on wg0 interface
   - Default policy: DROP
   - Rules allow DNS, 2FA service, and HTTP redirect

2. **WS_2FA_REDIRECT / WS_2FA_REDIRECT6** (iptables NAT chains)
   - Attached to PREROUTING in nat table
   - DNAT port 80 → 127.0.0.1:8443
   - Causes browser to be redirected to 2FA page

3. **ws_2fa_allowed_v4 / ws_2fa_allowed_v6** (ipsets)
   - Hash sets containing whitelisted client IPs
   - Populated when 2FA succeeds
   - Pruned when sessions expire

4. **2FA Service** (FastAPI on HTTPS 8443)
   - HTTP → HTTPS redirect middleware
   - Auto-discovery of clients by IP
   - Success page with 5-second auto-close

## Testing Scenarios

### Scenario 1: First-Time Connection (Setup Flow)

**Setup:**
- Fresh VPN client (no prior 2FA)
- VPN server deployed with fixed IP: `134.209.207.239`
- DNS servers: `1.1.1.1`, `1.0.0.1`

**Steps:**
1. User connects to VPN via WireGuard GUI/CLI
   ```bash
   wg-quick up <config-file>
   ```

2. Check connection status
   ```
   Expected: "Connected" with IP (e.g., 10.66.66.2)
   ```

3. Try to access any HTTP website (e.g., `http://example.com`)
   ```
   Expected: Browser auto-redirected to https://134.209.207.239:8443
   If auto-redirect fails: Manually open https://134.209.207.239:8443
   ```

4. On 2FA page:
   - See "Client ID" auto-populated
   - Click "Generate QR Code"
   - Scan with authenticator app (Google Authenticator, 1Password, Authy, etc.)

5. Enter 6-digit TOTP code
   - Wait for code to cycle (30-second window)
   - Enter latest code

6. Click "Verify and continue"
   ```
   Expected: Page shows green checkmark ✓
   Expected: Success page loads and auto-closes after 5 seconds
   ```

7. Try accessing internet
   ```bash
   ping 8.8.8.8          # Should work now
   curl https://google.com  # Should work
   ```

**Verification Commands (on server):**
```bash
# Check if client is in allowlist
CLIENT_ID="user1"
sudo sqlite3 /etc/wireshield/2fa/auth.db "SELECT client_id, wg_ipv4 FROM users WHERE client_id = '$CLIENT_ID';"

# Verify IP in ipset
CLIENT_IP="10.66.66.2"
sudo ipset list ws_2fa_allowed_v4 | grep $CLIENT_IP

# Check active session
sudo sqlite3 /etc/wireshield/2fa/auth.db "SELECT * FROM sessions WHERE client_id = '$CLIENT_ID' AND expires_at > datetime('now');"
```

---

### Scenario 2: Reconnection (Re-verification Flow)

**Setup:**
- User completed Scenario 1
- Session expires or user disconnects

**Steps:**
1. User disconnects from VPN
   ```bash
   wg-quick down <config-file>
   ```

2. Wait 30+ seconds

3. Reconnect to VPN
   ```bash
   wg-quick up <config-file>
   ```

4. Try to access internet
   ```
   Expected: NO internet access (firewall blocks again)
   ```

5. Try to access HTTP website (e.g., `http://example.com`)
   ```
   Expected: Redirected to 2FA page again
   ```

6. Enter 2FA code
   ```
   Expected: Same 6-digit code works (from same authenticator secret)
   ```

7. After verification
   ```
   Expected: Internet access restored immediately
   ```

**Verification Commands (on server):**
```bash
# Verify old IP was removed from allowlist
sudo ipset list ws_2fa_allowed_v4

# Check sessions (should show NEW session)
sqlite3 /etc/wireshield/2fa/auth.db "SELECT created_at, expires_at FROM sessions WHERE client_id = '$CLIENT_ID' ORDER BY created_at DESC LIMIT 2;"
```

---

### Scenario 3: Firewall Rules Verification

**Purpose:** Validate that firewall rules are correctly configured

**Commands to run (on server):**

```bash
# 1. Check iptables chains exist
sudo iptables -S WS_2FA_PORTAL
sudo ip6tables -S WS_2FA_PORTAL6
# Expected output shows rules for DNS (53), HTTPS (8443), and drop default

# 2. Check NAT redirect rules
sudo iptables -t nat -S | grep WS_2FA_REDIRECT
sudo ip6tables -t nat -S | grep WS_2FA_REDIRECT6
# Expected: Rules redirecting port 80 to 127.0.0.1:8443

# 3. Check ipsets exist with correct families
sudo ipset list ws_2fa_allowed_v4 | head -3
# Expected: Family: inet, Type: hash:ip

sudo ipset list ws_2fa_allowed_v6 | head -3
# Expected: Family: inet6, Type: hash:ip

# 4. Verify WireGuard is running
sudo wg show wg0
# Expected: Shows peers with their IPs

# 5. Check if 2FA service is running
sudo systemctl status wireshield-2fa
# Expected: active (running)

# 6. Test 2FA service health
curl -k https://127.0.0.1:8443/health
# Expected: {"status":"ok","service":"wireshield-2fa"}
```

---

### Scenario 4: Multi-Client Test

**Purpose:** Verify firewall gating works with multiple clients

**Setup:**
- Create 2+ clients via CLI
- Connect from different machines/IPs

**Steps:**
1. Create clients
   ```bash
   sudo ./wireshield.sh  # Choose "Add client"
   # Create: alice, bob, charlie
   ```

2. Connect simultaneously with different clients
   ```bash
   # Client 1 (alice): wg-quick up alice.conf
   # Client 2 (bob):   wg-quick up bob.conf
   # Client 3 (charlie): wg-quick up charlie.conf
   ```

3. Verify each needs 2FA independently
   ```
   alice   → Complete 2FA → Has internet
   bob     → Still blocked
   charlie → Still blocked
   ```

4. Complete 2FA for bob and charlie
   ```
   All three now have internet access
   ```

5. Check ipset has all three
   ```bash
   sudo ipset list ws_2fa_allowed_v4
   # Expected: Shows all three IPs (10.66.66.2, 10.66.66.3, 10.66.66.4)
   ```

---

### Scenario 5: DNS Resolution Works Without 2FA

**Purpose:** Verify DNS is allowed even before 2FA completion

**Setup:**
- Fresh connection (just connected, not yet verified 2FA)

**Steps:**
1. Connect to VPN
2. Try DNS resolution
   ```bash
   nslookup google.com
   # Expected: Works! Returns IPs for google.com
   ```

3. Try to ping google.com IP
   ```bash
   ping 142.250.185.46
   # Expected: FAILS (firewall blocks)
   ```

4. Complete 2FA
5. Retry ping
   ```bash
   ping 142.250.185.46
   # Expected: WORKS!
   ```

---

### Scenario 6: Session Pruning (Auto-Revocation)

**Purpose:** Verify background pruning removes expired sessions

**Setup:**
- Set short session timeout in app.py (e.g., 5 minutes instead of 24h)
- Or use direct database manipulation for testing

**Steps:**
1. Complete 2FA with client
2. Verify in allowlist
   ```bash
   sudo ipset list ws_2fa_allowed_v4
   ```

3. Wait for session to expire (5+ minutes with short timeout)
4. Check pruning removed the IP
   ```bash
   sudo ipset list ws_2fa_allowed_v4
   # Expected: Client IP removed
   ```

5. Try to access internet
   ```
   Expected: Blocked (need to re-verify 2FA)
   ```

---

### Scenario 7: Browser Captive Portal Detection

**Purpose:** Test automatic browser captive portal detection (OS-level)

**Supported on:**
- macOS (connects to `detectportal.firefox.com`)
- Windows (connects to `dns.msftncsi.com`)
- Linux (varies by desktop environment)

**Steps:**
1. Connect to VPN on macOS/Windows
2. Check if OS automatically shows login portal
   - macOS: "Sign in to Network" popup
   - Windows: "Captive portal" notification

3. If auto-detected:
   - Browser opens to 2FA page automatically ✓
   
4. If not auto-detected:
   - Manually open `https://vpn-server:8443/`

---

## Performance Metrics

### Expected Performance

| Operation | Expected Time | Tolerance |
|-----------|---------------|-----------|
| VPN connection | < 2s | Depends on network |
| 2FA page load | < 1s | HTTPS latency |
| QR code generation | < 500ms | JavaScript rendering |
| TOTP verification | < 500ms | Server processing |
| Firewall allowlist add | < 100ms | ipset operation |
| Internet access after verification | < 5s | Includes page redirect |
| Session pruning cycle | 60s | Configurable, default 60s |

### Load Test (Multiple Simultaneous 2FA)

```bash
# Test with 10 concurrent verifications
for i in {1..10}; do
  client_id="user$i"
  curl -s -k -X POST https://vpn-server:8443/api/setup-start \
    -d "client_id=$client_id" &
done
wait

# Measure 2FA service load
sudo journalctl -u wireshield-2fa --since "5 minutes ago" | grep -c "verify"
```

---

## Troubleshooting During Tests

### Issue: No internet access after 2FA

**Diagnosis:**
```bash
# 1. Check if client is in allowlist
sudo ipset list ws_2fa_allowed_v4 | grep <client-ip>
# If empty → Service didn't add client

# 2. Check if session exists
sqlite3 /etc/wireshield/2fa/auth.db \
  "SELECT * FROM sessions WHERE expires_at > datetime('now');"

# 3. Check service logs
sudo journalctl -u wireshield-2fa -n 50
# Look for errors

# 4. Check iptables rules
sudo iptables -S FORWARD | grep WS_2FA_PORTAL
```

**Fix:**
- Manually add to ipset: `sudo ipset add ws_2fa_allowed_v4 10.66.66.2`
- Restart service: `sudo systemctl restart wireshield-2fa`

### Issue: Browser doesn't redirect to 2FA page

**Diagnosis:**
```bash
# 1. Test DNAT rule directly
curl -i http://<client-ip>:80/test
# Should return 307 redirect

# 2. Check DNAT rules
sudo iptables -t nat -S | grep WS_2FA_REDIRECT

# 3. Check 2FA service port
sudo ss -tlnp | grep 8443
```

**Fix:**
- Manually visit `https://vpn-server:8443/?client_id=<id>`
- Check port 80 is listening on loopback
- Verify 2FA service is running on 8443

### Issue: Firefox/Safari shows certificate warning

**Expected behavior:**
- Self-signed certificates show security warnings
- Click "Advanced" → "Proceed" or equivalent

**Fix:**
- Add server certificate to system trust store
- Or use Let's Encrypt (requires domain + certbot)

---

## Cleanup After Testing

```bash
# Remove test clients
sudo ./wireshield.sh  # Choose "Remove client"

# Clear audit logs (optional)
sqlite3 /etc/wireshield/2fa/auth.db \
  "DELETE FROM audit_log WHERE timestamp < datetime('now', '-7 days');"

# Disconnect all clients
wg-quick down wg0  # On client machines
```

---

## Success Criteria

✅ All tests pass when:

- [ ] First-time connections trigger 2FA captive portal
- [ ] HTTP requests auto-redirect to HTTPS 2FA page
- [ ] 2FA verification grants full internet access
- [ ] Disconnecting requires re-verification on reconnect
- [ ] DNS works before 2FA (for captive portal)
- [ ] Multiple clients verify independently
- [ ] Sessions persist for 24 hours (or configured duration)
- [ ] Expired sessions are auto-pruned
- [ ] Firewall rules are correctly configured
- [ ] No syntax/runtime errors in app.py or wireshield.sh
- [ ] All audit logs are recorded
