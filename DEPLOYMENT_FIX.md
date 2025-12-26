# WireShield Deployment Fix Guide

## 🔴 Critical Issue Identified and Resolved

**Problem**: Users could verify 2FA successfully but had no internet access afterward.

**Root Cause**: Firewall rule ordering bug caused ALL traffic to be blocked before checking the verified-client allowlist.

---

## 🛠️ Fix for Existing Deployments

If you deployed WireShield **before commit `223dbcd`**, follow these steps to fix your server:

### Option 1: Quick Reinstall (Recommended - 2 minutes)

```bash
# On your VPN server
cd ~/WireShield
git pull
sudo ./wireshield.sh

# Choose option 3 "Uninstall WireGuard" first
# Then run again and choose option 1 "Install WireGuard"
# Re-add your clients afterward
```

### Option 2: Manual Firewall Rule Fix (Advanced - 5 minutes)

```bash
# SSH into your VPN server
sudo -i

# 1. Stop WireGuard
systemctl stop wg-quick@wg0

# 2. Backup current config
cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.backup

# 3. Edit the config file
nano /etc/wireguard/wg0.conf
```

**Find these lines** (around line 10-15):
```bash
PostUp = iptables -A WS_2FA_PORTAL -p tcp --dport 53 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -p udp --dport 53 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -j DROP
PostUp = iptables -I FORWARD -i wg0 -m set --match-set ws_2fa_allowed_v4 src -j ACCEPT
PostUp = iptables -A FORWARD -i wg0 -j WS_2FA_PORTAL
```

**Replace with** (note the changes on lines 3-5):
```bash
PostUp = iptables -A WS_2FA_PORTAL -p tcp --dport 53 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -p udp --dport 53 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -d 10.66.66.1 -p tcp --dport 443 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -d 10.66.66.1 -p tcp --dport 80 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -j DROP
PostUp = iptables -A FORWARD -i wg0 -m set --match-set ws_2fa_allowed_v4 src -j ACCEPT
PostUp = iptables -A FORWARD -i wg0 -j WS_2FA_PORTAL
```

**Also find these IPv6 lines**:
```bash
PostUp = ip6tables -A WS_2FA_PORTAL6 -p tcp --dport 53 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -p udp --dport 53 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -j DROP
PostUp = ip6tables -I FORWARD -i wg0 -m set --match-set ws_2fa_allowed_v6 src -j ACCEPT
PostUp = ip6tables -A FORWARD -i wg0 -j WS_2FA_PORTAL6
```

**Replace with**:
```bash
PostUp = ip6tables -A WS_2FA_PORTAL6 -p tcp --dport 53 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -p udp --dport 53 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -p tcp --dport 443 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -p tcp --dport 80 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -j DROP
PostUp = ip6tables -A FORWARD -i wg0 -m set --match-set ws_2fa_allowed_v6 src -j ACCEPT
PostUp = ip6tables -A FORWARD -i wg0 -j WS_2FA_PORTAL6
```

**Save and exit** (Ctrl+X, Y, Enter in nano)

```bash
# 4. Restart WireGuard
systemctl start wg-quick@wg0

# 5. Restart 2FA service
systemctl restart wireshield-2fa

# 6. Verify everything is working
systemctl status wg-quick@wg0
systemctl status wireshield-2fa
wg show
```

---

## ✅ Verification Steps

After applying the fix:

1. **Connect client to VPN**
2. **Complete 2FA verification** (scan QR or enter code)
3. **Test internet access**:
   ```bash
   # From client
   ping 1.1.1.1
   curl https://ipinfo.io
   ```

4. **Check server logs**:
   ```bash
   sudo journalctl -u wireshield-2fa -n 50 --no-pager
   sudo wg show wg0
   sudo ipset list ws_2fa_allowed_v4
   ```

Expected results:
- ✅ Ping succeeds
- ✅ HTTP requests work
- ✅ Client IP appears in `ipset list ws_2fa_allowed_v4`
- ✅ `wg show wg0` displays recent handshake timestamp
- ✅ Session appears in logs as "2FA_VERIFY - success"

---

## 🔍 Technical Details

### What Was Wrong?

The firewall FORWARD chain had rules in the wrong order:

**BEFORE (Broken)**:
```
1. iptables -I FORWARD ... (insert at position 0) ← Allowlist check
2. iptables -A FORWARD ... (append at end)        ← Portal DROP chain
```

Because `-I` inserted at position 0 and `-A` appended at the end, **the evaluation order was reversed**:
1. First rule added with `-A` became rule #1
2. Second rule added with `-I` was inserted BEFORE it, becoming rule #1
3. **Result**: Portal DROP chain was checked BEFORE allowlist

**AFTER (Fixed)**:
```
1. iptables -A FORWARD ... ← Allowlist check (verified 2FA users)
2. iptables -A FORWARD ... ← Portal chain (DNS + 2FA portal + DROP)
```

Both use `-A` (append), so rules are evaluated in the correct order:
1. Check ipset allowlist → ACCEPT if verified
2. If not verified, check portal chain → ACCEPT DNS/portal, DROP others

### Why DNS Worked But Internet Didn't

- DNS (port 53) was explicitly allowed in the `WS_2FA_PORTAL` chain
- General internet traffic wasn't in the allowlist and hit the DROP rule
- After 2FA verification, the client IP was added to `ws_2fa_allowed_v4` ipset
- **But** the allowlist check happened AFTER the DROP, so it was never reached

---

## 📊 Impact Timeline

| Version | Status | Description |
|---------|--------|-------------|
| Before `223dbcd` | 🔴 Broken | Internet blocked after 2FA |
| Commit `223dbcd` | ✅ Fixed | Proper firewall rule ordering |
| After `223dbcd` | ✅ Working | Full internet access post-2FA |

---

## 🆘 Still Having Issues?

### Check #1: Firewall Rules Order
```bash
sudo iptables -L FORWARD -n -v --line-numbers
```

Expected output should show:
```
1. ACCEPT from wg0 matching ipset ws_2fa_allowed_v4
2. WS_2FA_PORTAL chain check
```

### Check #2: IPSet Contents
```bash
sudo ipset list ws_2fa_allowed_v4
```

Your client IP (e.g., `10.66.66.2`) should appear after 2FA verification.

### Check #3: WireGuard Handshake
```bash
sudo wg show wg0
```

Look for `latest handshake: X seconds ago` - should be recent (< 30 seconds if client is active).

### Check #4: Session Database
```bash
sudo sqlite3 /etc/wireshield/2fa/auth.db 'SELECT client_id, ip_address, expires_at FROM sessions;'
```

Should show active session for your client.

### Check #5: Service Logs
```bash
sudo journalctl -u wireshield-2fa -f
```

Watch for:
- ✅ `Audit: 2FA_VERIFY - success`
- ❌ `SESSION_MONITOR - expired_on_disconnect` (means client disconnected)

---

## 📞 Support

If you're still experiencing issues after applying this fix:

1. Gather diagnostics:
   ```bash
   sudo iptables -L -n -v > /tmp/iptables.txt
   sudo wg show > /tmp/wg-status.txt
   sudo ipset list > /tmp/ipset.txt
   sudo journalctl -u wireshield-2fa -n 100 --no-pager > /tmp/2fa-logs.txt
   ```

2. Open an issue on GitHub with the diagnostic files attached

---

## ✅ Fresh Deployments

If you're deploying WireShield for the first time **after commit `223dbcd`**, you don't need to do anything - the fix is already included! Just run:

```bash
git clone https://github.com/siyamsarker/WireShield.git
cd WireShield
sudo ./wireshield.sh
```

---

**Last Updated**: December 26, 2025  
**Applies To**: WireShield v2.3.0 and earlier  
**Fixed In**: Commit `223dbcd` and later
