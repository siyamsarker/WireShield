# 🚨 EMERGENCY FIX - No Internet After 2FA

## Problem
✅ 2FA verification succeeds  
❌ No internet access  
✅ DNS works (can ping 1.1.1.1 but not google.com)

## Quick Fix (60 seconds)

### On Your VPN Server:

```bash
# Stop WireGuard
sudo systemctl stop wg-quick@wg0

# Edit config
sudo nano /etc/wireguard/wg0.conf
```

### Find This Section:
```bash
PostUp = iptables -A WS_2FA_PORTAL -j DROP
PostUp = iptables -I FORWARD -i wg0 -m set --match-set ws_2fa_allowed_v4 src -j ACCEPT
PostUp = iptables -A FORWARD -i wg0 -j WS_2FA_PORTAL
```

### Change The Line With `-I` to `-A`:
```bash
PostUp = iptables -A WS_2FA_PORTAL -j DROP
PostUp = iptables -A FORWARD -i wg0 -m set --match-set ws_2fa_allowed_v4 src -j ACCEPT  # Changed -I to -A
PostUp = iptables -A FORWARD -i wg0 -j WS_2FA_PORTAL
```

### Add 2FA Portal Access (Insert BEFORE the DROP line):
```bash
PostUp = iptables -A WS_2FA_PORTAL -p tcp --dport 53 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -p udp --dport 53 -j ACCEPT
PostUp = iptables -A WS_2FA_PORTAL -d 10.66.66.1 -p tcp --dport 443 -j ACCEPT  # ADD THIS
PostUp = iptables -A WS_2FA_PORTAL -d 10.66.66.1 -p tcp --dport 80 -j ACCEPT   # ADD THIS
PostUp = iptables -A WS_2FA_PORTAL -j DROP
```

### Do The Same For IPv6:
```bash
# Find:
PostUp = ip6tables -I FORWARD -i wg0 -m set --match-set ws_2fa_allowed_v6 src -j ACCEPT

# Change to:
PostUp = ip6tables -A FORWARD -i wg0 -m set --match-set ws_2fa_allowed_v6 src -j ACCEPT  # Changed -I to -A
```

```bash
# Add portal access:
PostUp = ip6tables -A WS_2FA_PORTAL6 -p tcp --dport 53 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -p udp --dport 53 -j ACCEPT
PostUp = ip6tables -A WS_2FA_PORTAL6 -p tcp --dport 443 -j ACCEPT  # ADD THIS
PostUp = ip6tables -A WS_2FA_PORTAL6 -p tcp --dport 80 -j ACCEPT   # ADD THIS
PostUp = ip6tables -A WS_2FA_PORTAL6 -j DROP
```

### Save and Restart:
```bash
# Save: Ctrl+X, Y, Enter

# Restart
sudo systemctl start wg-quick@wg0
sudo systemctl restart wireshield-2fa

# Verify
sudo wg show
```

## Test From Client:
```bash
# Reconnect VPN
# Complete 2FA
# Test internet
ping 8.8.8.8
curl https://google.com
```

## ✅ Should Work Now!

---

## Alternative: Clean Reinstall (Easier - 2 minutes)

```bash
cd ~/WireShield
git pull
sudo ./wireshield.sh
# → Choose "3" to uninstall
# → Run again, choose "1" to install
# → Re-add clients
```

---

**Still broken?** See [DEPLOYMENT_FIX.md](DEPLOYMENT_FIX.md) for detailed troubleshooting.
