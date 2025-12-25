#!/bin/bash
# Test script to verify 2FA access from both VPN and public interfaces

set -e

echo "==================================="
echo "WireShield 2FA Access Test Script"
echo "==================================="
echo ""

# Check if running on server
if [[ ! -f /etc/wireguard/wg0.conf ]]; then
    echo "❌ Error: This script must run on the WireShield server"
    exit 1
fi

echo "✓ WireGuard config found"
echo ""

# Get server IPs
SERVER_PUB_IP=$(grep "^SERVER_PUB_IP=" /etc/wireguard/params 2>/dev/null | cut -d'=' -f2 || echo "unknown")
SERVER_WG_IPV4=$(grep "^SERVER_WG_IPV4=" /etc/wireguard/params 2>/dev/null | cut -d'=' -f2 || echo "10.66.66.1")

echo "Server Public IP: $SERVER_PUB_IP"
echo "Server VPN IP: $SERVER_WG_IPV4"
echo ""

# Test 1: Local loopback access
echo "Test 1: Testing loopback access (127.0.0.1)"
if curl -sk --max-time 5 https://127.0.0.1/health | grep -q '"status":"ok"'; then
    echo "  ✓ Loopback HTTPS: OK"
else
    echo "  ❌ Loopback HTTPS: FAILED"
fi
echo ""

# Test 2: VPN interface access
echo "Test 2: Testing VPN interface ($SERVER_WG_IPV4)"
if curl -sk --max-time 5 "https://$SERVER_WG_IPV4/health" | grep -q '"status":"ok"'; then
    echo "  ✓ VPN HTTPS: OK"
else
    echo "  ❌ VPN HTTPS: FAILED"
fi
echo ""

# Test 3: Public IP access from server
echo "Test 3: Testing public IP from server ($SERVER_PUB_IP)"
if curl -sk --max-time 5 "https://$SERVER_PUB_IP/health" | grep -q '"status":"ok"'; then
    echo "  ✓ Public IP HTTPS: OK"
else
    echo "  ❌ Public IP HTTPS: FAILED (this is OK if behind NAT)"
fi
echo ""

# Test 4: Check iptables rules
echo "Test 4: Checking iptables DNAT rules"
if sudo iptables -t nat -L PREROUTING -n | grep -q "DNAT.*tcp dpt:443"; then
    echo "  ✓ DNAT rule for port 443 exists"
else
    echo "  ❌ DNAT rule for port 443 missing"
fi

if sudo iptables -t nat -L PREROUTING -n | grep -q "DNAT.*tcp dpt:80"; then
    echo "  ✓ DNAT rule for port 80 exists"
else
    echo "  ❌ DNAT rule for port 80 missing"
fi
echo ""

# Test 5: Check if 2FA service is running
echo "Test 5: Checking 2FA service status"
if systemctl is-active --quiet wireshield-2fa; then
    echo "  ✓ 2FA service is active"
else
    echo "  ❌ 2FA service is not running"
fi
echo ""

echo "==================================="
echo "Test Summary"
echo "==================================="
echo ""
echo "Next steps:"
echo "1. Connect to VPN from your client"
echo "2. Try accessing: https://$SERVER_PUB_IP/"
echo "3. Should work from both public IP and VPN IP ($SERVER_WG_IPV4)"
echo ""
