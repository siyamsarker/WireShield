#!/bin/bash

# WireShield 2FA Integration Test
# Validates that the 2FA service is properly installed and functioning

set -e

2FA_DIR="/etc/wireshield/2fa"
2FA_PORT=8443
TEST_CLIENT="test_2fa_client_$$"

echo "=========================================="
echo "WireShield 2FA Integration Test"
echo "=========================================="
echo ""

# Test 1: Check Python availability
echo "[Test 1] Checking Python3..."
if ! command -v python3 &> /dev/null; then
    echo "✗ Python3 not found"
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
echo "✓ $PYTHON_VERSION"
echo ""

# Test 2: Check dependencies
echo "[Test 2] Checking Python dependencies..."
python3 -c "import fastapi, uvicorn, pyotp, qrcode, sqlalchemy, pydantic, cryptography" 2>/dev/null && \
    echo "✓ All required packages installed" || \
    { echo "✗ Missing dependencies"; exit 1; }
echo ""

# Test 3: Check service file
echo "[Test 3] Checking systemd service..."
if systemctl list-unit-files | awk '{print $1}' | grep -q '^wireshield\.service$'; then
    echo "✓ Service unit installed"
else
    echo "⚠ Service unit not installed (not critical for testing)"
fi
echo ""

# Test 4: Check database
echo "[Test 4] Checking 2FA database..."
if [ -f "$2FA_DIR/auth.db" ]; then
    echo "✓ Database exists"
    ROWS=$(sqlite3 "$2FA_DIR/auth.db" "SELECT COUNT(*) FROM users;")
    echo "  Users in database: $ROWS"
else
    echo "⚠ Database doesn't exist yet (will be created on first run)"
fi
echo ""

# Test 5: Test database operations
echo "[Test 5] Testing database operations..."
python3 << 'PYEOF'
import sqlite3
import os

db_path = "/etc/wireshield/2fa/auth.db"
os.makedirs(os.path.dirname(db_path), exist_ok=True)

conn = sqlite3.connect(db_path)
c = conn.cursor()

# Initialize tables
c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    client_id TEXT UNIQUE,
    totp_secret TEXT,
    enabled BOOLEAN DEFAULT 0
)''')

# Test insert
c.execute("DELETE FROM users WHERE client_id = ?", ("test_client",))
c.execute("INSERT INTO users (client_id, enabled) VALUES (?, ?)", ("test_client", 0))
conn.commit()

# Test select
c.execute("SELECT * FROM users WHERE client_id = ?", ("test_client",))
result = c.fetchone()

if result:
    print("✓ Database operations working")
else:
    print("✗ Database insert/select failed")
    exit(1)

conn.close()
PYEOF
echo ""

# Test 6: Test TOTP generation
echo "[Test 6] Testing TOTP (Google Authenticator)..."
python3 << 'PYEOF'
import pyotp
import qrcode

# Generate secret
secret = pyotp.random_base32()
totp = pyotp.TOTP(secret)

# Generate code
code = totp.now()
print(f"✓ TOTP generated: {code}")
print(f"  Secret: {secret}")

# Verify
if totp.verify(code):
    print("✓ TOTP verification working")
else:
    print("✗ TOTP verification failed")
    exit(1)

# Test QR generation
qr = qrcode.QRCode()
qr.add_data(f"otpauth://totp/WireShield:{secret}?issuer=WireShield")
qr.make()
print("✓ QR code generation working")
PYEOF
echo ""

# Test 7: Check SSL certificates
echo "[Test 7] Checking SSL certificates..."
if [ -f "$2FA_DIR/cert.pem" ] && [ -f "$2FA_DIR/key.pem" ]; then
    echo "✓ SSL certificates present"
    EXPIRY=$(openssl x509 -enddate -noout -in "$2FA_DIR/cert.pem" 2>/dev/null | cut -d= -f2)
    echo "  Expiry: $EXPIRY"
else
    echo "⚠ SSL certificates not found (can be generated with generate-certs.sh)"
fi
echo ""

# Test 8: Service status (if installed)
echo "[Test 8] Checking service status..."
if systemctl list-unit-files | awk '{print $1}' | grep -q '^wireshield\.service$'; then
    STATUS=$(systemctl is-active wireshield 2>/dev/null || echo "inactive")
    if [ "$STATUS" = "active" ]; then
        echo "✓ Service is running"
        systemctl status wireshield --no-pager | head -n 5
    else
        echo "⚠ Service is not running (start with: sudo systemctl start wireshield)"
    fi
else
    echo "⚠ Service not yet installed"
fi
echo ""

# Summary
echo "=========================================="
echo "✓ 2FA integration test completed"
echo ""
echo "Next steps:"
echo "1. Install dependencies: pip3 install -r requirements.txt"
echo "2. Generate SSL certs: bash generate-certs.sh"
echo "3. Install service: sudo cp wireshield.service /etc/systemd/system/"
echo "4. Start service: sudo systemctl start wireshield"
echo "5. Access UI: https://127.0.0.1:8443/?client_id=YOUR_CLIENT"
echo "=========================================="
