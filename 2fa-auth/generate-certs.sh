#!/bin/bash

# Generate self-signed SSL certificates for WireShield 2FA service
# Usage: ./generate-certs.sh [days]

DAYS=${1:-365}
CERT_DIR="/etc/wireshield/2fa"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

set -e

# Create directory
mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

# Generate self-signed certificate
echo "[*] Generating self-signed SSL certificate for WireShield 2FA..."
openssl req \
    -x509 \
    -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days "$DAYS" \
    -nodes \
    -subj "/C=US/ST=State/L=City/O=WireShield/CN=wireshield-2fa" \
    2>/dev/null

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo "[✓] SSL certificates generated:"
echo "    Certificate: $CERT_FILE"
echo "    Private Key: $KEY_FILE"
echo "    Valid for: $DAYS days"
echo ""
echo "[!] Note: This is a self-signed certificate. Clients must trust it or be configured to skip verification."
