#!/bin/bash

# Generate self-signed SSL certificates for WireShield 2FA service
# Usage: ./generate-certs.sh [days] [hostname-or-ip]
#   days            - certificate validity in days (default: 365)
#   hostname-or-ip  - subjectAltName for the cert (default: WS_HOSTNAME_2FA
#                     from config.env, falling back to the host's public IP)

DAYS=${1:-365}
CERT_DIR="/etc/wireshield/2fa"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"
CONFIG_FILE="$CERT_DIR/config.env"

set -e

HOST="$2"

if [[ -z "$HOST" ]] && [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
    HOST="$WS_HOSTNAME_2FA"
fi

if [[ -z "$HOST" ]]; then
    HOST=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
fi

if [[ -z "$HOST" ]]; then
    echo "[!] Could not auto-detect a hostname/IP; defaulting to 'localhost'."
    echo "    Pass one explicitly: $0 [days] <hostname-or-ip>"
    HOST="localhost"
fi

# Browsers ignore CN and require subjectAltName; pick the right SAN type.
if [[ "$HOST" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    SAN="IP:${HOST}"
else
    SAN="DNS:${HOST}"
fi

# Create directory
mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

# Generate self-signed certificate
echo "[*] Generating self-signed SSL certificate for ${HOST}..."
openssl req \
    -x509 \
    -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days "$DAYS" \
    -nodes \
    -subj "/C=US/ST=State/L=City/O=WireShield/CN=${HOST}" \
    -addext "subjectAltName=${SAN}" \
    2>/dev/null

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo "[✓] SSL certificates generated:"
echo "    Certificate: $CERT_FILE"
echo "    Private Key: $KEY_FILE"
echo "    Hostname:    $HOST"
echo "    Valid for:   $DAYS days"
echo ""
echo "[!] Note: This is a self-signed certificate. Clients must trust it or be configured to skip verification."
