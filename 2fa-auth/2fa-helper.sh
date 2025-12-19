#!/bin/bash

# WireShield 2FA Service Management Helper
# This script integrates 2FA authentication with WireGuard clients

set -e

LOG_FILE="/var/log/wireshield-2fa.log"
DB_PATH="/etc/wireshield/2fa/auth.db"
CONFIG_DIR="/etc/wireshield/clients"
2FA_PORT=8443

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

error() {
    echo "[ERROR] $*" | tee -a "$LOG_FILE" >&2
    return 1
}

# ============================================================================
# Installation & Setup
# ============================================================================

install_2fa_dependencies() {
    log "Installing Python dependencies for 2FA service..."
    
    if command -v pip3 &> /dev/null; then
        pip3 install -q --upgrade pip setuptools wheel 2>&1 | tee -a "$LOG_FILE"
        pip3 install -q -r /etc/wireshield/2fa/requirements.txt 2>&1 | tee -a "$LOG_FILE"
    else
        error "pip3 not found. Please install python3-pip."
        return 1
    fi
    
    log "Python dependencies installed successfully"
}

setup_2fa_service() {
    log "Setting up 2FA systemd service..."
    
    # Create 2FA directory
    mkdir -p /etc/wireshield/2fa
    chmod 700 /etc/wireshield/2fa
    
    # Copy service file
    cp /opt/wireshield/2fa-auth/wireshield-2fa.service /etc/systemd/system/ 2>/dev/null || true
    
    # Generate SSL certs if needed
    if [ ! -f /etc/wireshield/2fa/cert.pem ] || [ ! -f /etc/wireshield/2fa/key.pem ]; then
        bash /etc/wireshield/2fa/generate-certs.sh 365
    fi
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable wireshield-2fa
    systemctl restart wireshield-2fa
    
    log "2FA service installed and started"
}

# ============================================================================
# Client Management
# ============================================================================

enable_2fa_for_client() {
    local client_id="$1"
    
    if [ -z "$client_id" ]; then
        error "Usage: enable_2fa_for_client <client_id>"
        return 1
    fi
    
    log "Enabling 2FA for client: $client_id"
    
    # Initialize user in 2FA database
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()
c.execute('SELECT id FROM users WHERE client_id = ?', ('$client_id',))
if not c.fetchone():
    c.execute('INSERT INTO users (client_id, enabled) VALUES (?, ?)', ('$client_id', 0))
    conn.commit()
    print('[✓] Client initialized for 2FA')
else:
    print('[!] Client already in 2FA system')
conn.close()
" 2>&1 | tee -a "$LOG_FILE"
}

disable_2fa_for_client() {
    local client_id="$1"
    
    if [ -z "$client_id" ]; then
        error "Usage: disable_2fa_for_client <client_id>"
        return 1
    fi
    
    log "Disabling 2FA for client: $client_id"
    
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()
c.execute('UPDATE users SET enabled = 0 WHERE client_id = ?', ('$client_id',))
c.execute('DELETE FROM sessions WHERE client_id = ?', ('$client_id',))
conn.commit()
conn.close()
print('[✓] 2FA disabled for client')
" 2>&1 | tee -a "$LOG_FILE"
}

get_2fa_status() {
    local client_id="$1"
    
    if [ -z "$client_id" ]; then
        error "Usage: get_2fa_status <client_id>"
        return 1
    fi
    
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()
c.execute('SELECT enabled, created_at FROM users WHERE client_id = ?', ('$client_id',))
result = c.fetchone()
conn.close()

if result:
    enabled, created = result
    status = '✓ Enabled' if enabled else '✗ Disabled'
    print(f'Client: $client_id')
    print(f'Status: {status}')
    print(f'Setup Date: {created}')
else:
    print('Client not found in 2FA system')
"
}

# ============================================================================
# Verification Helpers
# ============================================================================

validate_session() {
    local client_id="$1"
    local session_token="$2"
    
    if [ -z "$client_id" ] || [ -z "$session_token" ]; then
        error "Usage: validate_session <client_id> <session_token>"
        return 1
    fi
    
    curl -s -k \
        -X POST \
        https://127.0.0.1:$2FA_PORT/api/validate-session \
        -d "client_id=$client_id&session_token=$session_token" | jq .
}

check_2fa_service_status() {
    echo "=== WireShield 2FA Service Status ==="
    systemctl status wireshield-2fa || true
    echo ""
    echo "Database: $DB_PATH ($([ -f "$DB_PATH" ] && echo "✓ exists" || echo "✗ missing"))"
    echo "Service listening on: 127.0.0.1:$2FA_PORT"
}

# ============================================================================
# Cleanup
# ============================================================================

cleanup_expired_sessions() {
    log "Cleaning up expired 2FA sessions..."
    
    python3 -c "
import sqlite3
from datetime import datetime
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()
c.execute('DELETE FROM sessions WHERE expires_at < datetime(\"now\")')
deleted = c.rowcount
conn.commit()
conn.close()
print(f'[✓] Deleted {deleted} expired sessions')
"
}

# ============================================================================
# Main
# ============================================================================

case "$1" in
    install)
        install_2fa_dependencies
        setup_2fa_service
        ;;
    enable)
        enable_2fa_for_client "$2"
        ;;
    disable)
        disable_2fa_for_client "$2"
        ;;
    status)
        get_2fa_status "$2"
        ;;
    validate-session)
        validate_session "$2" "$3"
        ;;
    service-status)
        check_2fa_service_status
        ;;
    cleanup-sessions)
        cleanup_expired_sessions
        ;;
    *)
        echo "WireShield 2FA Helper - Service Management"
        echo "Usage: $0 {install|enable|disable|status|validate-session|service-status|cleanup-sessions} [args]"
        echo ""
        echo "Commands:"
        echo "  install                     - Install 2FA service and dependencies"
        echo "  enable <client_id>          - Enable 2FA for a client"
        echo "  disable <client_id>         - Disable 2FA for a client"
        echo "  status <client_id>          - Show 2FA status for a client"
        echo "  validate-session <id> <tk>  - Validate a session token"
        echo "  service-status              - Check 2FA service status"
        echo "  cleanup-sessions            - Remove expired sessions"
        exit 1
        ;;
esac
