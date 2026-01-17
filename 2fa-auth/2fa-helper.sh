#!/bin/bash

# WireShield 2FA Service Management Helper
# This script integrates 2FA authentication with WireGuard clients

set -e

LOG_FILE="/var/log/wireshield-2fa.log"
DB_PATH="/etc/wireshield/2fa/auth.db"
CONFIG_DIR="/etc/wireshield/clients"
# Use a bash-safe variable name
WS_2FA_PORT=8443

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
    cp /opt/wireshield/2fa-auth/wireshield.service /etc/systemd/system/ 2>/dev/null || true
    
    # Generate SSL certs if needed
    if [ ! -f /etc/wireshield/2fa/cert.pem ] || [ ! -f /etc/wireshield/2fa/key.pem ]; then
        bash /etc/wireshield/2fa/generate-certs.sh 365
    fi
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable wireshield
    systemctl restart wireshield
    
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
        https://127.0.0.1:$WS_2FA_PORT/api/validate-session \
        -d "client_id=$client_id&session_token=$session_token" | jq .
}

check_2fa_service_status() {
    echo "=== WireShield 2FA Service Status ==="
    systemctl status wireshield || true
    echo ""
    echo "Database: $DB_PATH ($([ -f "$DB_PATH" ] && echo "✓ exists" || echo "✗ missing"))"
    echo "Service listening on: 127.0.0.1:$WS_2FA_PORT"
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
# Audit Logs
# ============================================================================

view_audit_logs_all() {
    echo "=== WireShield Audit Logs (All Users) ==="
    echo ""
    
    python3 -c "
import sqlite3
from datetime import datetime
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()

# Get all audit logs
c.execute('''
    SELECT timestamp, client_id, action, status, ip_address 
    FROM audit_log 
    ORDER BY timestamp DESC 
    LIMIT 100
''')

logs = c.fetchall()
conn.close()

if not logs:
    print('No audit logs found')
    exit(0)

# Print header
print(f'{'Timestamp':<20} {'Client':<15} {'Action':<20} {'Status':<15} {'IP Address':<20}')
print('=' * 90)

# Print logs
for log in logs:
    timestamp, client_id, action, status, ip_address = log
    print(f'{timestamp:<20} {str(client_id):<15} {action:<20} {status:<15} {ip_address:<20}')

print('')
print(f'Total logs shown: {len(logs)}')
"
}

view_audit_logs_user() {
    local client_id="$1"
    
    if [ -z "$client_id" ]; then
        error "Usage: view_audit_logs_user <client_id>"
        return 1
    fi
    
    echo "=== WireShield Audit Logs for User: $client_id ==="
    echo ""
    
    python3 -c "
import sqlite3
from datetime import datetime
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()

# Get audit logs for specific client
c.execute('''
    SELECT timestamp, client_id, action, status, ip_address 
    FROM audit_log 
    WHERE client_id = ?
    ORDER BY timestamp DESC 
    LIMIT 100
''', ('$client_id',))

logs = c.fetchall()
conn.close()

if not logs:
    print(f'No audit logs found for client: $client_id')
    exit(0)

# Print header
print(f'{'Timestamp':<20} {'Action':<20} {'Status':<15} {'IP Address':<20}')
print('=' * 75)

# Print logs
for log in logs:
    timestamp, client_id, action, status, ip_address = log
    print(f'{timestamp:<20} {action:<20} {status:<15} {ip_address:<20}')

print('')
print(f'Total logs for {client_id}: {len(logs)}')
"
}

get_audit_stats() {
    echo "=== Audit Log Statistics ==="
    echo ""
    
    python3 -c "
import sqlite3
from datetime import datetime
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()

# Total logs
c.execute('SELECT COUNT(*) FROM audit_log')
total = c.fetchone()[0]

# Logs by action
c.execute('''
    SELECT action, COUNT(*) as count 
    FROM audit_log 
    GROUP BY action 
    ORDER BY count DESC
''')
actions = c.fetchall()

# Failed attempts
c.execute(\"\"\"
    SELECT COUNT(*) FROM audit_log 
    WHERE status LIKE '%fail%' OR status = 'invalid_code'
\"\"\")
failed = c.fetchone()[0]

# Successful authentications
c.execute(\"\"\"
    SELECT COUNT(*) FROM audit_log 
    WHERE status = 'success' AND action LIKE '%VERIFY%'
\"\"\")
success = c.fetchone()[0]

# Unique clients
c.execute('SELECT COUNT(DISTINCT client_id) FROM audit_log')
unique_clients = c.fetchone()[0]

conn.close()

print(f'Total Audit Logs: {total}')
print(f'Unique Clients: {unique_clients}')
print(f'Successful 2FA Verifications: {success}')
print(f'Failed Attempts: {failed}')
print('')
print('Actions Summary:')
for action, count in actions:
    print(f'  {action}: {count}')
"
}

export_audit_logs() {
    local output_file="${1:-/tmp/wireshield_audit_logs.csv}"
    
    echo "Exporting audit logs to: $output_file"
    
    python3 -c "
import sqlite3
import csv
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()

c.execute('''
    SELECT timestamp, client_id, action, status, ip_address 
    FROM audit_log 
    ORDER BY timestamp DESC
''')

with open('$output_file', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'Client ID', 'Action', 'Status', 'IP Address'])
    writer.writerows(c.fetchall())

conn.close()
print(f'[✓] Exported {c.rowcount} logs to {$output_file}')
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
    audit-logs)
        view_audit_logs_all
        ;;
    audit-logs-user)
        view_audit_logs_user "$2"
        ;;
    audit-stats)
        get_audit_stats
        ;;
    export-audit)
        export_audit_logs "$2"
        ;;
    *)
        echo "WireShield 2FA Helper - Service Management"
        echo "Usage: $0 {install|enable|disable|status|validate-session|service-status|cleanup-sessions|audit-logs|audit-logs-user|audit-stats|export-audit} [args]"
        echo ""
        echo "Commands:"
        echo "  install                     - Install 2FA service and dependencies"
        echo "  enable <client_id>          - Enable 2FA for a client"
        echo "  disable <client_id>         - Disable 2FA for a client"
        echo "  status <client_id>          - Show 2FA status for a client"
        echo "  validate-session <id> <tk>  - Validate a session token"
        echo "  service-status              - Check 2FA service status"
        echo "  cleanup-sessions            - Remove expired sessions"
        echo "  audit-logs                  - View all audit logs (last 100)"
        echo "  audit-logs-user <client_id> - View audit logs for specific user"
        echo "  audit-stats                 - Show audit log statistics"
        echo "  export-audit [file]         - Export audit logs to CSV"
        exit 1
        ;;
esac
