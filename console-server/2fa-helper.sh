#!/bin/bash

# WireShield 2FA Audit Log Helper
# Invoked by wireshield.sh's "View Audit Logs" menu.

set -e

DB_PATH="/etc/wireshield/2fa/auth.db"

error() {
    echo "[ERROR] $*" >&2
    return 1
}

# ============================================================================
# Audit Logs
# ============================================================================

view_audit_logs_all() {
    echo "=== WireShield Audit Logs (All Users) ==="
    echo ""

    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()

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

header = 'Timestamp'.ljust(20) + 'Client'.ljust(15) + 'Action'.ljust(20) + 'Status'.ljust(15) + 'IP Address'.ljust(20)
print(header)
print('=' * 90)

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
conn = sqlite3.connect('$DB_PATH')
c = conn.cursor()

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

header = 'Timestamp'.ljust(20) + 'Action'.ljust(20) + 'Status'.ljust(15) + 'IP Address'.ljust(20)
print(header)
print('=' * 75)

for log in logs:
    timestamp, client_id, action, status, ip_address = log
    print(f'{timestamp:<20} {action:<20} {status:<15} {ip_address:<20}')

print('')
print(f'Total logs for $client_id: {len(logs)}')
"
}

get_audit_stats() {
    echo "=== Audit Log Statistics ==="
    echo ""

    python3 -c "
import sqlite3
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
rows = c.fetchall()
conn.close()

with open('$output_file', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'Client ID', 'Action', 'Status', 'IP Address'])
    writer.writerows(rows)

print(f'[✓] Exported {len(rows)} logs to $output_file')
"
}

# ============================================================================
# Main
# ============================================================================

case "$1" in
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
        echo "WireShield 2FA Audit Log Helper"
        echo "Usage: $0 {audit-logs|audit-logs-user|audit-stats|export-audit} [args]"
        echo ""
        echo "Commands:"
        echo "  audit-logs                  - View all audit logs (last 100)"
        echo "  audit-logs-user <client_id> - View audit logs for specific user"
        echo "  audit-stats                 - Show audit log statistics"
        echo "  export-audit [file]         - Export audit logs to CSV"
        exit 1
        ;;
esac
