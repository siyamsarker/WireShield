import os
import sqlite3
import logging
from app.core.config import AUTH_DB_PATH

logger = logging.getLogger(__name__)

def init_db():
    """Initialize or migrate SQLite database."""
    os.makedirs(os.path.dirname(AUTH_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    
    # Users table: stores 2FA secrets and metadata
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT UNIQUE NOT NULL,
            totp_secret TEXT,
            backup_codes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            enabled BOOLEAN DEFAULT 1,
            console_access BOOLEAN DEFAULT 0
        )
    ''')
    
    # Sessions table: tracks active 2FA sessions
    c.execute('''
        create table if not exists sessions (
            id integer primary key autoincrement,
            client_id text not null,
            session_token text unique not null,
            expires_at timestamp not null,
            device_ip text,
            created_at timestamp default current_timestamp,
            foreign key (client_id) references users(client_id)
        )
    ''')

    # Bandwidth Usage table: tracks daily RX/TX bytes per client
    c.execute('''
        CREATE TABLE IF NOT EXISTS bandwidth_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            scan_date DATE NOT NULL,
            rx_bytes INTEGER DEFAULT 0,
            tx_bytes INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(client_id, scan_date)
        )
    ''')
    
    # Audit log table: security audit trail
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT,
            action TEXT NOT NULL,
            status TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # DNS Cache table: stores IP->Domain mappings from sniffer
    c.execute('''
        CREATE TABLE IF NOT EXISTS dns_cache (
            ip_address TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Activity Log table: stores parsed WireGuard/iptables audit events
    c.execute('''
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            client_id TEXT,
            direction TEXT,
            protocol TEXT,
            src_ip TEXT,
            src_port TEXT,
            dst_ip TEXT,
            dst_port TEXT,
            raw_line TEXT,
            line_hash TEXT UNIQUE
        )
    ''')

    # Activity Log metrics table: tracks cleanup/retention stats
    c.execute('''
        CREATE TABLE IF NOT EXISTS activity_log_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            last_cleanup_at TIMESTAMP,
            deleted_rows INTEGER DEFAULT 0,
            remaining_rows INTEGER DEFAULT 0
        )
    ''')
    
    conn.commit()
    # Migrations: add wg_ipv4/wg_ipv6 columns if missing
    try:
        c.execute('ALTER TABLE users ADD COLUMN wg_ipv4 TEXT')
    except Exception:
        pass
    try:
        c.execute('ALTER TABLE users ADD COLUMN wg_ipv6 TEXT')
    except Exception:
        pass
    try:
        c.execute('ALTER TABLE users ADD COLUMN console_access BOOLEAN DEFAULT 0')
    except Exception:
        pass

    # Performance indexes
    try:
        c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_client_expires ON sessions(client_id, expires_at)")
    except Exception:
        pass
    try:
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_client ON audit_log(client_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_status ON audit_log(status)")
    except Exception:
        pass
    try:
        c.execute("CREATE INDEX IF NOT EXISTS idx_dns_cache_domain ON dns_cache(domain)")
    except Exception:
        pass
    try:
        c.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_timestamp ON activity_log(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_client ON activity_log(client_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_src ON activity_log(src_ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_dst ON activity_log(dst_ip)")
    except Exception:
        pass
    conn.close()
    logger.info(f"Database initialized at {AUTH_DB_PATH}")

def get_db():
    """Get database connection."""
    conn = sqlite3.connect(AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
