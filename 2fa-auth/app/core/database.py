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
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            device_ip TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES users(client_id)
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
    conn.close()
    logger.info(f"Database initialized at {AUTH_DB_PATH}")

def get_db():
    """Get database connection."""
    conn = sqlite3.connect(AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
