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

    # Network Policies table: legacy split-tunnel rules (feature removed
    # in 3.0.2, table retained for safe downgrade — will be dropped in a
    # future cleanup migration once no supported upgrade path needs it).
    c.execute('''
        CREATE TABLE IF NOT EXISTS network_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            target_type TEXT NOT NULL DEFAULT 'ip',
            target TEXT NOT NULL,
            resolved_ip TEXT,
            port TEXT,
            protocol TEXT NOT NULL DEFAULT 'any',
            description TEXT,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES users(client_id)
        )
    ''')

    # Agents table: one row per registered agent (Cloudflare-Tunnel-style
    # reverse-connection gateway on a remote LAN). An agent is a special
    # WireGuard peer that claims to reach one or more LAN CIDRs; when a
    # VPN client sends traffic to those CIDRs, the server routes it back
    # out wg0 to the agent, which MASQUERADEs it onto the LAN.
    c.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            public_key TEXT,
            preshared_key TEXT,
            wg_ipv4 TEXT,
            advertised_cidrs TEXT,
            hostname TEXT,
            lan_interface TEXT,
            agent_version TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            last_seen TIMESTAMP,
            last_seen_ip TEXT,
            rx_bytes INTEGER DEFAULT 0,
            tx_bytes INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT,
            enrolled_at TIMESTAMP,
            revoked_at TIMESTAMP
        )
    ''')

    # Agent enrollment tokens: single-use, short-lived credentials that
    # prove an agent has been authorized to enroll. Stored hashed.
    c.execute('''
        CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP,
            used_by_ip TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(id)
        )
    ''')

    # Agent heartbeats: rolling window of per-agent heartbeat samples
    # (online-status sparkline, traffic counters). Pruned by a background
    # task similar to activity_log retention.
    c.execute('''
        CREATE TABLE IF NOT EXISTS agent_heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            agent_version TEXT,
            rx_bytes INTEGER,
            tx_bytes INTEGER,
            FOREIGN KEY (agent_id) REFERENCES agents(id)
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
    try:
        c.execute("CREATE INDEX IF NOT EXISTS idx_network_policies_client ON network_policies(client_id)")
    except Exception:
        pass
    # Migration: add gateway_client_id to network_policies if missing
    try:
        c.execute('ALTER TABLE network_policies ADD COLUMN gateway_client_id TEXT')
    except Exception:
        pass

    # Agent-subsystem indexes
    try:
        c.execute("CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_agents_pubkey ON agents(public_key)")
    except Exception:
        pass

    # Migration: per-user agent allowlist.
    # is_restricted defaults to 0 (false) so every existing agent stays
    # default-allow — no operator action required to keep current behaviour.
    try:
        c.execute("ALTER TABLE agents ADD COLUMN is_restricted INTEGER DEFAULT 0")
    except Exception:
        pass

    # Migration: bearer-token auth for heartbeat/revocation-check endpoints.
    # Replaces source-IP auth so the agent doesn't need to tunnel HTTP through
    # the WG interface. NULL on old rows — those agents must re-enroll.
    try:
        c.execute("ALTER TABLE agents ADD COLUMN heartbeat_secret_hash TEXT")
    except Exception:
        pass

    # Join table: which user (client_id) is permitted to reach an
    # agent's advertised CIDRs. Only consulted when agents.is_restricted=1.
    c.execute('''
        CREATE TABLE IF NOT EXISTS agent_user_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            client_id TEXT NOT NULL,
            granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            granted_by TEXT,
            UNIQUE(agent_id, client_id),
            FOREIGN KEY (agent_id) REFERENCES agents(id)
        )
    ''')
    try:
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_user_access_agent ON agent_user_access(agent_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_user_access_client ON agent_user_access(client_id)")
    except Exception:
        pass
    try:
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_tokens_hash ON agent_enrollment_tokens(token_hash)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_tokens_agent ON agent_enrollment_tokens(agent_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_tokens_expires ON agent_enrollment_tokens(expires_at)")
    except Exception:
        pass
    try:
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_agent_time ON agent_heartbeats(agent_id, received_at)")
    except Exception:
        pass
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {AUTH_DB_PATH}")

def get_db():
    """Get database connection."""
    conn = sqlite3.connect(AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
