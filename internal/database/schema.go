package database

const Schema = `
-- Clients table: stores client metadata and configuration
CREATE TABLE IF NOT EXISTS clients (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	public_key TEXT NOT NULL UNIQUE,
	allowed_ips TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	expires_at DATETIME,
	revoked_at DATETIME,
	enabled BOOLEAN DEFAULT 1,
	total_rx_bytes INTEGER DEFAULT 0,
	total_tx_bytes INTEGER DEFAULT 0,
	last_handshake DATETIME,
	endpoint TEXT,
	notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_clients_name ON clients(name);
CREATE INDEX IF NOT EXISTS idx_clients_public_key ON clients(public_key);
CREATE INDEX IF NOT EXISTS idx_clients_enabled ON clients(enabled);
CREATE INDEX IF NOT EXISTS idx_clients_revoked ON clients(revoked_at);

-- Audit logs: track all administrative actions
CREATE TABLE IF NOT EXISTS audit_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
	username TEXT NOT NULL,
	action TEXT NOT NULL,
	resource_type TEXT NOT NULL,
	resource_name TEXT NOT NULL,
	ip_address TEXT,
	user_agent TEXT,
	details TEXT,
	success BOOLEAN DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_logs(username);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);

-- Bandwidth stats: periodic bandwidth snapshots for graphing
CREATE TABLE IF NOT EXISTS bandwidth_stats (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
	client_id INTEGER,
	rx_bytes INTEGER DEFAULT 0,
	tx_bytes INTEGER DEFAULT 0,
	FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_bandwidth_timestamp ON bandwidth_stats(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_bandwidth_client ON bandwidth_stats(client_id);

-- System metrics: server resource usage history
CREATE TABLE IF NOT EXISTS system_metrics (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
	cpu_percent REAL DEFAULT 0,
	mem_used_bytes INTEGER DEFAULT 0,
	mem_used_percent REAL DEFAULT 0,
	total_rx_bytes INTEGER DEFAULT 0,
	total_tx_bytes INTEGER DEFAULT 0,
	active_peers INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON system_metrics(timestamp DESC);

-- Settings: key-value store for server configuration
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Sessions: active user sessions (optional enhancement over cookie-only)
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	expires_at DATETIME NOT NULL,
	ip_address TEXT,
	user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Migration tracking
CREATE TABLE IF NOT EXISTS migrations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	version TEXT NOT NULL UNIQUE,
	applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO migrations (version) VALUES ('v2.1.0_initial');
`
