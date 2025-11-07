package database

// Schema defines the complete SQLite database structure for WireShield.
// This includes tables for client management, audit logging, metrics tracking,
// and system configuration. All tables use appropriate indexes for query performance.
const Schema = `
-- ============================================================================
-- CLIENTS TABLE
-- ============================================================================
-- Stores WireGuard client configurations, connection metadata, and bandwidth stats.
-- Each client represents a device/user with VPN access to the server.
CREATE TABLE IF NOT EXISTS clients (
	id INTEGER PRIMARY KEY AUTOINCREMENT,           -- Unique identifier for each client
	name TEXT NOT NULL UNIQUE,                       -- Human-readable client name (e.g., "alice-laptop")
	public_key TEXT NOT NULL UNIQUE,                 -- WireGuard public key for authentication
	allowed_ips TEXT NOT NULL,                       -- CIDR ranges client is allowed to use (e.g., "10.7.0.2/32")
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,   -- When the client was first added
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,   -- Last modification timestamp
	expires_at DATETIME,                             -- Optional expiration date for temporary access
	revoked_at DATETIME,                             -- When the client was revoked (NULL if active)
	enabled BOOLEAN DEFAULT 1,                       -- Whether client is currently enabled (1=yes, 0=no)
	total_rx_bytes INTEGER DEFAULT 0,                -- Total bytes received (download)
	total_tx_bytes INTEGER DEFAULT 0,                -- Total bytes transmitted (upload)
	last_handshake DATETIME,                         -- Last successful WireGuard handshake
	endpoint TEXT,                                   -- Client's current IP:port endpoint
	notes TEXT                                       -- Optional admin notes about this client
);

-- Performance indexes for common queries
CREATE INDEX IF NOT EXISTS idx_clients_name ON clients(name);
CREATE INDEX IF NOT EXISTS idx_clients_public_key ON clients(public_key);
CREATE INDEX IF NOT EXISTS idx_clients_enabled ON clients(enabled);
CREATE INDEX IF NOT EXISTS idx_clients_revoked ON clients(revoked_at);

-- ============================================================================
-- AUDIT LOGS TABLE
-- ============================================================================
-- Tracks all administrative actions for security compliance and debugging.
-- Provides a complete audit trail of who did what and when.
CREATE TABLE IF NOT EXISTS audit_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,           -- Unique log entry ID
	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,   -- When the action occurred
	username TEXT NOT NULL,                         -- Admin user who performed the action
	action TEXT NOT NULL,                           -- Action type (e.g., "add_client", "revoke_client", "login")
	resource_type TEXT NOT NULL,                    -- Type of resource affected (e.g., "client", "settings")
	resource_name TEXT NOT NULL,                    -- Specific resource name (e.g., client name)
	ip_address TEXT,                                -- IP address of the admin performing action
	user_agent TEXT,                                -- Browser/client user agent string
	details TEXT,                                   -- Additional context or error messages
	success BOOLEAN DEFAULT 1                       -- Whether the action succeeded (1=success, 0=failure)
);

-- Indexes optimized for audit log queries (typically sorted by recent first)
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_logs(username);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);

-- ============================================================================
-- BANDWIDTH STATISTICS TABLE
-- ============================================================================
-- Stores periodic snapshots of client bandwidth usage for analytics and graphing.
-- Enables bandwidth trend analysis and identification of heavy users.
CREATE TABLE IF NOT EXISTS bandwidth_stats (
	id INTEGER PRIMARY KEY AUTOINCREMENT,           -- Unique stat entry ID
	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,   -- When this measurement was taken
	client_id INTEGER,                              -- Reference to clients table
	rx_bytes INTEGER DEFAULT 0,                     -- Bytes received at this point in time
	tx_bytes INTEGER DEFAULT 0,                     -- Bytes transmitted at this point in time
	FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE  -- Auto-delete stats when client removed
);

-- Indexes for time-series queries and per-client filtering
CREATE INDEX IF NOT EXISTS idx_bandwidth_timestamp ON bandwidth_stats(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_bandwidth_client ON bandwidth_stats(client_id);

-- ============================================================================
-- SYSTEM METRICS TABLE
-- ============================================================================
-- Captures server-wide resource usage for monitoring and capacity planning.
-- Helps identify performance issues and resource bottlenecks.
CREATE TABLE IF NOT EXISTS system_metrics (
	id INTEGER PRIMARY KEY AUTOINCREMENT,           -- Unique metric entry ID
	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,   -- Measurement timestamp
	cpu_percent REAL DEFAULT 0,                     -- CPU usage percentage (0-100)
	mem_used_bytes INTEGER DEFAULT 0,               -- Memory used in bytes
	mem_used_percent REAL DEFAULT 0,                -- Memory usage percentage (0-100)
	total_rx_bytes INTEGER DEFAULT 0,               -- Total server network receive bytes
	total_tx_bytes INTEGER DEFAULT 0,               -- Total server network transmit bytes
	active_peers INTEGER DEFAULT 0                  -- Number of currently connected clients
);

-- Index for time-series metric queries
CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON system_metrics(timestamp DESC);

-- ============================================================================
-- SETTINGS TABLE
-- ============================================================================
-- Key-value store for application configuration and feature flags.
-- Provides flexible configuration without schema changes.
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,                           -- Setting name (unique identifier)
	value TEXT NOT NULL,                            -- Setting value (stored as text)
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP   -- Last update timestamp
);

-- ============================================================================
-- SESSIONS TABLE
-- ============================================================================
-- Manages user authentication sessions for the web dashboard.
-- Provides stateful session tracking beyond cookie-only authentication.
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,                            -- Unique session identifier (random token)
	username TEXT NOT NULL,                         -- User associated with this session
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,  -- When session was created
	expires_at DATETIME NOT NULL,                   -- When session expires (enforced on lookup)
	ip_address TEXT,                                -- IP address session was created from
	user_agent TEXT                                 -- Browser/client user agent
);

-- Indexes for session lookup and cleanup
CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- ============================================================================
-- MIGRATIONS TABLE
-- ============================================================================
-- Tracks database schema version and migration history.
-- Ensures migrations run exactly once and provides rollback reference.
CREATE TABLE IF NOT EXISTS migrations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,           -- Migration entry ID
	version TEXT NOT NULL UNIQUE,                   -- Migration version identifier
	applied_at DATETIME DEFAULT CURRENT_TIMESTAMP   -- When this migration was applied
);

-- Initialize with the base schema version
INSERT OR IGNORE INTO migrations (version) VALUES ('v2.1.0_initial');
`
