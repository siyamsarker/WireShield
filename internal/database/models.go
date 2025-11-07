package database

import (
	"database/sql"
	"time"
)

// ============================================================================
// DATA MODELS
// ============================================================================
// These structs represent the database schema as Go types, enabling type-safe
// database operations and JSON serialization for API responses.

// Client represents a WireGuard VPN client with full lifecycle tracking.
// Each client corresponds to one device/user with access to the VPN server.
type Client struct {
	ID            int64      `json:"id"`                       // Unique database identifier
	Name          string     `json:"name"`                     // Human-readable name (e.g., "alice-phone")
	PublicKey     string     `json:"public_key"`               // WireGuard public key for authentication
	AllowedIPs    string     `json:"allowed_ips"`              // CIDR notation of allowed IP ranges
	CreatedAt     time.Time  `json:"created_at"`               // Initial creation timestamp
	UpdatedAt     time.Time  `json:"updated_at"`               // Last modification timestamp
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`     // Optional expiration date (nil = no expiry)
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`     // When access was revoked (nil = active)
	Enabled       bool       `json:"enabled"`                  // Whether client can currently connect
	TotalRxBytes  int64      `json:"total_rx_bytes"`           // Cumulative bytes downloaded
	TotalTxBytes  int64      `json:"total_tx_bytes"`           // Cumulative bytes uploaded
	LastHandshake *time.Time `json:"last_handshake,omitempty"` // Last successful WireGuard handshake
	Endpoint      string     `json:"endpoint,omitempty"`       // Client's current IP:port
	Notes         string     `json:"notes,omitempty"`          // Admin notes/comments
}

// AuditLog represents a recorded administrative action for compliance and debugging.
// Provides a complete audit trail of who performed what action, when, and with what result.
type AuditLog struct {
	ID           int64     `json:"id"`                   // Unique log entry identifier
	Timestamp    time.Time `json:"timestamp"`            // When the action occurred (UTC)
	Username     string    `json:"username"`             // Admin who performed the action
	Action       string    `json:"action"`               // Action type (e.g., "add_client", "revoke")
	ResourceType string    `json:"resource_type"`        // Resource category (e.g., "client", "settings")
	ResourceName string    `json:"resource_name"`        // Specific resource identifier
	IPAddress    string    `json:"ip_address,omitempty"` // Source IP of the action
	UserAgent    string    `json:"user_agent,omitempty"` // Browser/client identifier
	Details      string    `json:"details,omitempty"`    // Additional context or error messages
	Success      bool      `json:"success"`              // Whether operation succeeded
}

// BandwidthStat captures bandwidth usage at a specific point in time.
// Used for generating usage graphs and identifying bandwidth trends.
type BandwidthStat struct {
	ID        int64     `json:"id"`        // Unique measurement identifier
	Timestamp time.Time `json:"timestamp"` // When measurement was taken
	ClientID  int64     `json:"client_id"` // Reference to clients table
	RxBytes   int64     `json:"rx_bytes"`  // Bytes received at this time
	TxBytes   int64     `json:"tx_bytes"`  // Bytes transmitted at this time
}

// SystemMetric captures server resource utilization for monitoring.
// Tracks CPU, memory, network, and active connection metrics over time.
type SystemMetric struct {
	ID             int64     `json:"id"`               // Unique metric identifier
	Timestamp      time.Time `json:"timestamp"`        // Measurement timestamp
	CPUPercent     float64   `json:"cpu_percent"`      // CPU usage (0-100%)
	MemUsedBytes   int64     `json:"mem_used_bytes"`   // Memory consumption in bytes
	MemUsedPercent float64   `json:"mem_used_percent"` // Memory usage (0-100%)
	TotalRxBytes   int64     `json:"total_rx_bytes"`   // Total network bytes received
	TotalTxBytes   int64     `json:"total_tx_bytes"`   // Total network bytes transmitted
	ActivePeers    int       `json:"active_peers"`     // Number of connected clients
}

// Setting represents a flexible key-value configuration entry.
// Enables runtime configuration without database schema changes.
type Setting struct {
	Key       string    `json:"key"`        // Unique setting identifier
	Value     string    `json:"value"`      // Setting value (always string, parse as needed)
	UpdatedAt time.Time `json:"updated_at"` // Last modification timestamp
}

// Session represents an authenticated user's dashboard session.
// Provides stateful session tracking beyond cookie-only authentication.
type Session struct {
	ID        string    `json:"id"`                   // Unique session token
	Username  string    `json:"username"`             // Authenticated user
	CreatedAt time.Time `json:"created_at"`           // Session start time
	ExpiresAt time.Time `json:"expires_at"`           // Session expiration time
	IPAddress string    `json:"ip_address,omitempty"` // IP where session originated
	UserAgent string    `json:"user_agent,omitempty"` // Client user agent string
}

// ============================================================================
// REPOSITORY: CLIENT OPERATIONS
// ============================================================================
// ClientRepository provides CRUD operations and queries for VPN clients.
// All methods use prepared statements to prevent SQL injection.

// ClientRepository encapsulates all database operations for VPN clients.
type ClientRepository struct {
	db *DB // Database connection handle
}

// NewClientRepository initializes a new client repository with the given database.
func NewClientRepository(db *DB) *ClientRepository {
	return &ClientRepository{db: db}
}

// Create inserts a new client into the database.
// Automatically sets creation and update timestamps.
//
// Parameters:
//   - client: Client struct with name, public key, allowed IPs, and optional fields
//
// Returns:
//   - error: nil on success, or database error (e.g., duplicate name)
//
// Side effects:
//   - Sets client.ID to the auto-generated database ID
//   - Sets client.CreatedAt and client.UpdatedAt to current time
func (r *ClientRepository) Create(client *Client) error {
	client.CreatedAt = time.Now()
	client.UpdatedAt = time.Now()

	result, err := r.db.Exec(`
		INSERT INTO clients (name, public_key, allowed_ips, created_at, updated_at, expires_at, enabled, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, client.Name, client.PublicKey, client.AllowedIPs, client.CreatedAt, client.UpdatedAt, client.ExpiresAt, client.Enabled, client.Notes)

	if err != nil {
		return err
	}

	client.ID, err = result.LastInsertId()
	return err
}

// GetByName retrieves a client by name
func (r *ClientRepository) GetByName(name string) (*Client, error) {
	client := &Client{}
	err := r.db.QueryRow(`
		SELECT id, name, public_key, allowed_ips, created_at, updated_at, expires_at, revoked_at, enabled,
		       total_rx_bytes, total_tx_bytes, last_handshake, endpoint, notes
		FROM clients WHERE name = ?
	`, name).Scan(&client.ID, &client.Name, &client.PublicKey, &client.AllowedIPs, &client.CreatedAt,
		&client.UpdatedAt, &client.ExpiresAt, &client.RevokedAt, &client.Enabled,
		&client.TotalRxBytes, &client.TotalTxBytes, &client.LastHandshake, &client.Endpoint, &client.Notes)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return client, err
}

// GetByID retrieves a client by ID
func (r *ClientRepository) GetByID(id int64) (*Client, error) {
	client := &Client{}
	err := r.db.QueryRow(`
		SELECT id, name, public_key, allowed_ips, created_at, updated_at, expires_at, revoked_at, enabled,
		       total_rx_bytes, total_tx_bytes, last_handshake, endpoint, notes
		FROM clients WHERE id = ?
	`, id).Scan(&client.ID, &client.Name, &client.PublicKey, &client.AllowedIPs, &client.CreatedAt,
		&client.UpdatedAt, &client.ExpiresAt, &client.RevokedAt, &client.Enabled,
		&client.TotalRxBytes, &client.TotalTxBytes, &client.LastHandshake, &client.Endpoint, &client.Notes)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return client, err
}

// List retrieves all clients with optional filters
func (r *ClientRepository) List(includeRevoked bool) ([]*Client, error) {
	query := `
		SELECT id, name, public_key, allowed_ips, created_at, updated_at, expires_at, revoked_at, enabled,
		       total_rx_bytes, total_tx_bytes, last_handshake, endpoint, notes
		FROM clients
	`
	if !includeRevoked {
		query += ` WHERE revoked_at IS NULL`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*Client
	for rows.Next() {
		client := &Client{}
		err := rows.Scan(&client.ID, &client.Name, &client.PublicKey, &client.AllowedIPs, &client.CreatedAt,
			&client.UpdatedAt, &client.ExpiresAt, &client.RevokedAt, &client.Enabled,
			&client.TotalRxBytes, &client.TotalTxBytes, &client.LastHandshake, &client.Endpoint, &client.Notes)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

// Search finds clients matching a search term
func (r *ClientRepository) Search(term string) ([]*Client, error) {
	query := `
		SELECT id, name, public_key, allowed_ips, created_at, updated_at, expires_at, revoked_at, enabled,
		       total_rx_bytes, total_tx_bytes, last_handshake, endpoint, notes
		FROM clients
		WHERE (name LIKE ? OR notes LIKE ? OR allowed_ips LIKE ?)
		  AND revoked_at IS NULL
		ORDER BY created_at DESC
	`
	searchPattern := "%" + term + "%"
	rows, err := r.db.Query(query, searchPattern, searchPattern, searchPattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*Client
	for rows.Next() {
		client := &Client{}
		err := rows.Scan(&client.ID, &client.Name, &client.PublicKey, &client.AllowedIPs, &client.CreatedAt,
			&client.UpdatedAt, &client.ExpiresAt, &client.RevokedAt, &client.Enabled,
			&client.TotalRxBytes, &client.TotalTxBytes, &client.LastHandshake, &client.Endpoint, &client.Notes)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

// Update updates a client's information
func (r *ClientRepository) Update(client *Client) error {
	client.UpdatedAt = time.Now()
	_, err := r.db.Exec(`
		UPDATE clients
		SET name = ?, public_key = ?, allowed_ips = ?, updated_at = ?, expires_at = ?, 
		    revoked_at = ?, enabled = ?, total_rx_bytes = ?, total_tx_bytes = ?, 
		    last_handshake = ?, endpoint = ?, notes = ?
		WHERE id = ?
	`, client.Name, client.PublicKey, client.AllowedIPs, client.UpdatedAt, client.ExpiresAt,
		client.RevokedAt, client.Enabled, client.TotalRxBytes, client.TotalTxBytes,
		client.LastHandshake, client.Endpoint, client.Notes, client.ID)
	return err
}

// Revoke marks a client as revoked
func (r *ClientRepository) Revoke(name string) error {
	now := time.Now()
	_, err := r.db.Exec(`
		UPDATE clients SET revoked_at = ?, updated_at = ?, enabled = 0 WHERE name = ? AND revoked_at IS NULL
	`, now, now, name)
	return err
}

// UpdateStats updates bandwidth and handshake statistics
func (r *ClientRepository) UpdateStats(publicKey string, rxBytes, txBytes int64, lastHandshake *time.Time) error {
	_, err := r.db.Exec(`
		UPDATE clients
		SET total_rx_bytes = ?, total_tx_bytes = ?, last_handshake = ?, updated_at = ?
		WHERE public_key = ?
	`, rxBytes, txBytes, lastHandshake, time.Now(), publicKey)
	return err
}

// Delete permanently removes a client
func (r *ClientRepository) Delete(name string) error {
	_, err := r.db.Exec(`DELETE FROM clients WHERE name = ?`, name)
	return err
}

// Count returns the total number of clients
func (r *ClientRepository) Count(activeOnly bool) (int, error) {
	query := `SELECT COUNT(*) FROM clients WHERE 1=1`
	if activeOnly {
		query += ` AND revoked_at IS NULL AND enabled = 1`
	}
	var count int
	err := r.db.QueryRow(query).Scan(&count)
	return count, err
}

// GetExpired returns clients that have expired but not yet revoked
func (r *ClientRepository) GetExpired() ([]*Client, error) {
	query := `
		SELECT id, name, public_key, allowed_ips, created_at, updated_at, expires_at, revoked_at, enabled,
		       total_rx_bytes, total_tx_bytes, last_handshake, endpoint, notes
		FROM clients
		WHERE expires_at IS NOT NULL AND expires_at < ? AND revoked_at IS NULL
		ORDER BY expires_at ASC
	`
	rows, err := r.db.Query(query, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*Client
	for rows.Next() {
		client := &Client{}
		err := rows.Scan(&client.ID, &client.Name, &client.PublicKey, &client.AllowedIPs, &client.CreatedAt,
			&client.UpdatedAt, &client.ExpiresAt, &client.RevokedAt, &client.Enabled,
			&client.TotalRxBytes, &client.TotalTxBytes, &client.LastHandshake, &client.Endpoint, &client.Notes)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}
