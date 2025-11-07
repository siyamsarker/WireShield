package database

import (
	"database/sql"
	"time"
)

// Client represents a WireGuard client configuration
type Client struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	PublicKey     string     `json:"public_key"`
	AllowedIPs    string     `json:"allowed_ips"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	Enabled       bool       `json:"enabled"`
	TotalRxBytes  int64      `json:"total_rx_bytes"`
	TotalTxBytes  int64      `json:"total_tx_bytes"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	Endpoint      string     `json:"endpoint,omitempty"`
	Notes         string     `json:"notes,omitempty"`
}

// AuditLog represents an administrative action log entry
type AuditLog struct {
	ID           int64     `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	Username     string    `json:"username"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceName string    `json:"resource_name"`
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	Details      string    `json:"details,omitempty"`
	Success      bool      `json:"success"`
}

// BandwidthStat represents a periodic bandwidth measurement
type BandwidthStat struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	ClientID  int64     `json:"client_id"`
	RxBytes   int64     `json:"rx_bytes"`
	TxBytes   int64     `json:"tx_bytes"`
}

// SystemMetric represents server resource usage at a point in time
type SystemMetric struct {
	ID             int64     `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	CPUPercent     float64   `json:"cpu_percent"`
	MemUsedBytes   int64     `json:"mem_used_bytes"`
	MemUsedPercent float64   `json:"mem_used_percent"`
	TotalRxBytes   int64     `json:"total_rx_bytes"`
	TotalTxBytes   int64     `json:"total_tx_bytes"`
	ActivePeers    int       `json:"active_peers"`
}

// Setting represents a configuration key-value pair
type Setting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Session represents an active user session
type Session struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

// ClientRepository handles client data operations
type ClientRepository struct {
	db *DB
}

// NewClientRepository creates a new client repository
func NewClientRepository(db *DB) *ClientRepository {
	return &ClientRepository{db: db}
}

// Create adds a new client
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
